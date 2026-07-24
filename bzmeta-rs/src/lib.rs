use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Lanlu/v1.00 (https://github.com/copurxia/lanlu)";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;
const AUTH_DATA_KEY: &str = "__lanlu.phase.bzlogin.data";

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wasmedge_host")]
extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32) -> i32;
    fn host_progress(percent: i32, ptr: i32, len: i32) -> i32;
    fn host_call(op: i32, req_ptr: i32, req_len: i32) -> i32;
    fn host_response_len() -> i32;
    fn host_response_read(dst_ptr: i32, dst_len: i32) -> i32;
    fn host_last_error_len() -> i32;
    fn host_last_error_read(dst_ptr: i32, dst_len: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_call(_: i32, _: i32, _: i32) -> i32 { 1 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_len() -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_read(_: i32, _: i32) -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_len() -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_read(_: i32, _: i32) -> i32 { 0 }

thread_local! {
    static STATE: RefCell<PluginState> = RefCell::new(PluginState::default());
}

#[derive(Default)]
struct PluginState {
    info: Vec<u8>,
    result: Vec<u8>,
    error: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct PluginInput {
    #[serde(rename = "pluginType", default)]
    plugin_type: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
    #[serde(default)]
    action: String,
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(rename = "extraParams", default)]
    extra_params: Value,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct BzAuthData {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    cdn_domains: String,
    #[serde(default)]
    image_quality: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    tsid: String,
    #[serde(default)]
    username: String,
}

struct HostBridge;
impl HostBridge {
    fn log(level: i32, message: &str) {
        unsafe { let _ = host_log(level, message.as_ptr() as i32, message.len() as i32); }
    }
    fn progress(percent: i32, message: &str) {
        unsafe { let _ = host_progress(percent, message.as_ptr() as i32, message.len() as i32); }
    }
    fn call(method: &str, params: Value) -> Result<Value, String> {
        let req = json!({ "method": method, "params": params });
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 { return Err(Self::read_error()); }
        Self::read_response()
    }
    fn read_response() -> Result<Value, String> {
        let len = unsafe { host_response_len() };
        if len < 0 { return Err("host_response_len negative".to_string()); }
        if len == 0 { return Ok(Value::Null); }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buf.as_mut_ptr() as i32, len) };
        if read < 0 { return Err("host_response_read failed".to_string()); }
        serde_json::from_slice(&buf[..read as usize]).map_err(|e| e.to_string())
    }
    fn read_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 { return "host call failed".to_string(); }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buf.as_mut_ptr() as i32, len) };
        if read <= 0 { return "host call failed".to_string(); }
        String::from_utf8_lossy(&buf[..read as usize]).to_string()
    }
    fn task_kv_get(key: &str) -> Result<Option<Value>, String> {
        let response = Self::call("task_kv.get", json!({ "key": key }))?;
        let found = response.get("found").and_then(Value::as_bool).unwrap_or(false);
        if !found { return Ok(None); }
        Ok(response.get("value").cloned())
    }
    fn task_kv_set(key: &str, value: Value) -> Result<(), String> {
        Self::call("task_kv.set", json!({ "key": key, "value": value }))?;
        Ok(())
    }
    fn install_asset(guest_path: &str, original_filename: &str, content_type: &str) -> Result<i64, String> {
        let resp = Self::call("asset.install_from_file", json!({
            "guest_path": guest_path,
            "original_filename": original_filename,
            "content_type": content_type,
        }))?;
        resp.get("asset_id").and_then(Value::as_i64).ok_or_else(|| "no asset_id in response".to_string())
    }
    fn select_index(title: &str, options: Vec<Value>, message: &str, default_index: i32, timeout_seconds: i32) -> Result<usize, String> {
        let value = Self::call("ui.select", json!({
            "title": title,
            "message": message,
            "default_index": default_index,
            "timeout_seconds": timeout_seconds,
            "options": options,
        }))?;
        let index = value.get("index").and_then(Value::as_i64).ok_or("ui.select missing index")?;
        usize::try_from(index).map_err(|_| "ui.select invalid index".to_string())
    }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_alloc(size: i32) -> i32 {
    if size <= 0 { return 0; }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_free(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 { return; }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info() -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        ensure_info_bytes(&mut state);
        state.info.as_ptr() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info_len() -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        ensure_info_bytes(&mut state);
        state.info.len() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_run(input_ptr: i32, input_len: i32) -> i32 {
    clear_runtime_buffers();
    let input_bytes = unsafe { read_guest_bytes(input_ptr, input_len) };
    let input = match serde_json::from_slice::<PluginInput>(input_bytes) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("invalid plugin input: {e}")),
    };
    let payload = if input.action.trim() == "resolve_cover" {
        resolve_cover_action(&input)
    } else if input.action.trim() == "resolve_metadata"
        && normalize_target_type(&input.target_type, &input.params) == "source"
    {
        resolve_source_metadata(&input)
    } else {
        build_result_payload(input)
    };
    let output = match serde_json::to_vec(&payload) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("failed to encode result: {e}")),
    };
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = output;
        state.result.as_ptr() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_result_len() -> i32 {
    STATE.with(|state| state.borrow().result.len() as i32)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_last_error() -> i32 {
    STATE.with(|state| state.borrow().error.as_ptr() as i32)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_last_error_len() -> i32 {
    STATE.with(|state| state.borrow().error.len() as i32)
}

fn plugin_info_json() -> Value {
    json!({
        "name": "Baozi Metadata",
        "type": "metadata",
        "namespace": "bzmeta",
        "pre": ["bzlogin"],
        "source_id_regex": "^source:bzsource:.*$",
        "author": "Lanlu",
        "version": "1.0.0",
        "description": "Fetches metadata from Baozi Manhua (包子漫画).",
        "parameters": [
            {"name": "fetch_cover", "type": "bool", "desc": "Fetch cover URL into metadata", "default_value": "1"}
        ],
        "oneshot_arg": "Baozi comic URL or ID (e.g. https://cn.bzmgcn.com/comic/xxx)",
        "cooldown": 2,
        "permissions": [
            "metadata.read_input",
            "tcp.connect",
            "ui.select",
            "log.write",
            "progress.report",
            "task_kv.read",
            "task_kv.write",
            "asset.install_from_file"
        ]
    })
}

fn resolve_cover_action(input: &PluginInput) -> Value {
    let asset_id = input.extra_params.get("asset_id").and_then(Value::as_i64).unwrap_or(0);
    if asset_id <= 0 { return json!({"success": false, "error": "missing asset_id"}); }
    json!({"success": false, "error": "resolve_cover not yet implemented"})
}

/// 下载 BZ 漫画封面并安装为 asset，返回 cover_asset_id（0 表示失败）。
/// 带 task_kv 缓存（按 comic_id），避免每次 resolve_metadata 都重下封面。
/// 对齐 picacgmeta/jmcomicmeta 的 resolve_cover_asset。
fn resolve_cover_asset(cover_url: &str, comic_id: &str) -> i64 {
    if cover_url.trim().is_empty() {
        return 0;
    }

    // 缓存命中则直接返回已安装的 asset_id
    let cache_key = format!("bz_cover_{comic_id}");
    if let Ok(Some(cached)) = HostBridge::task_kv_get(&cache_key) {
        if let Some(id) = cached.as_i64() {
            if id > 0 { return id; }
        }
    }

    // 推断扩展名与 content_type
    let lower = cover_url.to_ascii_lowercase();
    let ext = if lower.ends_with(".png") { "png" }
        else if lower.ends_with(".gif") { "gif" }
        else if lower.ends_with(".webp") { "webp" }
        else { "jpg" };
    let content_type = match ext {
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "image/jpeg",
    };
    let guest_path = format!("/plugin/bz_cover_{comic_id}.{ext}");
    let original_filename = format!("cover_{comic_id}.{ext}");

    // 下载封面（CDN，无需鉴权 header，带 UA + Referer 即可）
    let headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "image/webp,image/apng,image/*,*/*;q=0.8".to_string()),
        ("Referer".to_string(), cover_url.to_string()),
    ];
    let response = match http_get_bytes_follow_redirects(cover_url, &headers) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(2, &format!("bz cover download failed for {comic_id}: {e}"));
            return 0;
        }
    };
    if response.status >= 400 {
        HostBridge::log(2, &format!("bz cover HTTP {} for {comic_id}", response.status));
        return 0;
    }
    if response.body.is_empty() {
        HostBridge::log(2, &format!("bz cover empty body for {comic_id}"));
        return 0;
    }

    // 写入 WASI guest path
    if let Err(e) = std::fs::write(&guest_path, &response.body) {
        HostBridge::log(2, &format!("bz cover write failed for {comic_id}: {e}"));
        return 0;
    }

    // 安装为 asset
    match HostBridge::install_asset(&guest_path, &original_filename, content_type) {
        Ok(asset_id) => {
            let _ = HostBridge::task_kv_set(&cache_key, json!(asset_id));
            asset_id
        }
        Err(e) => {
            HostBridge::log(2, &format!("bz cover install failed for {comic_id}: {e}"));
            0
        }
    }
}

fn normalize_target_type(raw: &str, params: &Value) -> String {
    let from_input = raw.trim().to_ascii_lowercase();
    if !from_input.is_empty() { return from_input; }
    params.get("__target_type").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase()
}

fn value_to_id_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// 解析 source 元数据：从 sourceId（source:bzsource:{comicId} 或 source:bzsource:{comicId}_{epId}）解析
/// 调 BZ HTML 页面获取漫画元数据/章节/页面。
fn resolve_source_metadata(input: &PluginInput) -> Value {
    HostBridge::progress(5, "解析 sourceId...");
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return json!({"success": false, "error": e}),
    };

    let target_id = input.target_id.trim();
    let remote_id = match target_id.strip_prefix("source:bzsource:") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return json!({"success": false, "error": format!("invalid sourceId: {target_id}")}),
    };

    HostBridge::log(1, &format!("bzmeta resolve_source_metadata id={}", remote_id));

    // 检查是否是章节（comicId_epId 格式）
    if let Some(underscore_pos) = remote_id.rfind('_') {
        let ep_id = &remote_id[underscore_pos + 1..];
        let comic_id = &remote_id[..underscore_pos];
        if !ep_id.is_empty() && !comic_id.is_empty() {
            // 章节模式 → 获取页面列表
            HostBridge::progress(40, &format!("获取章节 {} 页面...", remote_id));
            return match fetch_chapter_image_urls(&remote_id) {
                Ok(image_count) => {
                    let children: Vec<Value> = (1..=image_count).map(|page_num| {
                        json!({
                            "entity_type": "page",
                            "entity_id": format!("source:bzsource:{}#page:{}", remote_id, page_num),
                            "title": "",
                            "sort_order": page_num as i64,
                            "path": format!("{}/{}", remote_id, page_num),
                            "media_type": "image",
                        })
                    }).collect();
                    HostBridge::progress(100, "元数据获取完成");
                    json!({"success": true, "data": json!({"children": children})})
                }
                Err(e) => json!({"success": false, "error": e}),
            };
        }
    }

    // 漫画模式 → 获取详情和章节列表
    HostBridge::progress(30, &format!("获取漫画 {} 详情...", remote_id));
    match fetch_comic_detail(&remote_id, &auth) {
        Ok(detail) => {
            let tags = metadata_tags_from_csv(&detail.tags);

            // 下载封面并安装为 asset（对齐 picacgmeta/jmcomicmeta）
            HostBridge::progress(70, "处理封面...");
            let cover_asset_id = resolve_cover_asset(&detail.cover, &remote_id);

            // 解析章节
            let comic_url = format!("{}/comic/{}", auth.base_url, remote_id);
            let (status, html) = match http_get_text(&comic_url, &build_headers(&auth)) {
                Ok(v) => v,
                Err(e) => return json!({"success": false, "error": format!("fetch comic page: {e}")}),
            };
            if !(200..300).contains(&status) {
                return json!({"success": false, "error": format!("comic page HTTP {status}")});
            }
            let chapters = parse_chapters_from_html(&html);
            let children: Vec<Value> = chapters.iter().enumerate().map(|(idx, (ep_id, ch_title))| {
                let mut child = json!({
                    "entity_type": "archive",
                    "entity_id": format!("source:bzsource:{}_{}", remote_id, ep_id),
                    "title": ch_title,
                    "sort_order": (idx + 1) as i64,
                });
                // 每个档案复用合集封面（对齐 picacgmeta/jmcomicmeta）
                if cover_asset_id > 0 {
                    child["assets"] = json!([{ "key": "cover", "value": cover_asset_id }]);
                }
                child
            }).collect();

            let mut data = json!({
                "title": detail.title,
                "description": detail.description,
                "tags": tags,
                "children": children,
            });
            if cover_asset_id > 0 {
                data["assets"] = json!([{ "key": "cover", "value": cover_asset_id }]);
            }
            HostBridge::progress(100, "元数据获取完成");
            json!({"success": true, "data": data})
        }
        Err(e) => json!({"success": false, "error": e}),
    }
}

/// 从 BZ 章节 HTML 提取图片 URL 列表（用于确定 page 数量）
fn fetch_chapter_image_urls(comic_chapter_id: &str) -> Result<usize, String> {
    // comic_chapter_id = "{comic_id}_{ep_id}"
    let parts: Vec<&str> = comic_chapter_id.splitn(2, '_').collect();
    if parts.len() < 2 { return Err("invalid chapter id".to_string()); }
    let comic_id = parts[0];
    let ep_id = parts[1];

    let app_url = format!("https://appcn.baozimh.com/baozimhapp/comic/chapter/{comic_id}/0_{ep_id}.html");
    let headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "text/html,*/*;q=0.8".to_string()),
    ];
    let (status, html) = http_get_text(&app_url, &headers)?;
    if !(200..300).contains(&status) {
        return Err(format!("chapter page HTTP {status}"));
    }

    // data-src then src pattern (same as bzsource)
    let mut urls = Vec::new();
    if let Ok(re) = Regex::new(r#"data-src=["']([^"']+)["']"#) {
        for cap in re.captures_iter(&html) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str().trim();
                if !u.is_empty() { urls.push(u.to_string()); }
            }
        }
    }
    if urls.is_empty() {
        if let Ok(re) = Regex::new(r#"<img[^>]*src=["']([^"']+)["']"#) {
            for cap in re.captures_iter(&html) {
                if let Some(url) = cap.get(1) {
                    let u = url.as_str().trim();
                    if !u.is_empty() && (u.starts_with("http://") || u.starts_with("https://")) {
                        urls.push(u.to_string());
                    }
                }
            }
        }
    }

    if urls.is_empty() {
        return Err("no images found in chapter".to_string());
    }
    Ok(urls.len())
}

/// 从漫画详情 HTML 解析章节列表（复用 bzsource 的解析模式）
fn parse_chapters_from_html(html: &str) -> Vec<(String, String)> {
    // 对齐 venera baozi.js: div#chapter-items / div#chapters_other_list 下的
    // <div class="comics-chapters"><a href="/user/page_direct?...&chapter_slot=N"><div><span>title</span></div></a></div>
    // 页面常渲染两份列表（正序+倒序），需按 chapter_slot 去重后排序。
    // ep_id = chapter_slot 的值。先尝试带 chapter_slot 的链接（新版 HTML）。
    use std::collections::BTreeMap;
    let mut chapters_map: BTreeMap<i64, String> = BTreeMap::new();
    if let Ok(re) = Regex::new(r#"<a[^>]*href="[^"]*chapter_slot=(\d+)[^"]*"[^>]*>\s*(?:<div[^>]*>)?\s*<span[^>]*>(.*?)</span>"#) {
        for cap in re.captures_iter(html) {
            let ep_id_str = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let title = strip_html_tags(cap.get(2).map(|m| m.as_str()).unwrap_or("").trim());
            if let Ok(ep_id) = ep_id_str.parse::<i64>() {
                if !title.is_empty() {
                    chapters_map.entry(ep_id).or_insert(title);
                }
            }
        }
    }
    if !chapters_map.is_empty() {
        return chapters_map.into_iter().map(|(ep, title)| (ep.to_string(), title)).collect();
    }

    // 旧版 HTML：/chapter/{comicId}/{epId}_ 格式
    if let Ok(re) = Regex::new(r#"<a[^>]*href=["']?/chapter/[^"']*?/(\d+)_["']?[^>]*>[\s\S]*?<span[^>]*>(.*?)</span>[\s\S]*?</a>"#) {
        let mut found = Vec::new();
        for cap in re.captures_iter(html) {
            let ep_id = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let title = strip_html_tags(cap.get(2).map(|m| m.as_str()).unwrap_or("").trim());
            if !ep_id.is_empty() && !title.is_empty() {
                found.push((ep_id, title));
            }
        }
        if !found.is_empty() { return found; }
    }

    // Fallback: comics-chapters > span（仅标题，ep_id 用序号）
    let mut chapters = Vec::new();
    if let Ok(re) = Regex::new(r#"class=["']?[^"']*comics-chapters["']?[^>]*>[\s\S]*?<span[^>]*>(.*?)</span>"#) {
        for (idx, cap) in re.captures_iter(html).enumerate() {
            let title = strip_html_tags(cap.get(1).map(|m| m.as_str()).unwrap_or("").trim());
            if !title.is_empty() {
                chapters.push((idx.to_string(), title));
            }
        }
    }
    chapters
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    HostBridge::progress(5, "初始化 Baozi 元数据...");
    let auth = load_bz_auth()?;
    let fetch_cover = read_bool_param(&input.params, "fetch_cover", true);

    let mut metadata = ensure_metadata_object(input.metadata);
    let title = metadata.get("title").and_then(Value::as_str).unwrap_or("").trim().to_string();

    let comic_id = if let Some(id) = extract_comic_id(&input.oneshot_param) {
        Some(id)
    } else if let Some(id) = extract_comic_id_from_tags(&metadata) {
        Some(id)
    } else if title.is_empty() {
        None
    } else {
        search_comic_id_by_title(&title, &auth)?
    };

    let Some(comic_id) = comic_id else {
        return Err("No matching Baozi comic found.".to_string());
    };
    HostBridge::log(1, &format!("bzmeta resolved comic_id={comic_id}"));

    HostBridge::progress(40, &format!("获取漫画 {comic_id} 详情..."));
    let detail = fetch_comic_detail(&comic_id, &auth)?;

    if !detail.title.is_empty() {
        metadata.insert("title".to_string(), Value::String(detail.title));
    }
    if !detail.tags.is_empty() {
        metadata.insert("tags".to_string(), metadata_tags_from_csv(&detail.tags));
    }
    if !detail.description.is_empty() {
        metadata.insert("description".to_string(), Value::String(detail.description));
    }
    if fetch_cover && !detail.cover.is_empty() {
        let cover_asset_id = resolve_cover_asset(&detail.cover, &comic_id);
        if cover_asset_id > 0 {
            metadata.insert(
                "assets".to_string(),
                json!([{ "key": "cover", "value": cover_asset_id }]),
            );
        }
    }
    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "元数据获取完成");
    Ok(Value::Object(metadata))
}

fn load_bz_auth() -> Result<BzAuthData, String> {
    let value = HostBridge::task_kv_get(AUTH_DATA_KEY)?.ok_or("Missing bzlogin auth data. Ensure bzlogin ran as a pre hook.")?;
    serde_json::from_value(value).map_err(|e| format!("Invalid bzlogin auth data: {e}"))
}

fn extract_comic_id(input: &str) -> Option<String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() { return None; }
    if clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { return Some(clean.to_string()); }
    let re = Regex::new(r"/comic/([^/\s?#]+)").ok()?;
    re.captures(clean)?.get(1).map(|m| m.as_str().to_string())
}

fn extract_comic_id_from_tags(metadata: &Map<String, Value>) -> Option<String> {
    let tags_csv = metadata_tags_to_csv(metadata);
    let re = Regex::new(r"source:\s*(?:https?://)?[^/]+/comic/([^/\s,]+)").ok()?;
    re.captures(&tags_csv)?.get(1).map(|m| m.as_str().to_string())
}

fn search_comic_id_by_title(title: &str, auth: &BzAuthData) -> Result<Option<String>, String> {
    if title.is_empty() { return Ok(None); }
    let query = urlencoding::encode(title);
    let url = format!("{}/api/bzmhq/amp_comic_list?type=all&region=all&state=all&filter=%2a&page=1&limit=36&language={}&q={}", auth.base_url, auth.language, query);
    HostBridge::log(1, &format!("bzmeta search GET {url}"));
    let (status, text) = http_get_text(&url, &build_headers(auth))?;
    HostBridge::log(1, &format!("bzmeta search status={status}"));
    if !(200..300).contains(&status) { return Ok(None); }

    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("search JSON parse error: {e}"))?;
    let items = parsed.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    if items.is_empty() { return Ok(None); }

    let mut candidates = Vec::new();
    for item in items {
        let id = item.get("comic_id").and_then(Value::as_str).unwrap_or("").to_string();
        let name = item.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let author = item.get("author").and_then(Value::as_str).unwrap_or("").to_string();
        if id.is_empty() || name.is_empty() { continue; }
        let score = score_title_match(title, &name);
        candidates.push((score, id, name, author));
    }

    if candidates.is_empty() { return Ok(None); }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));

    let top = &candidates[0];
    if candidates.len() == 1 || top.0 >= 80 {
        return Ok(Some(top.1.clone()));
    }

    let selectable = candidates.into_iter().filter(|c| c.0 >= 30).take(5).collect::<Vec<_>>();
    if selectable.len() == 1 { return Ok(Some(selectable[0].1.clone())); }
    if selectable.is_empty() { return Ok(None); }

    let options = selectable.iter().map(|(_, _, name, author)| {
        json!({
            "label": name.clone(),
            "description": if author.is_empty() { String::new() } else { author.clone() },
        })
    }).collect::<Vec<_>>();

    let selected = HostBridge::select_index(
        "Baozi 候选匹配",
        options,
        &format!("为 \"{title}\" 选择最合适的 Baozi 漫画"),
        0,
        120,
    )?;
    Ok(Some(selectable.get(selected).or_else(|| selectable.first()).map(|c| c.1.clone()).unwrap_or_default()))
}

fn score_title_match(query: &str, candidate: &str) -> i64 {
    let q = normalize_text(query);
    let c = normalize_text(candidate);
    if q == c { return 120; }
    if c.contains(&q) || q.contains(&c) {
        let shorter = q.len().min(c.len()) as i64;
        let longer = q.len().max(c.len()) as i64;
        return 60 + (shorter * 24 / longer.max(1));
    }
    let qt: BTreeSet<String> = q.split_whitespace().filter(|s| s.len() >= 2).map(|s| s.to_string()).collect();
    let ct: BTreeSet<String> = c.split_whitespace().filter(|s| s.len() >= 2).map(|s| s.to_string()).collect();
    let common = qt.intersection(&ct).count() as i64;
    if common == 0 { return 0; }
    let mut score = common * 12;
    if common as usize == qt.len() && qt.len() >= 2 { score += 18; }
    score
}

fn normalize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = true;
    for ch in input.to_lowercase().chars() {
        if ch.is_alphanumeric() {
            out.push(ch);
            last_space = false;
        } else if ch.is_whitespace() {
            if !last_space { out.push(' '); last_space = true; }
        } else if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim().to_string()
}

#[derive(Default)]
struct ComicDetail {
    title: String,
    tags: String,
    description: String,
    cover: String,
}

fn fetch_comic_detail(comic_id: &str, auth: &BzAuthData) -> Result<ComicDetail, String> {
    let url = format!("{}/comic/{comic_id}", auth.base_url);
    HostBridge::log(1, &format!("bzmeta detail GET {url}"));
    let (status, html) = http_get_text(&url, &build_headers(auth))?;
    if !(200..300).contains(&status) {
        return Err(format!("Detail fetch failed: HTTP {status}"));
    }

    let mut detail = ComicDetail::default();

    // Title
    if let Some(caps) = Regex::new(r#"<h1[^>]*class=["']?comics-detail__title["']?[^>]*>(.*?)</h1>"#).ok().and_then(|re| re.captures(&html)) {
        detail.title = strip_html_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }
    if detail.title.is_empty() {
        if let Some(caps) = Regex::new(r#"<title[^>]*>(.*?)</title>"#).ok().and_then(|re| re.captures(&html)) {
            detail.title = strip_html_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
        }
    }

    // Author
    let mut author = String::new();
    if let Some(caps) = Regex::new(r#"<h2[^>]*class=["']?comics-detail__author["']?[^>]*>(.*?)</h2>"#).ok().and_then(|re| re.captures(&html)) {
        author = strip_html_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }

    // Tags
    let mut tags = Vec::new();
    if let Ok(re) = Regex::new(r#"<div[^>]*class=["']?tag-list["']?[^>]*>(.*?)</div>"#) {
        if let Some(caps) = re.captures(&html) {
            let block = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Ok(tag_re) = Regex::new(r#"<span[^>]*>(.*?)</span>"#) {
                for cap in tag_re.captures_iter(block) {
                    let t = strip_html_tags(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
                    if !t.is_empty() { tags.push(t); }
                }
            }
        }
    }

    // Description
    if let Some(caps) = Regex::new(r#"<p[^>]*class=["']?comics-detail__desc["']?[^>]*>(.*?)</p>"#).ok().and_then(|re| re.captures(&html)) {
        detail.description = strip_html_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }

    // Cover
    if let Some(caps) = Regex::new(r#"<div[^>]*class=["']?l-content["']?[^>]*>.*?<amp-img[^>]*src=["']([^"']+)["']"#).ok().and_then(|re| re.captures(&html)) {
        detail.cover = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
    }
    if detail.cover.is_empty() {
        if let Some(caps) = Regex::new(r#"<amp-img[^>]*src=["']([^"']+)["']"#).ok().and_then(|re| re.captures(&html)) {
            detail.cover = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        }
    }

    let mut tag_parts = Vec::new();
    if !author.is_empty() {
        tag_parts.push(format!("author:{author}"));
    }
    for t in tags {
        tag_parts.push(t);
    }
    tag_parts.push(format!("source:{}/comic/{comic_id}", auth.base_url));
    detail.tags = tag_parts.join(", ");

    Ok(detail)
}

fn strip_html_tags(input: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap_or_else(|_| Regex::new("").unwrap());
    let cleaned = re.replace_all(input, " ").to_string();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_headers(auth: &BzAuthData) -> Vec<(String, String)> {
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
        ("Accept-Language".to_string(), "zh-CN,zh;q=0.9,en;q=0.8".to_string()),
    ];
    if !auth.tsid.is_empty() {
        headers.push(("Cookie".to_string(), format!("TSID={}", auth.tsid)));
    }
    headers
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value { Value::Object(map) => map, _ => Map::new() }
}

fn metadata_tags_to_csv(metadata: &Map<String, Value>) -> String {
    match metadata.get("tags") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| match v {
            Value::String(s) => Some(s.trim().to_string()),
            Value::Object(o) => o.get("name").and_then(Value::as_str).map(|s| s.trim().to_string()),
            _ => None,
        }).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    Value::Array(csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string())).collect())
}

fn read_bool_param(params: &Value, name: &str, default: bool) -> bool {
    match params.get(name) {
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(v)) => v.as_i64().unwrap_or(0) != 0,
        Some(Value::String(v)) => {
            let s = v.trim().to_ascii_lowercase();
            !(s.is_empty() || s == "0" || s == "false" || s == "no" || s == "off")
        }
        _ => default,
    }
}

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error.clear();
    });
}

fn set_error_and_zero(message: String) -> i32 {
    HostBridge::log(2, &message);
    STATE.with(|state| state.borrow_mut().error = message.into_bytes());
    0
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 { &[] } else { slice::from_raw_parts(ptr as *const u8, len as usize) }
}

// ===== HTTP Client =====

struct HttpTextResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_text: String,
}

fn http_get_text(url: &str, headers: &[(String, String)]) -> Result<(u16, String), String> {
    let resp = http_get_bytes_follow_redirects(url, headers)?;
    let text = String::from_utf8_lossy(&resp.body).to_string();
    Ok((resp.status, text))
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_get_bytes_follow_redirects(url: &str, headers: &[(String, String)]) -> Result<HttpResponse, String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let resp = http_get_once(&current, headers)?;
        if is_redirect(resp.status) {
            let location = find_header(&resp.headers, "Location").ok_or_else(|| format!("redirect {} without Location", resp.status))?;
            let base = Url::parse(&current).map_err(|e| e.to_string())?;
            current = base.join(location).map_err(|e| e.to_string())?.to_string();
            continue;
        }
        return Ok(resp);
    }
    Err("too many redirects".to_string())
}

fn http_get_once(url: &str, extra_headers: &[(String, String)]) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid url {url}: {e}"))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or("missing host")?;
    let port = parsed.port_or_known_default().ok_or("missing port")?;
    let mut path = parsed.path().to_string();
    if path.is_empty() { path.push('/'); }
    if let Some(q) = parsed.query() { path.push('?'); path.push_str(q); }

    let mut req = format!("GET {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {host}\r\n"));
    req.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    req.push_str("Accept: */*\r\n");
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");

    let stream = connect_stream(scheme, host, port)?;
    let raw = if scheme == "https" {
        read_https(stream, host, req.as_bytes(), &[])?
    } else {
        let mut s = stream;
        write_all(&mut s, req.as_bytes())?;
        read_all(&mut s)?
    };
    parse_http(&raw)
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
#[derive(Debug)]
struct HostTcpStream { stream: WasiTcpStream }
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let _ = stream.as_mut().set_recv_timeout(Some(timeout));
        let _ = stream.as_mut().set_send_timeout(Some(timeout));
        Ok(Self { stream })
    }
}
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl Read for HostTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stream.read(buf) }
}
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.stream.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct HostTcpStream { stream: TcpStream }
#[cfg(not(target_arch = "wasm32"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let addr = resolve_socket_addr(host, port)?;
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        Ok(Self { stream })
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl Read for HostTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stream.read(buf) }
}
#[cfg(not(target_arch = "wasm32"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.stream.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
}

fn connect_stream(scheme: &str, host: &str, port: u16) -> Result<HostTcpStream, String> {
    if scheme.eq_ignore_ascii_case("https") {
        if let Some((ph, pp)) = resolve_proxy(scheme) {
            let mut s = HostTcpStream::connect(&ph, pp, DEFAULT_TIMEOUT_MS)?;
            proxy_tunnel(&mut s, host, port)?;
            return Ok(s);
        }
    }
    HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)
}

fn resolve_proxy(scheme: &str) -> Option<(String, u16)> {
    let keys: &[&str] = if scheme.eq_ignore_ascii_case("https") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            if let Some(p) = parse_proxy(&raw) { return Some(p); }
        }
    }
    None
}

fn parse_proxy(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() { return None; }
    let normalized = if trimmed.contains("://") { trimmed.to_string() } else { format!("http://{trimmed}") };
    let parsed = Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(8080);
    Some((host, port))
}

fn proxy_tunnel(stream: &mut HostTcpStream, target_host: &str, target_port: u16) -> Result<(), String> {
    let req = format!("CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n");
    write_all(stream, req.as_bytes())?;
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 1024];
    loop {
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = &data[..pos + 4];
            let status_line = String::from_utf8_lossy(head).split("\r\n").next().unwrap_or_default().to_string();
            let status = status_line.split_whitespace().nth(1).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
            if !(200..300).contains(&status) { return Err(format!("proxy CONNECT failed: HTTP {status}")); }
            return Ok(());
        }
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { return Err("proxy closed before CONNECT response".to_string()); }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 64 * 1024 { return Err("proxy CONNECT response too large".to_string()); }
    }
}

fn write_all<T: Write>(stream: &mut T, buf: &[u8]) -> Result<(), String> {
    let mut sent = 0usize;
    while sent < buf.len() {
        let n = stream.write(&buf[sent..]).map_err(|e| e.to_string())?;
        if n == 0 { return Err("socket write returned 0".to_string()); }
        sent += n;
    }
    stream.flush().map_err(|e| e.to_string())
}

fn read_all<T: Read>(stream: &mut T) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}

fn read_https(stream: HostTcpStream, host: &str, head: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| format!("invalid tls server name: {host}"))?;
    let conn = ClientConnection::new(tls_config().clone(), server_name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, stream);
    write_all(&mut tls, head)?;
    if !body.is_empty() { write_all(&mut tls, body)?; }
    read_all(&mut tls)
}

fn tls_config() -> Arc<ClientConfig> {
    static TLS_CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    TLS_CFG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
    }).clone()
}

fn parse_http(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("missing headers")?;
    let (head, rest) = raw.split_at(header_end + 4);
    let header_text = String::from_utf8_lossy(head);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or("empty status line")?;
    let mut parts = status_line.split_whitespace();
    parts.next();
    let status = parts.next().ok_or("missing status")?.parse::<u16>().map_err(|e| format!("invalid status: {e}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        if let Some((n, v)) = line.split_once(':') { headers.push((n.trim().to_string(), v.trim().to_string())); }
    }
    let body = if is_chunked(&headers) {
        decode_chunked(rest)?
    } else if let Some(len) = content_length(&headers) {
        rest[..rest.len().min(len)].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpResponse { status, headers, body })
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    loop {
        let line_end = find_crlf(input, idx).ok_or("invalid chunked body")?;
        let size_line = String::from_utf8_lossy(&input[idx..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| format!("invalid chunk size: {size_hex}"))?;
        idx = line_end + 2;
        if size == 0 { break; }
        if idx + size > input.len() { return Err("truncated chunk".to_string()); }
        out.extend_from_slice(&input[idx..idx + size]);
        idx += size;
        if idx + 2 > input.len() || &input[idx..idx+2] != b"\r\n" { return Err("missing chunk terminator".to_string()); }
        idx += 2;
    }
    Ok(out)
}

fn find_crlf(input: &[u8], start: usize) -> Option<usize> {
    if start >= input.len() { return None; }
    input[start..].windows(2).position(|w| w == b"\r\n").map(|p| start + p)
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    find_header(headers, "content-length").and_then(|v| v.parse::<usize>().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    find_header(headers, "transfer-encoding").map(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("chunked"))).unwrap_or(false)
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or_else(|| format!("failed to resolve {host}:{port}"))
}
