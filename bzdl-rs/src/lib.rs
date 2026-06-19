use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::slice;
use std::sync::Arc;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;
const MAX_HTTP_RETRIES: usize = 3;
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
    #[serde(default)]
    params: Value,
    #[serde(default)]
    url: String,
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
    #[serde(default)]
    action: String,
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(default)]
    path: String,
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

    let action = input.action.trim();
    let result_bytes: Vec<u8> = match action {
        "resolve_page_asset" => resolve_page_asset(&input),
        "download_archive" => {
            let val = download_archive_action(&input);
            serde_json::to_vec(&val).unwrap_or_else(|e| {
                serde_json::to_vec(&output_err(&format!("encode error: {e}"))).unwrap_or_default()
            })
        }
        _ => {
            let val = run_download(&input);
            serde_json::to_vec(&val).unwrap_or_else(|e| {
                serde_json::to_vec(&output_err(&format!("encode error: {e}"))).unwrap_or_default()
            })
        }
    };
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = result_bytes;
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
        "name": "Baozi Downloader (Rust)",
        "type": "download",
        "namespace": "bzdl",
        "pre": ["bzlogin"],
        "source_id_regex": "^source:bzsource:.*$",
        "author": "Lanlu",
        "version": "1.0.0",
        "description": "Downloads comic chapters from Baozi Manhua (包子漫画).",
        "parameters": [
            {
                "name": "all_chapters",
                "type": "bool",
                "desc": "Download all chapters instead of first chapter only",
                "default_value": "0"
            }
        ],
        "url_regex": "https?://(cn|tw)\\.(bzmgcn\\.com|baozimhcn\\.com|webmota\\.com|kukuc\\.co|twmanga\\.com|dinnerku\\.com)/comic/[^/]+",
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "fs.write",
            "task_kv.read",
            "task_kv.write"
        ]
    })
}

fn run_download(input: &PluginInput) -> Value {
    let url = input.url.trim();
    if url.is_empty() { return output_err("No URL provided."); }

    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    let comic_id = match extract_comic_id(url) {
        Some(v) => v,
        None => return output_err("Invalid Baozi comic URL."),
    };

    let all_chapters = read_bool_param(&input.params, "all_chapters", false);

    HostBridge::progress(1, "获取漫画信息...");
    let detail_url = format!("{}/comic/{comic_id}", auth.base_url);
    let (status, html) = match http_get_with_retry(&detail_url, &build_headers(&auth), MAX_HTTP_RETRIES) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Detail fetch failed: {e}")),
    };
    if status != 200 { return output_err(&format!("Detail returned status {status}")); }

    let title = parse_title(&html);
    let chapters = parse_chapters(&html);
    if chapters.is_empty() { return output_err("No chapters found."); }

    let safe_title = sanitize_filename(&title);
    let folder_name = if safe_title.is_empty() { format!("baozi-{comic_id}") } else { format!("{safe_title}-{comic_id}") };
    let plugin_base = resolve_plugin_dir(&input.plugin_dir, "bzdl");
    let plugin_dir = format!("{plugin_base}/{folder_name}");
    if let Err(e) = fs::create_dir_all(&plugin_dir) {
        return output_err(&format!("Failed to create plugin dir: {e}"));
    }

    let chapters_to_dl = if all_chapters { &chapters[..] } else { &chapters[..1.min(chapters.len())] };
    let total_chapters = chapters_to_dl.len();
    let mut total_ok = 0usize;
    let mut total_fail = 0usize;

    for (ch_idx, (ep_id, ch_title)) in chapters_to_dl.iter().enumerate() {
        HostBridge::progress(
            (((ch_idx + 1) * 100) / total_chapters).clamp(1, 99) as i32,
            &format!("下载章节 {}/{}: {}", ch_idx + 1, total_chapters, ch_title),
        );

        let app_url = format!("https://appcn.baozimh.com/baozimhapp/comic/chapter/{comic_id}/0_{ep_id}.html");
        let images = match fetch_chapter_images(&app_url, &auth) {
            Ok(v) => v,
            Err(e) => {
                HostBridge::log(2, &format!("chapter {} fetch failed: {}", ep_id, e));
                continue;
            }
        };
        if images.is_empty() {
            HostBridge::log(2, &format!("chapter {} has no images", ep_id));
            continue;
        }

        let ch_dir = format!("{plugin_dir}/{:03}_{}", ch_idx + 1, sanitize_filename(ch_title));
        if let Err(e) = fs::create_dir_all(&ch_dir) {
            HostBridge::log(2, &format!("mkdir failed {ch_dir}: {e}"));
            continue;
        }

        for (img_idx, img_url) in images.iter().enumerate() {
            let ext = guess_ext(img_url);
            let filename = format!("{:04}.{}", img_idx + 1, ext);
            let mut out_path = PathBuf::from(&ch_dir);
            out_path.push(&filename);

            match download_file(img_url, Some(&app_url), &auth, &out_path) {
                Ok(_) => total_ok += 1,
                Err(err) => {
                    total_fail += 1;
                    HostBridge::log(1, &format!("download failed: {} ({err})", img_url));
                }
            }
        }
    }

    HostBridge::progress(100, &format!("完成. 成功: {total_ok}, 失败: {total_fail}"));
    if total_ok == 0 { return output_err("All downloads failed."); }

    json!({
        "success": true,
        "data": [{
            "plugin_relative_path": folder_name,
            "relative_path": folder_name,
            "filename": folder_name,
            "source": url,
            "downloaded_count": total_ok,
            "failed_count": total_fail,
            "archive_type": "folder"
        }]
    })
}

/// resolve_page_asset action（targetType=source，直连执行）：
/// path = "{comicId}_{epId}/{page_num}"，直接返回图片二进制数据。
fn resolve_page_asset(input: &PluginInput) -> Vec<u8> {
    let path = input.path.trim();
    if path.is_empty() {
        return build_binary_response(&output_err("path is required for resolve_page_asset"), &[]);
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return build_binary_response(&output_err(&format!("invalid path: {path}")), &[]);
    }
    let chapter_id = parts[0]; // comicId_epId
    let page: u64 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return build_binary_response(&output_err(&format!("invalid page: {path}")), &[]),
    };
    if page == 0 { return build_binary_response(&output_err("page must be >= 1"), &[]); }

    HostBridge::progress(10, "加载登录态...");
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&e), &[]),
    };

    // Split chapter_id into comic_id and ep_id
    let id_parts: Vec<&str> = chapter_id.splitn(2, '_').collect();
    if id_parts.len() < 2 {
        return build_binary_response(&output_err(&format!("invalid chapter_id: {chapter_id}")), &[]);
    }
    let comic_id = id_parts[0];
    let ep_id = id_parts[1];

    let app_url = format!("https://appcn.baozimh.com/baozimhapp/comic/chapter/{comic_id}/0_{ep_id}.html");

    HostBridge::progress(30, "获取章节图片列表...");
    let cache_key = format!("bzdl_chapter_images_{chapter_id}");
    let images: Vec<String> = match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => {
            cached.as_array().map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let images = if !images.is_empty() { images } else {
        let fetched = match fetch_chapter_images(&app_url, &auth) {
            Ok(v) => v,
            Err(e) => return build_binary_response(&output_err(&e), &[]),
        };
        if fetched.is_empty() {
            return build_binary_response(&output_err("no images in chapter"), &[]);
        }
        let _ = HostBridge::task_kv_set(&cache_key, json!(fetched));
        fetched
    };

    let idx = (page - 1) as usize;
    if idx >= images.len() {
        return build_binary_response(&output_err(&format!("page {page} out of range ({})", images.len())), &[]);
    }

    let img_url = &images[idx];
    let ext = guess_ext(img_url);
    let content_type = if ext == "jpg" || ext == "jpeg" { "image/jpeg" }
        else if ext == "png" { "image/png" }
        else if ext == "webp" { "image/webp" }
        else if ext == "gif" { "image/gif" }
        else { "application/octet-stream" };

    HostBridge::progress(70, &format!("下载第 {} 页...", page));
    let img_headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "image/webp,image/apng,image/*,*/*;q=0.8".to_string()),
        ("Referer".to_string(), app_url.clone()),
    ];
    let resp = match http_get_bytes(&img_url, &img_headers) {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&format!("image download: {e}")), &[]),
    };
    if resp.status != 200 {
        return build_binary_response(&output_err(&format!("image HTTP {}", resp.status)), &[]);
    }

    HostBridge::progress(100, "单页资源解析完成");
    let success_json = json!({"success": true, "content_type": content_type});
    build_binary_response(&success_json, &resp.body)
}

/// download_archive action：从 targetId 解析 remoteId，复用整本下载流程。
fn download_archive_action(input: &PluginInput) -> Value {
    let target_id = input.target_id.trim();
    let comic_id = match target_id.strip_prefix("source:bzsource:") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return output_err(&format!("invalid sourceId: {target_id}")),
    };

    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    // 构造一个兼容 run_download 的 url
    let fake_url = format!("{}/comic/{}", auth.base_url, comic_id);
    let mut fake_input = PluginInput {
        plugin_type: input.plugin_type.clone(),
        params: input.params.clone(),
        url: fake_url,
        plugin_dir: input.plugin_dir.clone(),
        action: String::new(),
        target_type: String::new(),
        target_id: String::new(),
        path: String::new(),
        extra_params: Value::Null,
    };
    run_download(&fake_input)
}

fn build_binary_response(json_val: &Value, binary: &[u8]) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(json_val).unwrap_or_else(|_| b"{}".to_vec());
    let json_len = json_bytes.len() as u32;
    let mut out = Vec::with_capacity(4 + json_bytes.len() + binary.len());
    out.extend_from_slice(&json_len.to_le_bytes());
    out.extend_from_slice(&json_bytes);
    out.extend_from_slice(binary);
    out
}

fn http_get_bytes(url: &str, extra_headers: &[(String, String)]) -> Result<HttpResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..MAX_HTTP_RETRIES {
        if attempt > 0 {
            HostBridge::log(1, &format!("http_get_bytes retry {}/{}", attempt + 1, MAX_HTTP_RETRIES));
        }
        match http_get_once_raw(url, extra_headers) {
            Ok(resp) => {
                if resp.status == 429 {
                    let delay = (1u64 << attempt).min(60);
                    HostBridge::log(1, &format!("rate limited, retry in {delay}s"));
                    std::thread::sleep(std::time::Duration::from_secs(delay));
                    continue;
                }
                if resp.status >= 500 || resp.status == 408 || resp.status == 425 {
                    last_err = format!("HTTP {}", resp.status);
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                last_err = e;
                continue;
            }
        }
    }
    Err(last_err)
}

fn http_get_once_raw(url: &str, extra_headers: &[(String, String)]) -> Result<HttpResponse, String> {
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
    req.push_str("Accept: image/webp,image/apng,image/*,*/*;q=0.8\r\n");
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");

    use std::io::Read;
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

fn load_bz_auth() -> Result<BzAuthData, String> {
    let value = HostBridge::task_kv_get(AUTH_DATA_KEY)?.ok_or("Missing bzlogin auth data. Ensure bzlogin ran as a pre hook.")?;
    serde_json::from_value(value).map_err(|e| format!("Invalid bzlogin auth data: {e}"))
}

fn extract_comic_id(url: &str) -> Option<String> {
    let re = Regex::new(r"/comic/([^/\s?#]+)").ok()?;
    re.captures(url)?.get(1).map(|m| m.as_str().to_string())
}

fn parse_title(html: &str) -> String {
    if let Some(caps) = Regex::new(r#"<h1[^>]*class=["']?comics-detail__title["']?[^>]*>(.*?)</h1>"#).ok().and_then(|re| re.captures(html)) {
        return strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }
    if let Some(caps) = Regex::new(r#"<title[^>]*>(.*?)</title>"#).ok().and_then(|re| re.captures(html)) {
        return strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }
    String::new()
}

fn parse_chapters(html: &str) -> Vec<(String, String)> {
    let mut chapters = Vec::new();
    // Try to find chapter links with slot numbers
    let re = Regex::new(r#"<a[^>]*href=["']?/chapter/[^"']*?/(\d+)_["']?[^>]*>.*?<span[^>]*>(.*?)</span>.*?</a>"#).ok();
    if let Some(re) = re {
        for caps in re.captures_iter(html) {
            let ep_id = caps.get(1).map(|m| m.as_str()).unwrap_or("0").to_string();
            let title = strip_tags(caps.get(2).map(|m| m.as_str()).unwrap_or(""));
            if !ep_id.is_empty() && !title.is_empty() {
                chapters.push((ep_id, title));
            }
        }
    }
    if chapters.is_empty() {
        // Fallback: extract from chapter-items
        let block_re = Regex::new(r#"<div[^>]*id=["']?chapter-items["']?[^>]*>(.*?)</div>"#).ok();
        if let Some(block_caps) = block_re.and_then(|re| re.captures(html)) {
            let block = block_caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let ch_re = Regex::new(r#"<a[^>]*>.*?<span[^>]*>(.*?)</span>.*?</a>"#).ok();
            if let Some(ch_re) = ch_re {
                for (i, caps) in ch_re.captures_iter(block).enumerate() {
                    let title = strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
                    if !title.is_empty() {
                        chapters.push((i.to_string(), title));
                    }
                }
            }
        }
    }
    chapters
}

fn fetch_chapter_images(url: &str, auth: &BzAuthData) -> Result<Vec<String>, String> {
    let (status, html) = http_get_with_retry(url, &build_headers(auth), MAX_HTTP_RETRIES)?;
    if status != 200 { return Err(format!("HTTP {status}")); }
    Ok(parse_chapter_images(&html, auth))
}

fn parse_chapter_images(html: &str, auth: &BzAuthData) -> Vec<String> {
    let mut images = Vec::new();
    let re = Regex::new(r#"data-src=["']([^"']+)["']"#).ok();
    if let Some(re) = re {
        for caps in re.captures_iter(html) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if raw.is_empty() { continue; }
            let url = transform_image_url(&raw, auth);
            if !images.contains(&url) { images.push(url); }
        }
    }
    if images.is_empty() {
        let re = Regex::new(r#"<img[^>]*src=["']([^"']+)["']"#).ok();
        if let Some(re) = re {
            for caps in re.captures_iter(html) {
                let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                if raw.is_empty() || raw.starts_with("data:") { continue; }
                let url = transform_image_url(&raw, auth);
                if !images.contains(&url) { images.push(url); }
            }
        }
    }
    images
}

fn transform_image_url(raw: &str, auth: &BzAuthData) -> String {
    if raw.starts_with("http") {
        let re = Regex::new(r"^(https?://)([^/\s:]+)(:\d+)?(/[a-z]comic/.*)").ok();
        if let Some(caps) = re.and_then(|r| r.captures(raw)) {
            let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("https://");
            let domain = if auth.cdn_domains.is_empty() { caps.get(2).map(|m| m.as_str()).unwrap_or("") } else { &auth.cdn_domains };
            let path = caps.get(4).map(|m| m.as_str()).unwrap_or("");
            let quality = if auth.image_quality.is_empty() { "" } else { &auth.image_quality };
            return format!("{scheme}{domain}{quality}{path}");
        }
        return raw.to_string();
    }
    raw.to_string()
}

fn download_file(url: &str, referer: Option<&str>, auth: &BzAuthData, output: &PathBuf) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "image/*,*/*".to_string()),
    ];
    if let Some(r) = referer {
        headers.push(("Referer".to_string(), r.to_string()));
    }
    let (status, body) = http_get_with_retry(url, &headers, MAX_HTTP_RETRIES)?;
    if status >= 400 { return Err(format!("HTTP {status}")); }
    if body.is_empty() { return Err("empty response body".to_string()); }
    let mut file = File::create(output).map_err(|e| e.to_string())?;
    file.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

fn build_headers(auth: &BzAuthData) -> Vec<(String, String)> {
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
    ];
    if !auth.tsid.is_empty() {
        headers.push(("Cookie".to_string(), format!("TSID={}", auth.tsid)));
    }
    headers
}

fn strip_tags(input: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap_or_else(|_| Regex::new("").unwrap());
    re.replace_all(input, " ").to_string().split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sanitize_filename(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ' ' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out.trim().trim_matches('_').to_string()
}

fn resolve_plugin_dir(raw: &str, ns: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() { format!("./data/cache/plugins/{ns}") } else { trimmed.to_string() }
}

fn guess_ext(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        if let Some(seg) = parsed.path_segments().and_then(|mut s| s.next_back()) {
            if let Some((_, ext)) = seg.rsplit_once('.') {
                let ext = ext.to_ascii_lowercase();
                if !ext.is_empty() && ext.len() <= 6 { return ext; }
            }
        }
    }
    "jpg".to_string()
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

fn output_err(msg: &str) -> Value {
    json!({ "success": false, "error": msg })
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

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_get_with_retry(url: &str, extra_headers: &[(String, String)], max_retries: usize) -> Result<(u16, String), String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_get(url, extra_headers) {
            Ok(response) => {
                if response.status == 429 {
                    let wait_ms = 1_000u64.saturating_mul(attempt as u64 + 1);
                    if attempt >= max_retries { return Err(format!("HTTP 429 for {url}")); }
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms.min(60_000)));
                    continue;
                }
                if is_retryable_status(response.status) {
                    last_err = format!("HTTP {}", response.status);
                    if attempt >= max_retries { return Ok((response.status, String::from_utf8_lossy(&response.body).to_string())); }
                    let wait_ms = 250u64.saturating_mul(attempt as u64 + 1);
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                    continue;
                }
                let text = String::from_utf8_lossy(&response.body).to_string();
                return Ok((response.status, text));
            }
            Err(err) => {
                if attempt >= max_retries || !is_retryable_network_error(&err) { return Err(err); }
                last_err = err;
                let wait_ms = 200u64.saturating_mul(attempt as u64 + 1);
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
            }
        }
    }
    Err(last_err)
}

fn http_get(url: &str, extra_headers: &[(String, String)]) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let response = http_get_once(&current_url, extra_headers)?;
        if is_redirect(response.status) {
            let location = find_header(&response.headers, "location").ok_or_else(|| format!("redirect {} without Location", response.status))?;
            let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
            current_url = base.join(location).map_err(|e| e.to_string())?.to_string();
            continue;
        }
        return Ok(response);
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

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
struct HostTcpStream { stream: WasiTcpStream }
#[cfg(target_arch = "wasm32")]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let _ = stream.as_mut().set_recv_timeout(Some(timeout));
        let _ = stream.as_mut().set_send_timeout(Some(timeout));
        Ok(Self { stream })
    }
}
#[cfg(target_arch = "wasm32")]
impl Read for HostTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stream.read(buf) }
}
#[cfg(target_arch = "wasm32")]
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
        let _ = stream.set_nodelay(true);
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

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 500 | 502 | 503 | 504)
}

fn is_retryable_network_error(err: &str) -> bool {
    let s = err.to_ascii_lowercase();
    s.contains("resource temporarily unavailable") || s.contains("would block") || s.contains("timed out") || s.contains("interrupted") || s.contains("connection reset")
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or_else(|| format!("failed to resolve {host}:{port}"))
}
