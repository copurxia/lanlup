use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Lanlu/v1.00 (https://github.com/copurxia/lanlu)";
const HTTP_TIMEOUT_MS: i32 = 15000;
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
    action: String,
    #[serde(default)]
    params: Value,
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

    HostBridge::log(1, &format!("bzsource action={}", input.action));

    let result = match input.action.as_str() {
        "source_home" => run_source_home(&input),
        "source_search" => run_source_search(&input),
        "source_detail" => run_source_detail(&input),
        "source_download" => run_source_download(&input),
        _ => output_err(&format!("unknown source action: {}", input.action)),
    };

    match serde_json::to_vec(&result) {
        Ok(bytes) => STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.result = bytes;
            state.result.as_ptr() as i32
        }),
        Err(e) => set_error_and_zero(format!("failed to encode output: {e}")),
    }
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
        "name": "Baozi Source (Rust)",
        "plugin_type": "Source",
        "namespace": "bzsource",
        "pre": ["bzlogin"],
        "author": "Lanlu",
        "version": "1.0.0",
        "description": "Browse and search Baozi Manhua (包子漫画) comics.",
        "parameters": [],
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read"
        ]
    })
}

fn load_bz_auth() -> Result<BzAuthData, String> {
    let value = HostBridge::task_kv_get(AUTH_DATA_KEY)?.ok_or("Missing bzlogin auth data. Ensure bzlogin ran.")?;
    serde_json::from_value(value).map_err(|e| format!("Invalid auth data: {e}"))
}

fn build_headers(auth: &BzAuthData) -> Vec<(String, String)> {
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
    ];
    if !auth.tsid.is_empty() {
        headers.push(("Cookie".to_string(), format!("TSID={}", auth.tsid)));
    }
    headers
}

fn run_source_home(input: &PluginInput) -> Value {
    HostBridge::progress(5, "加载首页...");
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };
    let page = input.params.get("page").and_then(|v| v.as_u64()).unwrap_or(1);
    let url = format!("{}/api/bzmhq/amp_comic_list?type=all&region=all&state=all&filter=%2a&page={page}&limit=36&language={}&__amp_source_origin={}", auth.base_url, auth.language, auth.base_url);
    let (status, text) = match http_get_with_retry(&url, &build_headers(&auth), MAX_HTTP_RETRIES) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to fetch home: {e}")),
    };
    if status != 200 { return output_err(&format!("Home API returned status {status}")); }

    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse home response: {e}")),
    };
    let items = map_comic_list_items(&parsed, &auth);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };
    HostBridge::progress(100, "首页加载完成");
    output_ok_data(json!({ "items": items, "next_page": next_page }))
}

fn run_source_search(input: &PluginInput) -> Value {
    HostBridge::progress(5, "搜索中...");
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };
    let query = input.params.get("query").and_then(Value::as_str).unwrap_or("");
    let page = input.params.get("page").and_then(|v| v.as_u64()).unwrap_or(1);
    if query.is_empty() { return output_err("query is required for search"); }

    let encoded = urlencoding::encode(query);
    let url = format!("{}/search?q={encoded}&page={page}", auth.base_url);
    let (status, html) = match http_get_with_retry(&url, &build_headers(&auth), MAX_HTTP_RETRIES) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Search failed: {e}")),
    };
    if status != 200 { return output_err(&format!("Search returned status {status}")); }

    let items = parse_search_html(&html, &auth);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };
    HostBridge::progress(100, "搜索完成");
    output_ok_data(json!({ "items": items, "next_page": next_page }))
}

fn run_source_detail(input: &PluginInput) -> Value {
    HostBridge::progress(10, "加载详情...");
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };
    let comic_id = extract_remote_id(&input.params);
    if comic_id.is_empty() { return output_err("remote_id is required for detail"); }

    let url = format!("{}/comic/{comic_id}", auth.base_url);
    let (status, html) = match http_get_with_retry(&url, &build_headers(&auth), MAX_HTTP_RETRIES) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Detail fetch failed: {e}")),
    };
    if status != 200 { return output_err(&format!("Detail returned status {status}")); }

    let detail = parse_detail_html(&html, &comic_id, &auth);
    HostBridge::progress(100, "详情加载完成");
    output_ok_data(json!({
        "id": comic_id,
        "title": detail.title,
        "description": detail.description,
        "cover": detail.cover,
        "tags": detail.tags,
        "chapters": detail.chapters,
        "archives": [{
            "id": comic_id,
            "title": detail.title,
            "filename": format!("baozi-{comic_id}.zip"),
            "size": 0
        }],
    }))
}

fn run_source_download(input: &PluginInput) -> Value {
    let auth = match load_bz_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };
    let comic_id = extract_remote_id(&input.params);
    if comic_id.is_empty() { return output_err("remote_id is required for download"); }
    let ep_id = input.params.get("ep_id").and_then(Value::as_str).unwrap_or("0");

    // Fetch chapter images from app URL
    let app_url = format!("https://appcn.baozimh.com/baozimhapp/comic/chapter/{comic_id}/0_{ep_id}.html");
    HostBridge::log(1, &format!("bzsource download GET {app_url}"));

    let (status, html) = match http_get_with_retry(&app_url, &build_headers(&auth), MAX_HTTP_RETRIES) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Chapter fetch failed: {e}")),
    };
    if status != 200 { return output_err(&format!("Chapter returned status {status}")); }

    let images = parse_chapter_images(&html, &auth);
    output_ok_data(json!({ "images": images }))
}

fn extract_remote_id(params: &Value) -> String {
    params.get("remote_id").and_then(Value::as_str)
        .or_else(|| params.get("__target_id").and_then(Value::as_str))
        .unwrap_or("").to_string()
}

fn map_comic_list_items(parsed: &Value, auth: &BzAuthData) -> Vec<Value> {
    parsed.get("items").and_then(Value::as_array).cloned().unwrap_or_default()
        .iter().map(|item| {
            let id = item.get("comic_id").and_then(Value::as_str).unwrap_or("").to_string();
            let title = item.get("name").and_then(Value::as_str).unwrap_or("Untitled").to_string();
            let author = item.get("author").and_then(Value::as_str).unwrap_or("").to_string();
            let cover = item.get("topic_img").and_then(Value::as_str).unwrap_or("").to_string();
            let cover_url = if !cover.is_empty() {
                if cover.starts_with("http") { cover } else { format!("https://static-tw.baozimh.com/cover/{cover}?w=285&h=375&q=100") }
            } else { String::new() };
            let tags = item.get("type_names").and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(|t| t.as_str()).map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            json!({
                "id": id,
                "title": title,
                "subtitle": author,
                "cover": cover_url,
                "tags": tags,
                "source": "baozi"
            })
        }).collect()
}

fn parse_search_html(html: &str, auth: &BzAuthData) -> Vec<Value> {
    let mut items = Vec::new();
    // Match div.comics-card blocks
    let card_re = Regex::new(r#"<div[^>]*class=["']?comics-card["']?[^>]*>(.*?)</div>\s*(?=<div|$)"#).ok();
    if let Some(re) = card_re {
        for caps in re.captures_iter(html) {
            let block = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let id = extract_attr(block, "href").and_then(|href| {
                href.split('/').last().map(|s| s.to_string())
            }).unwrap_or_default();
            let title = extract_tag_text(block, "h3").unwrap_or_default();
            let cover = extract_attr(block, "src").unwrap_or_default();
            let mut tags = Vec::new();
            if let Ok(tag_re) = Regex::new(r#"<span[^>]*>(.*?)</span>"#) {
                for cap in tag_re.captures_iter(block) {
                    let t = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim().to_string();
                    if !t.is_empty() { tags.push(t); }
                }
            }
            if !id.is_empty() && !title.is_empty() {
                items.push(json!({
                    "id": id,
                    "title": title,
                    "subtitle": "",
                    "cover": cover,
                    "tags": tags,
                    "source": "baozi"
                }));
            }
        }
    }
    items
}

#[derive(Default)]
struct DetailResult {
    title: String,
    description: String,
    cover: String,
    tags: Vec<String>,
    chapters: Vec<Value>,
}

fn parse_detail_html(html: &str, comic_id: &str, auth: &BzAuthData) -> DetailResult {
    let mut result = DetailResult::default();

    if let Some(caps) = Regex::new(r#"<h1[^>]*class=["']?comics-detail__title["']?[^>]*>(.*?)</h1>"#).ok().and_then(|re| re.captures(html)) {
        result.title = strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }
    if result.title.is_empty() {
        if let Some(caps) = Regex::new(r#"<title[^>]*>(.*?)</title>"#).ok().and_then(|re| re.captures(html)) {
            result.title = strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
        }
    }

    if let Some(caps) = Regex::new(r#"<p[^>]*class=["']?comics-detail__desc["']?[^>]*>(.*?)</p>"#).ok().and_then(|re| re.captures(html)) {
        result.description = strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }

    if let Some(caps) = Regex::new(r#"<div[^>]*class=["']?l-content["']?[^>]*>.*?<amp-img[^>]*src=["']([^"']+)["']"#).ok().and_then(|re| re.captures(html)) {
        result.cover = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
    }
    if result.cover.is_empty() {
        if let Some(caps) = Regex::new(r#"<amp-img[^>]*src=["']([^"']+)["']"#).ok().and_then(|re| re.captures(html)) {
            result.cover = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        }
    }

    let mut author = String::new();
    if let Some(caps) = Regex::new(r#"<h2[^>]*class=["']?comics-detail__author["']?[^>]*>(.*?)</h2>"#).ok().and_then(|re| re.captures(html)) {
        author = strip_tags(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
    }

    if let Some(caps) = Regex::new(r#"<div[^>]*class=["']?tag-list["']?[^>]*>(.*?)</div>"#).ok().and_then(|re| re.captures(html)) {
        let block = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Ok(tag_re) = Regex::new(r#"<span[^>]*>(.*?)</span>"#) {
            for cap in tag_re.captures_iter(block) {
                let t = strip_tags(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
                if !t.is_empty() { result.tags.push(t); }
            }
        }
    }
    if !author.is_empty() {
        result.tags.push(format!("author:{author}"));
    }

    // Parse chapters from #chapter-items and #chapters_other_list
    let mut chapter_map = Vec::new();
    for pattern in [
        r#"<div[^>]*id=["']?chapter-items["']?[^>]*>(.*?)</div>"#,
        r#"<div[^>]*id=["']?chapters_other_list["']?[^>]*>(.*?)</div>"#,
    ] {
        if let Some(caps) = Regex::new(pattern).ok().and_then(|re| re.captures(html)) {
            let block = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Ok(ch_re) = Regex::new(r#"<a[^>]*href=["']?/chapter/[^"']*["']?[^>]*>.*?<span[^>]*>(.*?)</span>.*?</a>"#) {
                for cap in ch_re.captures_iter(block) {
                    let name = strip_tags(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
                    if !name.is_empty() { chapter_map.push(name); }
                }
            }
        }
    }
    if chapter_map.is_empty() {
        // Fallback: any comics-chapters > a > div > span
        if let Ok(ch_re) = Regex::new(r#"<div[^>]*class=["']?comics-chapters["']?[^>]*>.*?<a[^>]*>.*?<span[^>]*>(.*?)</span>.*?</a>.*?</div>"#) {
            for cap in ch_re.captures_iter(html) {
                let name = strip_tags(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
                if !name.is_empty() { chapter_map.push(name); }
            }
        }
    }

    for (i, name) in chapter_map.iter().enumerate() {
        result.chapters.push(json!({
            "id": i.to_string(),
            "title": name,
            "page_count": 0,
        }));
    }

    result
}

fn parse_chapter_images(html: &str, auth: &BzAuthData) -> Vec<String> {
    let mut images = Vec::new();
    let img_re = Regex::new(r#"data-src=["']([^"']+)["']"#).ok();
    if let Some(re) = img_re {
        for caps in re.captures_iter(html) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if raw.is_empty() { continue; }
            let url = transform_image_url(&raw, auth);
            if !images.contains(&url) { images.push(url); }
        }
    }
    // Also match src attributes for images
    if images.is_empty() {
        let src_re = Regex::new(r#"<img[^>]*src=["']([^"']+)["']"#).ok();
        if let Some(re) = src_re {
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
        // Apply CDN and quality overrides
        let re = Regex::new(r"^(https?://)([^/\s:]+)(:\d+)?(/[a-z]comic/.*)").ok();
        if let Some(caps) = re.and_then(|r| r.captures(raw)) {
            let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("https://");
            let domain = if auth.cdn_domains.is_empty() {
                caps.get(2).map(|m| m.as_str()).unwrap_or("")
            } else {
                &auth.cdn_domains
            };
            let path = caps.get(4).map(|m| m.as_str()).unwrap_or("");
            let quality = if auth.image_quality.is_empty() { "" } else { &auth.image_quality };
            return format!("{scheme}{domain}{quality}{path}");
        }
        return raw.to_string();
    }
    raw.to_string()
}

fn strip_tags(input: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap_or_else(|_| Regex::new("").unwrap());
    re.replace_all(input, " ").to_string().split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_attr(html: &str, attr: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"{}=["']([^"']+)["']"#, attr)).ok()?;
    re.captures(html)?.get(1).map(|m| m.as_str().to_string())
}

fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"<{}[^>]*>(.*?)</{}>"#, tag, tag)).ok()?;
    re.captures(html)?.get(1).map(|m| strip_tags(m.as_str())).filter(|s| !s.is_empty())
}

fn output_err(message: &str) -> Value {
    json!({ "success": false, "error": message })
}

fn output_ok_data(data: Value) -> Value {
    json!({ "success": true, "data": data })
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
            let mut s = HostTcpStream::connect(&ph, pp, HTTP_TIMEOUT_MS)?;
            proxy_tunnel(&mut s, host, port)?;
            return Ok(s);
        }
    }
    HostTcpStream::connect(host, port, HTTP_TIMEOUT_MS)
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
