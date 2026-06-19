use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs;
use std::io::{Read, Write};
use std::slice;
use std::sync::{Arc, OnceLock};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Lanlu/v1.00 (https://github.com/copurxia/lanlu)";
const HTTP_TIMEOUT_MS: i32 = 15000;
const MAX_REDIRECTS: usize = 5;
const AUTH_DATA_KEY: &str = "__lanlu.phase.nhlogin.data";
const MAX_HTTP_RETRIES: usize = 3;
const NHENTAI_API_BASE: &str = "https://nhentai.net/api/v2";
const DEFAULT_IMAGE_CDN: &str = "https://i.nhentai.net";

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
#[allow(dead_code)]
struct PluginInput {
    #[serde(rename = "pluginType", default)]
    plugin_type: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NhAuthData {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    api_key: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
struct HostTcpStream {
    stream: WasiTcpStream,
}

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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(target_arch = "wasm32")]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct HostTcpStream {
    stream: TcpStream,
}

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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct HostBridge;

impl HostBridge {
    fn log(level: i32, message: &str) {
        unsafe {
            let _ = host_log(level, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn progress(percent: i32, message: &str) {
        unsafe {
            let _ = host_progress(percent, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn call(method: &str, params: Value) -> Result<Value, String> {
        let req = json!({
            "method": method,
            "params": params,
        });
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 {
            return Err(Self::read_error());
        }
        Self::read_response()
    }

    fn read_response() -> Result<Value, String> {
        let len = unsafe { host_response_len() };
        if len < 0 { return Err("host_response_len returned negative".to_string()); }
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
        let response = Self::call("task_kv.get", json!({"key": key}))?;
        let found = response.get("found").and_then(Value::as_bool).unwrap_or(false);
        if !found { return Ok(None); }
        Ok(response.get("value").cloned())
    }

    fn task_kv_set(key: &str, value: Value) -> Result<(), String> {
        Self::call("task_kv.set", json!({"key": key, "value": value}))?;
        Ok(())
    }
}

unsafe fn read_guest_bytes(ptr: i32, len: i32) -> &'static [u8] {
    slice::from_raw_parts(ptr as *const u8, len as usize)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_alloc(size: i32) -> i32 {
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_free(ptr: i32, size: i32) {
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

    HostBridge::log(1, &format!("nhsource action={}", input.action));

    let result = match input.action.as_str() {
        "source_home" => run_source_home(&input),
        "source_search" => run_source_search(&input),
        "source_filters" => run_source_filters(&input),
        "source_detail" | "source_download" | "source_reader" | "source_page_asset" | "source_cover_asset" => {
            output_err("this action has been moved to the Metadata or Download plugin")
        }
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

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error.clear();
    });
}

fn set_error_and_zero(msg: String) -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.error = msg.into_bytes();
        0
    })
}

fn run_source_filters(_input: &PluginInput) -> Value {
    output_ok_data(json!({
        "filters": [
            {
                "key": "category",
                "label": "分类",
                "type": "select",
                "options": [
                    { "label": "全部", "value": "" },
                    { "label": "同人志", "value": "doujinshi" },
                    { "label": "漫画", "value": "manga" },
                    { "label": "画集", "value": "artistcg" },
                    { "label": "游戏CG", "value": "game" }
                ]
            },
            {
                "key": "language",
                "label": "语言",
                "type": "select",
                "options": [
                    { "label": "全部", "value": "" },
                    { "label": "中文", "value": "chinese" },
                    { "label": "日文", "value": "japanese" },
                    { "label": "英文", "value": "english" }
                ]
            },
            {
                "key": "sort",
                "label": "排序",
                "type": "select",
                "options": [
                    { "label": "最新", "value": "date" },
                    { "label": "人气", "value": "popular" },
                    { "label": "评分", "value": "rating" }
                ]
            }
        ]
    }))
}

fn output_err(message: &str) -> Value {
    json!({
        "success": false,
        "error": message
    })
}

fn output_ok_data(data: Value) -> Value {
    json!({
        "success": true,
        "data": data
    })
}

fn load_nh_auth() -> Result<NhAuthData, String> {
    let value = HostBridge::task_kv_get(AUTH_DATA_KEY)?
        .ok_or_else(|| "Missing nhentai auth data. Ensure nhlogin ran.".to_string())?;
    serde_json::from_value(value).map_err(|e| format!("Invalid auth data: {e}"))
}

fn build_api_auth_headers(auth: &NhAuthData) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    headers.push(("User-Agent".to_string(), USER_AGENT.to_string()));
    if !auth.api_key.is_empty() {
        headers.push(("Authorization".to_string(), format!("Key {}", auth.api_key)));
    }
    headers
}

fn api_get(url: &str, auth: &NhAuthData) -> Result<(u16, String), String> {
    let headers = build_api_auth_headers(auth);
    let response = http_get_with_retry(url, None, &[], "application/json", &headers, MAX_HTTP_RETRIES)?;
    let text = String::from_utf8_lossy(&response.body).to_string();
    Ok((response.status, text))
}

fn run_source_home(input: &PluginInput) -> Value {
    HostBridge::progress(5, "加载首页...");
    let auth = match load_nh_auth() {
        Ok(v) => v,
        Err(_) => NhAuthData { mode: String::new(), api_key: String::new() },
    };

    let page = read_page(&input.params);
    let url = format!("{NHENTAI_API_BASE}/galleries?page={page}");
    let (status, text) = match api_get(&url, &auth) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to fetch galleries: {e}")),
    };
    if status != 200 {
        return output_err(&format!("Home API returned status {status}"));
    }

    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse home response: {e}")),
    };

    let items = map_gallery_list_items(&parsed);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };
    HostBridge::progress(100, "首页加载完成");
    output_ok_data(json!({
        "items": items,
        "next_page": next_page,
    }))
}

fn run_source_search(input: &PluginInput) -> Value {
    HostBridge::progress(5, "搜索中...");
    let auth = match load_nh_auth() {
        Ok(v) => v,
        Err(_) => NhAuthData { mode: String::new(), api_key: String::new() },
    };

    let query = input.params.get("query").and_then(Value::as_str).unwrap_or("");
    let page = read_page(&input.params);
    let sort = input.params.get("sort").and_then(Value::as_str).unwrap_or("date");

    if query.is_empty() {
        return output_err("query is required for search");
    }

    let encoded_query = urlencoding_encode(query);
    let url = format!(
        "{NHENTAI_API_BASE}/search?query={encoded_query}&page={page}&sort={sort}"
    );
    let (status, text) = match api_get(&url, &auth) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Search failed: {e}")),
    };
    if status != 200 {
        return output_err(&format!("Search API returned status {status}"));
    }

    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse search response: {e}")),
    };

    let items = map_gallery_list_items(&parsed);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };

    HostBridge::progress(100, "搜索完成");
    output_ok_data(json!({
        "items": items,
        "next_page": next_page,
    }))
}

fn run_source_detail(input: &PluginInput) -> Value {
    HostBridge::progress(10, "加载详情...");
    let auth = match load_nh_auth() {
        Ok(v) => v,
        Err(_) => NhAuthData { mode: String::new(), api_key: String::new() },
    };

    let gallery_id = extract_remote_id(&input.params);
    if gallery_id.is_empty() {
        return output_err("remote_id (gallery_id) is required for detail");
    }

    let url = format!("{NHENTAI_API_BASE}/galleries/{gallery_id}");
    let (status, text) = match api_get(&url, &auth) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Detail fetch failed: {e}")),
    };
    if status != 200 {
        return output_err(&format!("Detail API returned status {status}"));
    }

    let gallery: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse detail: {e}")),
    };

    let title = gallery.get("title").cloned().unwrap_or(Value::Null);
    let english_title = title.get("english").and_then(Value::as_str).unwrap_or("Untitled");
    let japanese_title = title.get("japanese").and_then(Value::as_str).unwrap_or("");
    let pretty_title = title.get("pretty").and_then(Value::as_str).unwrap_or("");

    let cover_path = gallery.get("cover")
        .and_then(|c| c.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let cover_url = if !cover_path.is_empty() {
        format!("https://t.nhentai.net/{}", cover_path.trim_start_matches('/'))
    } else {
        String::new()
    };

    let scans = gallery.get("scanlator").and_then(Value::as_str).unwrap_or("");

    let tags: Vec<String> = gallery.get("tags").and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|tag| tag.get("name").and_then(Value::as_str))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let num_pages = gallery.get("num_pages").and_then(|v| v.as_u64()).unwrap_or(0);
    let num_favorites = gallery.get("num_favorites").and_then(|v| v.as_u64()).unwrap_or(0);

    let mut description = String::new();
    if !english_title.is_empty() {
        description.push_str(english_title);
    }
    if !japanese_title.is_empty() && japanese_title != english_title {
        if !description.is_empty() { description.push('\n'); }
        description.push_str(japanese_title);
    }
    if !scans.is_empty() {
        if !description.is_empty() { description.push('\n'); }
        description.push_str(&format!("Scanlator: {scans}"));
    }
    if num_pages > 0 {
        if !description.is_empty() { description.push('\n'); }
        description.push_str(&format!("Pages: {num_pages}"));
    }
    if num_favorites > 0 {
        if !description.is_empty() { description.push_str(" | "); }
        description.push_str(&format!("Favorites: {num_favorites}"));
    }

    let display_title = if !pretty_title.is_empty() { pretty_title } else if !english_title.is_empty() { english_title } else { "Untitled" };

    HostBridge::progress(100, "详情加载完成");
    output_ok_data(json!({
        "kind": "archive",
        "source_namespace": "nhsource",
        "remote_id": gallery_id,
        "title": display_title,
        "description": description,
        "cover": cover_url,
        "cover_asset_id": ensure_cover_asset(&cover_url, &gallery_id),
        "tags": tags,
        "page_count": num_pages,
        "downloadable": true,
        "readable": true,
        "reader": {
            "page_count": num_pages,
            "reader_action": "source_reader",
            "download_action": "source_download",
        },
    }))
}

fn run_source_download(input: &PluginInput) -> Value {
    let gallery_id = extract_remote_id(&input.params);
    if gallery_id.is_empty() {
        return output_err("remote_id (gallery_id) is required for download");
    }

    let gallery_url = format!("https://nhentai.net/g/{gallery_id}/");
    HostBridge::log(1, &format!("nhsource source_download enqueues gallery url: {gallery_url}"));

    output_ok_data(json!({
        "gallery_url": gallery_url,
        "gallery_id": gallery_id,
    }))
}

fn run_source_reader(input: &PluginInput) -> Value {
    HostBridge::progress(2, "加载阅读器...");
    let auth = match load_nh_auth() {
        Ok(v) => v,
        Err(_) => NhAuthData { mode: String::new(), api_key: String::new() },
    };

    let gallery_id = extract_remote_id(&input.params);
    if gallery_id.is_empty() {
        return output_err("remote_id (gallery_id) is required for reader");
    }

    let url = format!("{NHENTAI_API_BASE}/galleries/{gallery_id}");
    let (status, text) = match api_get(&url, &auth) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Reader fetch failed: {e}")),
    };
    if status != 200 {
        return output_err(&format!("Reader API returned status {status}"));
    }

    let gallery: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse gallery: {e}")),
    };

    let page_paths = parse_gallery_page_paths(&gallery);
    if page_paths.is_empty() {
        return output_err("Gallery has no pages");
    }

    let total_pages = page_paths.len();
    let mut pages = Vec::with_capacity(total_pages);

    for (idx, path) in page_paths.iter().enumerate() {
        let page_num = idx + 1;
        let cached_asset_id = get_cached_page_asset_id(&gallery_id, page_num as u64);
        if cached_asset_id > 0 {
            pages.push(json!({
                "path": path,
                "asset_id": cached_asset_id,
                "type": "image"
            }));
        } else {
            pages.push(json!({
                "path": path,
                "type": "image"
            }));
        }
    }

    HostBridge::progress(100, "阅读器加载完成");
    output_ok_data(json!({ "pages": pages }))
}

fn run_source_page_asset(_input: &PluginInput) -> Value {
    // Dead code: this action has been moved to the Download plugin
    output_err("this action has been moved to the Download plugin")
}

fn run_source_cover_asset(input: &PluginInput) -> Value {
    let gallery_id = extract_remote_id(&input.params);
    if gallery_id.is_empty() {
        return output_err("remote_id (gallery_id) is required for cover_asset");
    }
    let cover_ref = input.params.get("cover_ref").and_then(Value::as_str).unwrap_or("");
    if cover_ref.is_empty() {
        return output_err("cover_ref is required for cover_asset");
    }
    match ensure_cover_asset(cover_ref, &gallery_id) {
        Some(asset_id) => output_ok_data(json!({"asset_id": asset_id})),
        None => output_err("failed to create cover asset"),
    }
}

fn guess_content_type(ext: &str) -> &'static str {
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        _ => "application/octet-stream",
    }
}

/// Download an image and register it as a system asset via HostBridge
fn download_and_install_asset(_guest_path: &str, _original_filename: &str, _content_type: &str) -> Option<i64> {
    // Dead code
    None
}

fn page_asset_cache_key(gallery_id: &str, page: u64) -> String {
    format!("nh_page_{gallery_id}_{page}")
}

fn get_cached_page_asset_id(gallery_id: &str, page: u64) -> i64 {
    let cache_key = page_asset_cache_key(gallery_id, page);
    match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => cached.as_i64().filter(|id| *id > 0).unwrap_or(0),
        _ => 0,
    }
}

fn cache_page_asset_id(gallery_id: &str, page: u64, asset_id: i64) {
    if asset_id > 0 {
        let cache_key = page_asset_cache_key(gallery_id, page);
        let _ = HostBridge::task_kv_set(&cache_key, json!(asset_id));
    }
}

fn cover_asset_cache_key(gallery_id: &str) -> String {
    format!("nh_cover_{gallery_id}")
}

fn get_cached_cover_asset_id(gallery_id: &str) -> Option<i64> {
    let cache_key = cover_asset_cache_key(gallery_id);
    match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => cached.as_i64().filter(|id| *id > 0),
        _ => None,
    }
}

/// Ensure cover asset exists for a gallery, using task_kv cache
/// Returns Some(asset_id) on success, None on failure or empty url
fn ensure_cover_asset(_cover_url: &str, _gallery_id: &str) -> Option<i64> {
    // Dead code
    None
}

fn parse_gallery_page_paths(gallery: &Value) -> Vec<String> {
    let mut page_paths = gallery
        .get("pages")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|page| page.get("path").and_then(Value::as_str))
                .map(|path| path.trim().trim_start_matches('/').to_string())
                .filter(|path| !path.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if page_paths.is_empty() {
        if let Some(media_id) = gallery.get("media_id").and_then(Value::as_str) {
            if let Some(items) = gallery
                .get("images")
                .and_then(|x| x.get("pages"))
                .and_then(Value::as_array)
            {
                for (index, page) in items.iter().enumerate() {
                    let ext = match page.get("t").and_then(Value::as_str).unwrap_or("j") {
                        "j" => "jpg",
                        "p" => "png",
                        "g" => "gif",
                        "w" => "webp",
                        _ => "jpg",
                    };
                    page_paths.push(format!("galleries/{media_id}/{}.{}", index + 1, ext));
                }
            }
        }
    }

    page_paths
}

fn parse_page_number_from_path(path: &str) -> u64 {
    let filename = path.trim().trim_end_matches('/').rsplit('/').next().unwrap_or_default();
    let stem = filename.split('.').next().unwrap_or_default();
    stem.chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse::<u64>()
        .unwrap_or(0)
}

fn fetch_image_servers(auth: &NhAuthData) -> Result<Vec<String>, String> {
    let url = format!("{NHENTAI_API_BASE}/cdn");
    let (status, text) = api_get(&url, auth)?;
    if status != 200 {
        return Err(format!("CDN API returned status {status}"));
    }
    let parsed: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(items) = parsed.get("image_servers").and_then(Value::as_array) {
        for item in items {
            if let Some(server) = item.as_str() {
                let trimmed = server.trim().trim_end_matches('/');
                if !trimmed.is_empty() && !out.contains(&trimmed.to_string()) {
                    out.push(trimmed.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        return Err("No image servers in CDN response".to_string());
    }
    Ok(out)
}

fn pick_image_server(image_servers: &[String], gallery_id: i64, page_index: usize) -> String {
    if image_servers.is_empty() {
        return DEFAULT_IMAGE_CDN.to_string();
    }
    let base = gallery_id.unsigned_abs() as usize;
    let start = (base + page_index.saturating_sub(1)) % image_servers.len();
    image_servers[start].clone()
}

fn extract_remote_id(params: &Value) -> String {
    params.get("remote_id")
        .and_then(Value::as_str)
        .or_else(|| params.get("__target_id").and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

fn read_page(params: &Value) -> u64 {
    params.get("page")
        .and_then(|v| match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        })
        .filter(|page| *page > 0)
        .unwrap_or(1)
}

fn map_gallery_list_items(parsed: &Value) -> Vec<Value> {
    let result = parsed.get("result").and_then(Value::as_array)
        .or_else(|| parsed.as_array());
    match result {
        Some(arr) => arr.iter().map(|item| {
            let id = item.get("id").and_then(Value::as_i64).map(|v| v.to_string()).unwrap_or_default();
            let title = item.get("english_title").and_then(Value::as_str).unwrap_or("Untitled");
            let jp_title = item.get("japanese_title").and_then(Value::as_str).unwrap_or("");
            let cover_raw = item.get("thumbnail").and_then(Value::as_str).unwrap_or("");
            let cover = if !cover_raw.is_empty() {
                if cover_raw.starts_with("http") {
                    cover_raw.to_string()
                } else {
                    format!("https://t.nhentai.net/{}", cover_raw.trim_start_matches('/'))
                }
            } else {
                String::new()
            };
            let num_pages = item.get("num_pages").and_then(|v| v.as_u64()).unwrap_or(0);

            let subtitle = if !jp_title.is_empty() { jp_title.to_string() } else { String::new() };

            let mut tag_ids = Vec::new();
            if let Some(tags) = item.get("tag_ids").and_then(Value::as_array) {
                for tag in tags {
                    if let Some(t) = tag.as_u64() {
                        tag_ids.push(t.to_string());
                    }
                }
            }

            json!({
                "kind": "archive",
                "source_namespace": "nhsource",
                "remote_id": id,
                "title": title,
                "subtitle": subtitle,
                "cover": cover,
                "cover_asset_id": get_cached_cover_asset_id(&id),
                "tags": tag_ids,
                "page_count": num_pages,
                "downloadable": true,
                "readable": true,
                "reader": {
                    "page_count": num_pages,
                    "reader_action": "source_reader",
                    "download_action": "source_download",
                },
            })
        }).collect(),
        None => Vec::new(),
    }
}

fn urlencoding_encode(input: &str) -> String {
    let mut result = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

fn http_get_with_retry(
    url: &str,
    referer: Option<&str>,
    _cookies: &[&str],
    accept: &str,
    extra_headers: &[(String, String)],
    max_retries: usize,
) -> Result<HttpResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_get(url, referer, accept, extra_headers) {
            Ok(response) => {
                if response.status == 429 {
                    if attempt >= max_retries {
                        return Err(format!("HTTP 429 for {url}. Retry later."));
                    }
                    let wait_ms = 1000u64.saturating_mul(attempt as u64 + 1);
                    HostBridge::log(1, &format!("nhsource hit HTTP 429 attempt={attempt} url={url}"));
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms.min(60_000)));
                    continue;
                }
                if is_retryable_status(response.status) {
                    if attempt >= max_retries { return Ok(response); }
                    last_err = format!("HTTP {}", response.status);
                    let wait_ms = 250u64.saturating_mul(attempt as u64 + 1);
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                    continue;
                }
                return Ok(response);
            }
            Err(err) => {
                if attempt >= max_retries {
                    return Err(err);
                }
                last_err = err;
                let wait_ms = 200u64.saturating_mul(attempt as u64 + 1);
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
            }
        }
    }
    Err(last_err)
}

fn http_get(
    url: &str,
    referer: Option<&str>,
    accept: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut current_referer = referer.map(|v| v.to_string());
    for _ in 0..=MAX_REDIRECTS {
        let response = http_get_once(&current_url, current_referer.as_deref(), accept, extra_headers)?;
        if is_redirect_status(response.status) {
            let location = find_header_value(&response.headers, "location")
                .ok_or_else(|| format!("redirect {} without Location", response.status))?;
            let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
            let next = base.join(location).map_err(|e| e.to_string())?;
            current_referer = Some(current_url);
            current_url = next.to_string();
            continue;
        }
        return Ok(response);
    }
    Err("too many redirects".to_string())
}

fn http_get_once(
    url: &str,
    referer: Option<&str>,
    accept: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid url {url}: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme: {scheme}"));
    }
    let host = parsed.host_str().ok_or_else(|| "url missing host".to_string())?;
    let port = parsed.port_or_known_default().ok_or_else(|| "url missing port".to_string())?;

    let mut path = parsed.path().to_string();
    if path.is_empty() { path.push('/'); }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut req = String::new();
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    if has_default_port(scheme, port) {
        req.push_str(&format!("Host: {host}\r\n"));
    } else {
        req.push_str(&format!("Host: {host}:{port}\r\n"));
    }
    req.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    req.push_str(&format!("Accept: {accept}\r\n"));
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    if let Some(v) = referer {
        req.push_str(&format!("Referer: {v}\r\n"));
    }
    for (name, value) in extra_headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");

    let stream = connect_target_stream(scheme, host, port)?;
    let raw = if scheme == "https" {
        read_https_response(stream, host, req.as_bytes())?
    } else {
        let mut plain_stream = stream;
        write_all_to_stream(&mut plain_stream, req.as_bytes())?;
        read_all_from_stream(&mut plain_stream)?
    };
    parse_http_response(&raw)
}

fn connect_target_stream(scheme: &str, host: &str, port: u16) -> Result<HostTcpStream, String> {
    if scheme.eq_ignore_ascii_case("https") {
        if let Some((proxy_host, proxy_port)) = resolve_proxy_for_scheme(scheme) {
            let mut stream = HostTcpStream::connect(&proxy_host, proxy_port, HTTP_TIMEOUT_MS)?;
            establish_proxy_connect_tunnel(&mut stream, host, port)?;
            return Ok(stream);
        }
    }
    HostTcpStream::connect(host, port, HTTP_TIMEOUT_MS)
}

fn resolve_proxy_for_scheme(scheme: &str) -> Option<(String, u16)> {
    let keys: &[&str] = if scheme.eq_ignore_ascii_case("https") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            if let Some(parsed) = parse_proxy_endpoint(&raw) {
                return Some(parsed);
            }
        }
    }
    None
}

fn parse_proxy_endpoint(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(8080);
    Some((host, port))
}

fn establish_proxy_connect_tunnel(
    stream: &mut HostTcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(), String> {
    let req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    write_all_to_stream(stream, req.as_bytes())?;

    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 1024];
    loop {
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = &data[..pos + 4];
            let status_line = String::from_utf8_lossy(head)
                .split("\r\n")
                .next()
                .unwrap_or_default()
                .to_string();
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| format!("invalid proxy CONNECT status line: {status_line}"))?;
            if !(200..300).contains(&status) {
                return Err(format!("proxy CONNECT failed: HTTP {status}"));
            }
            return Ok(());
        }
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("proxy closed before CONNECT response".to_string());
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 64 * 1024 {
            return Err("proxy CONNECT response too large".to_string());
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("failed to resolve {host}:{port}"))
}

fn write_all_to_stream<T: Write>(stream: &mut T, buf: &[u8]) -> Result<(), String> {
    let mut sent = 0usize;
    while sent < buf.len() {
        let n = stream.write(&buf[sent..]).map_err(|e| e.to_string())?;
        if n == 0 { return Err("socket write returned 0".to_string()); }
        sent += n;
    }
    stream.flush().map_err(|e| e.to_string())
}

fn read_all_from_stream<T: Read>(stream: &mut T) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}

fn read_https_response(stream: HostTcpStream, host: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid tls server name: {host}"))?;
    let conn = ClientConnection::new(tls_client_config().clone(), server_name)
        .map_err(|e| e.to_string())?;
    let mut tls_stream = StreamOwned::new(conn, stream);
    write_all_to_stream(&mut tls_stream, request)?;
    read_all_from_stream(&mut tls_stream)
}

fn tls_client_config() -> &'static Arc<ClientConfig> {
    static TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response: missing headers".to_string())?;
    let (head, rest) = raw.split_at(header_end + 4);
    let header_text = String::from_utf8_lossy(head);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next()
        .ok_or_else(|| "invalid HTTP response: empty status line".to_string())?;
    let mut status_parts = status_line.split_whitespace();
    status_parts.next();
    let status = status_parts.next()
        .ok_or_else(|| "invalid HTTP response: missing status".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("invalid HTTP status: {e}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let body = if is_chunked(&headers) {
        decode_chunked_body(rest)?
    } else if let Some(len) = content_length(&headers) {
        rest[..rest.len().min(len)].to_vec()
    } else {
        rest.to_vec()
    };

    Ok(HttpResponse { status, headers, body })
}

fn decode_chunked_body(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    loop {
        let line_end = find_crlf(input, idx).ok_or_else(|| "invalid chunked body".to_string())?;
        let size_line = String::from_utf8_lossy(&input[idx..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {size_hex}"))?;
        idx = line_end + 2;
        if size == 0 { break; }
        if idx + size > input.len() {
            return Err("invalid chunked body: truncated chunk".to_string());
        }
        out.extend_from_slice(&input[idx..idx + size]);
        idx += size;
        if idx + 2 > input.len() || &input[idx..idx + 2] != b"\r\n" {
            return Err("invalid chunked body: missing chunk terminator".to_string());
        }
        idx += 2;
    }
    Ok(out)
}

fn find_crlf(input: &[u8], start: usize) -> Option<usize> {
    if start >= input.len() { return None; }
    input[start..].windows(2).position(|w| w == b"\r\n").map(|offset| start + offset)
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    find_header_value(headers, "content-length").and_then(|v| v.parse::<usize>().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    find_header_value(headers, "transfer-encoding")
        .map(|v| v.split(',').any(|part| part.trim().eq_ignore_ascii_case("chunked")))
        .unwrap_or(false)
}

fn find_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn has_default_port(scheme: &str, port: u16) -> bool {
    (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 500 | 502 | 503 | 504)
}

fn plugin_info_json() -> Value {
    json!({
        "name": "nhentai Source (Rust)",
        "plugin_type": "Source",
        "namespace": "nhsource",
        "pre": ["nhlogin"],
        "author": "Lanlu",
        "version": "0.2.0",
        "description": "Browse and search nhentai.net online galleries for Lanlu.",
        "parameters": [],
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read",
            "task_kv.write",
        ]
    })
}

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}
