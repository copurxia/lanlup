use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, KeyInit};
use aes::Aes256;
use md5::{Digest, Md5};
use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::slice;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 Mobile Safari/537.36";
const JM_PKG_NAME: &str = "com.example.app";
const JM_VERSION: &str = "2.0.16";
const JM_AUTH_KEY: &str = "18comicAPPContent";
const JM_SECRET: &str = "185Hcomic3PAPP7R";
const API_DOMAINS: [&str; 4] = [
    "www.cdnsha.org",
    "www.cdnntr.cc",
    "www.cdnaspa.cc",
    "www.cdntwice.org",
];
const DEFAULT_IMAGE_BASE: &str = "https://cdn-msp.jmapinodeudzn.net";
const AUTH_DATA_KEY: &str = "__lanlu.phase.jmcomiclogin.data";
const HTTP_TIMEOUT_MS: i32 = 30000;
const MAX_REDIRECTS: usize = 5;

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
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_call(_: i32, _: i32, _: i32) -> i32 {
    1
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_len() -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_read(_: i32, _: i32) -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_len() -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_read(_: i32, _: i32) -> i32 {
    0
}

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

#[derive(Debug, Deserialize, Clone)]
struct JmAuthData {
    #[serde(default)]
    uid: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    api_domain: i64,
    #[serde(default)]
    api_domains: Vec<String>,
    #[serde(default)]
    image_stream: i64,
    #[serde(default)]
    bypass_url: String,
    #[serde(default)]
    mode: String,
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
        if len < 0 {
            return Err("host_response_len returned negative".to_string());
        }
        if len == 0 {
            return Ok(Value::Null);
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buf.as_mut_ptr() as i32, len) };
        if read < 0 {
            return Err("host_response_read failed".to_string());
        }
        serde_json::from_slice(&buf[..read as usize]).map_err(|e| e.to_string())
    }

    fn read_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 {
            return "host call failed".to_string();
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buf.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return "host call failed".to_string();
        }
        String::from_utf8_lossy(&buf[..read as usize]).to_string()
    }

    fn task_kv_get(key: &str) -> Result<Option<Value>, String> {
        let response = Self::call("task_kv.get", json!({ "key": key }))?;
        let found = response
            .get("found")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !found {
            return Ok(None);
        }
        Ok(response.get("value").cloned())
    }

    fn task_kv_set(key: &str, value: Value) -> Result<(), String> {
        Self::call("task_kv.set", json!({ "key": key, "value": value }))?;
        Ok(())
    }
}

unsafe fn read_guest_bytes(ptr: i32, len: i32) -> &'static [u8] {
    if ptr == 0 || len <= 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr as *const u8, len as usize)
    }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_free(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 {
        return;
    }
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
        "name": "JM Comic Downloader",
        "type": "download",
        "namespace": "jmcomicdl",
        "pre": ["jmcomiclogin"],
        "source_id_regex": "^source:jmcomicsource:.*$",
        "author": "Lanlu",
        "version": "0.2.1",
        "description": "Downloads JM Comic albums as zip archives.",
        "parameters": [],
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read",
            "task_kv.write"
        ],
        "url_regex": "^(\\d+|jm\\d+|https?://.*(jmapinodeudzn\\.net|cdnsha\\.org|cdnntr\\.cc|cdnaspa\\.cc|cdntwice\\.org)/album\\?id=\\d+)$",
        "update_url": ""
    })
}

fn run_download(input: &PluginInput) -> Value {
    let url = input.url.trim();
    if url.is_empty() {
        return output_err("No URL provided.");
    }

    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    let album_id = match extract_album_id(url) {
        Some(id) => id,
        None => {
            return output_err("Not a valid JM Comic URL or ID. Expected format: jm12345 or 12345")
        }
    };

    let plugin_dir = resolve_plugin_dir(&input.plugin_dir, "jmcomicdl");
    HostBridge::progress(1, "Starting JM Comic download...");
    HostBridge::log(
        1,
        &format!("jmcomicdl album_id={} plugin_dir={}", album_id, plugin_dir),
    );

    match download_album(&album_id, &auth, &plugin_dir, &input.params) {
        Ok((relative_path, filename)) => {
            HostBridge::progress(100, "Download complete");
            json!({
                "success": true,
                "data": [{
                    "plugin_relative_path": relative_path,
                    "relative_path": relative_path,
                    "filename": filename,
                    "source": format!("jm{}", album_id),
                    "archive_type": "archive"
                }]
            })
        }
        Err(e) => output_err(&format!("Download failed: {}", e)),
    }
}

/// resolve_page_asset action（targetType=source，直连执行）：
/// path = "{ep_id}/{page_num}"，直接返回图片二进制数据（零磁盘、零 asset）。
fn resolve_page_asset(input: &PluginInput) -> Vec<u8> {
    let path = input.path.trim();
    if path.is_empty() {
        return build_binary_response(&output_err("path is required for resolve_page_asset"), &[]);
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return build_binary_response(
            &output_err(&format!("invalid path (expected ep_id/page): {path}")),
            &[],
        );
    }
    let ep_id = parts[0];
    let page: u64 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => {
            return build_binary_response(
                &output_err(&format!("invalid page number in path: {path}")),
                &[],
            )
        }
    };
    if page == 0 {
        return build_binary_response(&output_err("page number must be >= 1"), &[]);
    }

    HostBridge::progress(10, "加载登录态...");
    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&e), &[]),
    };

    let api_base = resolve_api_base(&input.params, &auth);
    let bypass_url = resolve_bypass_url(&input.params, &auth);
    let image_base = resolve_image_base(&api_base, &input.params, &auth, &bypass_url)
        .unwrap_or_else(|e| {
            HostBridge::log(1, &format!("jmcomicdl image base fallback: {}", e));
            DEFAULT_IMAGE_BASE.to_string()
        });

    HostBridge::progress(30, &format!("获取章节 {} 图片列表...", ep_id));

    // 缓存章节图片列表，避免每页都重抓
    let cache_key = format!("jmcomicdl_chapter_images_{ep_id}");
    let images: Vec<String> = match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => {
            cached.as_array().map(|arr| {
                arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
            }).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let images = if !images.is_empty() {
        images
    } else {
        let chapter_time = current_timestamp();
        let chapter_url = format!("{}/chapter?id={}", api_base, ep_id);
        let chapter_headers = build_jm_headers(chapter_time);
        let chapter_resp = match http_request_text("GET", &chapter_url, None, &chapter_headers, &bypass_url) {
            Ok(v) => v,
            Err(e) => return build_binary_response(&output_err(&format!("chapter fetch failed: {e}")), &[]),
        };
        if chapter_resp.status != 200 {
            return build_binary_response(
                &output_err(&format!("chapter fetch HTTP {}", chapter_resp.status)),
                &[],
            );
        }
        let body_text = String::from_utf8_lossy(&chapter_resp.body);
        let json_resp: Value = match serde_json::from_str(&body_text) {
            Ok(v) => v,
            Err(e) => return build_binary_response(&output_err(&format!("parse error: {e}")), &[]),
        };
        let data_field = match json_resp.get("data").and_then(Value::as_str) {
            Some(v) => v,
            None => return build_binary_response(&output_err("missing chapter data field"), &[]),
        };
        let secret = format!("{}{}", chapter_time, JM_SECRET);
        let decrypted = match jm_decrypt(data_field, &secret) {
            Ok(v) => v,
            Err(e) => return build_binary_response(&output_err(&format!("decrypt error: {e}")), &[]),
        };
        let chapter: Value = match serde_json::from_str(&decrypted) {
            Ok(v) => v,
            Err(e) => return build_binary_response(&output_err(&format!("parse chapter: {e}")), &[]),
        };
        let fetched: Vec<String> = chapter
            .get("images")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if fetched.is_empty() {
            return build_binary_response(&output_err("no images in chapter"), &[]);
        }
        let _ = HostBridge::task_kv_set(&cache_key, json!(fetched));
        fetched
    };

    let idx = (page - 1) as usize;
    if idx >= images.len() {
        return build_binary_response(
            &output_err(&format!("page {page} out of range ({} pages)", images.len())),
            &[],
        );
    }
    let img_name = &images[idx];
    let img_url = format!("{}/media/photos/{}/{}", image_base, ep_id, img_name);
    let ext = guess_ext_from_url(img_name);
    let content_type = guess_content_type(&ext);

    HostBridge::progress(70, &format!("下载第 {} 页...", page));
    let img_headers = build_img_headers();
    let img_resp = match http_request_bytes("GET", &img_url, None, &img_headers, &bypass_url) {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&format!("image download failed: {e}")), &[]),
    };
    if img_resp.status != 200 {
        return build_binary_response(
            &output_err(&format!("image download HTTP {}", img_resp.status)),
            &[],
        );
    }

    HostBridge::progress(100, "单页资源解析完成");
    let success_json = json!({
        "success": true,
        "content_type": content_type
    });
    build_binary_response(&success_json, &img_resp.body)
}

/// download_archive action（targetType=source）：从 targetId 解析 remoteId，复用整本下载流程。
fn download_archive_action(input: &PluginInput) -> Value {
    let target_id = input.target_id.trim();
    let album_id = match target_id.strip_prefix("source:jmcomicsource:") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return output_err(&format!("invalid sourceId: {target_id}")),
    };

    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    let plugin_dir = resolve_plugin_dir(&input.plugin_dir, "jmcomicdl");
    HostBridge::log(1, &format!("jmcomicdl download_archive album_id={}", album_id));

    match download_album(&album_id, &auth, &plugin_dir, &input.params) {
        Ok((relative_path, filename)) => {
            HostBridge::progress(100, "下载完成");
            json!({
                "success": true,
                "data": [{
                    "plugin_relative_path": relative_path,
                    "relative_path": relative_path,
                    "filename": filename,
                    "source": format!("source:jmcomicsource:{}", album_id),
                    "archive_type": "archive"
                }]
            })
        }
        Err(e) => output_err(&format!("Download failed: {}", e)),
    }
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

fn guess_ext_from_url(name: &str) -> String {
    let name_lower = name.to_ascii_lowercase();
    if let Some(dot) = name_lower.rfind('.') {
        name_lower[dot + 1..].to_string()
    } else {
        String::new()
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

fn download_album(
    album_id: &str,
    auth: &JmAuthData,
    plugin_dir: &str,
    params: &Value,
) -> Result<(String, String), String> {
    let time = current_timestamp();
    let api_base = resolve_api_base(params, auth);
    let bypass_url = resolve_bypass_url(params, auth);
    let album_url = format!("{}/album?id={}", api_base, album_id);
    let headers = build_jm_headers(time);

    HostBridge::progress(5, "Fetching album info...");
    HostBridge::log(1, &format!("jmcomicdl GET {}", album_url));
    let album_resp = http_request_text("GET", &album_url, None, &headers, &bypass_url)?;
    if album_resp.status != 200 {
        return Err(format!("Album fetch failed: HTTP {}", album_resp.status));
    }

    let body_text = String::from_utf8_lossy(&album_resp.body);
    let album_json: Value = serde_json::from_str(&body_text).map_err(|e| e.to_string())?;
    let data_field = album_json
        .get("data")
        .and_then(Value::as_str)
        .ok_or("Missing album data field")?;
    let secret = format!("{}{}", time, JM_SECRET);
    let decrypted = jm_decrypt(data_field, &secret)?;
    let album: Value = serde_json::from_str(&decrypted).map_err(|e| e.to_string())?;

    let title = album
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let safe_title = sanitize_filename(&title);
    let filename = format!("jm_{}_{}.zip", album_id, safe_title);
    let zip_path = format!("{}/{}", plugin_dir, filename);

    HostBridge::log(1, &format!("jmcomicdl creating zip: {}", zip_path));

    // Collect chapters
    let mut chapters: Vec<(String, String)> = Vec::new();
    if let Some(series) = album.get("series").and_then(Value::as_array) {
        for item in series {
            let ep_id = item
                .get("id")
                .and_then(|v| v.as_i64())
                .map(|v| v.to_string())
                .unwrap_or_default();
            let ep_name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if !ep_id.is_empty() {
                chapters.push((ep_id, ep_name));
            }
        }
    }
    if chapters.is_empty() {
        chapters.push((album_id.to_string(), "第1話".to_string()));
    }

    let total_chapters = chapters.len();
    let mut total_images = 0usize;
    let image_base = resolve_image_base(&api_base, params, auth, &bypass_url).unwrap_or_else(|e| {
        HostBridge::log(1, &format!("jmcomicdl image base fallback: {}", e));
        DEFAULT_IMAGE_BASE.to_string()
    });

    // Create zip file
    let zip_file = std::fs::File::create(&zip_path)
        .map_err(|e| format!("Failed to create zip file: {}", e))?;
    let mut zip = zip::ZipWriter::new(zip_file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for (idx, (ep_id, _ep_name)) in chapters.iter().enumerate() {
        let progress = 10 + ((idx as i32) * 80 / (total_chapters as i32));
        HostBridge::progress(
            progress,
            &format!("Downloading chapter {}/{}...", idx + 1, total_chapters),
        );

        let chapter_time = current_timestamp();
        let chapter_url = format!("{}/chapter?id={}", api_base, ep_id);
        let chapter_headers = build_jm_headers(chapter_time);

        HostBridge::log(1, &format!("jmcomicdl GET {}", chapter_url));
        let chapter_resp =
            http_request_text("GET", &chapter_url, None, &chapter_headers, &bypass_url)?;
        if chapter_resp.status != 200 {
            HostBridge::log(
                2,
                &format!(
                    "Chapter {} fetch failed: HTTP {}",
                    ep_id, chapter_resp.status
                ),
            );
            continue;
        }

        let chapter_body_text = String::from_utf8_lossy(&chapter_resp.body);
        let chapter_json: Value =
            serde_json::from_str(&chapter_body_text).map_err(|e| e.to_string())?;
        let chapter_data = chapter_json
            .get("data")
            .and_then(Value::as_str)
            .ok_or("Missing chapter data")?;
        let chapter_secret = format!("{}{}", chapter_time, JM_SECRET);
        let chapter_decrypted = jm_decrypt(chapter_data, &chapter_secret)?;
        let chapter: Value = serde_json::from_str(&chapter_decrypted).map_err(|e| e.to_string())?;

        let images = chapter
            .get("images")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let img_count = images.len();
        HostBridge::log(
            1,
            &format!("jmcomicdl chapter {} has {} images", ep_id, img_count),
        );

        for (img_idx, img_name_val) in images.iter().enumerate() {
            let img_name = img_name_val.as_str().unwrap_or("");
            if img_name.is_empty() {
                continue;
            }

            let img_url = format!("{}/media/photos/{}/{}", image_base, ep_id, img_name);
            let img_headers = build_img_headers();

            match http_request_bytes("GET", &img_url, None, &img_headers, &bypass_url) {
                Ok(img_resp) => {
                    if img_resp.status == 200 {
                        let zip_entry_name = format!("{}/{:04}_{}", ep_id, img_idx + 1, img_name);
                        zip.start_file(&zip_entry_name, options)
                            .map_err(|e| e.to_string())?;
                        zip.write_all(&img_resp.body).map_err(|e| e.to_string())?;
                        total_images += 1;
                    } else {
                        HostBridge::log(
                            2,
                            &format!("Image {} returned HTTP {}", img_url, img_resp.status),
                        );
                    }
                }
                Err(e) => {
                    HostBridge::log(2, &format!("Image download failed: {} - {}", img_url, e));
                }
            }
        }
    }

    zip.finish()
        .map_err(|e| format!("Failed to finalize zip: {}", e))?;
    HostBridge::log(
        1,
        &format!(
            "jmcomicdl downloaded {} images to {}",
            total_images, zip_path
        ),
    );

    if total_images == 0 {
        return Err("No images were downloaded.".to_string());
    }

    let relative_path = filename.clone();
    Ok((relative_path, filename))
}

fn load_jm_auth() -> Result<JmAuthData, String> {
    let Some(value) = HostBridge::task_kv_get(AUTH_DATA_KEY)? else {
        return Err(
            "Missing JM Comic auth data in task KV. Ensure jmcomiclogin ran as a pre hook."
                .to_string(),
        );
    };
    serde_json::from_value(value).map_err(|e| format!("Invalid JM Comic auth data in task KV: {e}"))
}

fn resolve_image_base(
    api_base: &str,
    params: &Value,
    auth: &JmAuthData,
    bypass_url: &str,
) -> Result<String, String> {
    let index = if auth.image_stream > 0 {
        auth.image_stream
    } else {
        read_int_param(params, "image_stream", 1)
    };
    let time = current_timestamp();
    let url = format!(
        "{}/setting?app_img_shunt={}&express=",
        api_base,
        clamp_index(index, 4) + 1
    );
    let headers = build_jm_headers(time);
    let url_with_uid = if auth.uid.is_empty() {
        url
    } else {
        let sep = if url.contains('?') { "&" } else { "?" };
        format!("{}{}uid={}", url, sep, auth.uid)
    };
    let response = http_request_text("GET", &url_with_uid, None, &headers, bypass_url)?;
    if response.status != 200 {
        return Err(format!(
            "Image stream settings failed: HTTP {}",
            response.status
        ));
    }
    let body_text = String::from_utf8_lossy(&response.body);
    let json_resp: Value = serde_json::from_str(&body_text).map_err(|e| e.to_string())?;
    let data_field = json_resp
        .get("data")
        .and_then(Value::as_str)
        .ok_or("Missing data field")?;
    let secret = format!("{}{}", time, JM_SECRET);
    let decrypted = jm_decrypt(data_field, &secret)?;
    let setting: Value = serde_json::from_str(&decrypted).map_err(|e| e.to_string())?;
    let base = setting
        .get("img_host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if base.is_empty() {
        return Ok(DEFAULT_IMAGE_BASE.to_string());
    }
    Ok(base.trim_end_matches('/').to_string())
}

fn resolve_api_base(params: &Value, auth: &JmAuthData) -> String {
    let index = if auth.api_domain > 0 {
        auth.api_domain
    } else {
        read_int_param(params, "api_domain", 1)
    };
    let chosen = clamp_index(index, 4);
    // 优先用 login 插件刷新来的动态域名，空则回退硬编码 API_DOMAINS。
    if !auth.api_domains.is_empty() {
        let i = chosen.min(auth.api_domains.len() - 1);
        format!("https://{}", auth.api_domains[i])
    } else {
        format!("https://{}", API_DOMAINS[chosen])
    }
}

fn resolve_bypass_url(params: &Value, auth: &JmAuthData) -> String {
    if !auth.bypass_url.trim().is_empty() {
        return auth.bypass_url.trim().to_string();
    }
    read_string_param(params, "bypass_url")
}

fn clamp_index(index: i64, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if index <= 1 {
        0
    } else if index as usize > len {
        len - 1
    } else {
        index as usize - 1
    }
}

fn read_int_param(params: &Value, name: &str, default: i64) -> i64 {
    match params.get(name) {
        Some(Value::Number(v)) => v.as_i64().unwrap_or(default),
        Some(Value::String(v)) => v.trim().parse::<i64>().unwrap_or(default),
        Some(Value::Bool(v)) => {
            if *v {
                1
            } else {
                0
            }
        }
        _ => default,
    }
}

fn read_string_param(params: &Value, name: &str) -> String {
    params
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn extract_album_id(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Some(trimmed.to_string());
    }
    let re = Regex::new(r"jm(\d+)").ok()?;
    if let Some(caps) = re.captures(trimmed) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }
    let re2 = Regex::new(r"album\?id=(\d+)").ok()?;
    if let Some(caps) = re2.captures(trimmed) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }
    None
}

fn resolve_plugin_dir(raw: &str, ns: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return format!("./data/cache/plugins/{}", ns);
    }
    trimmed.to_string()
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .replace(' ', "_")
        .trim_matches('_')
        .to_string()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_jm_headers(time: u64) -> Vec<(String, String)> {
    let token_input = format!("{}{}", time, JM_AUTH_KEY);
    let token_hash = md5_hash(token_input.as_bytes());
    let token = bytes_to_hex(&token_hash);

    vec![
        ("Accept".to_string(), "*/*".to_string()),
        (
            "Accept-Language".to_string(),
            "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7".to_string(),
        ),
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Origin".to_string(), "https://localhost".to_string()),
        ("Referer".to_string(), "https://localhost/".to_string()),
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("X-Requested-With".to_string(), JM_PKG_NAME.to_string()),
        ("Authorization".to_string(), "Bearer".to_string()),
        ("token".to_string(), token),
        (
            "tokenparam".to_string(),
            format!("{}, {}", time, JM_VERSION),
        ),
    ]
}

fn build_img_headers() -> Vec<(String, String)> {
    vec![
        (
            "Accept".to_string(),
            "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8".to_string(),
        ),
        (
            "Accept-Language".to_string(),
            "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7".to_string(),
        ),
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Referer".to_string(), "https://localhost/".to_string()),
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("X-Requested-With".to_string(), JM_PKG_NAME.to_string()),
    ]
}

fn md5_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn bytes_to_hex(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| e.to_string())
}

fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("AES key must be 32 bytes, got {}", key.len()));
    }
    if ciphertext.len() % 16 != 0 {
        return Err("ciphertext length must be multiple of 16".to_string());
    }
    let mut cipher = Aes256::new(GenericArray::from_slice(key));
    let mut plaintext = ciphertext.to_vec();
    for chunk in plaintext.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(block);
    }
    if let Some(&last) = plaintext.last() {
        let pad_len = last as usize;
        if pad_len > 0 && pad_len <= 16 {
            let valid = plaintext.len() >= pad_len
                && plaintext[plaintext.len() - pad_len..]
                    .iter()
                    .all(|&b| b == last);
            if valid {
                plaintext.truncate(plaintext.len() - pad_len);
            }
        }
    }
    Ok(plaintext)
}

fn jm_decrypt(data_base64: &str, secret: &str) -> Result<String, String> {
    let md5_hash_val = md5_hash(secret.as_bytes());
    let hex_str = bytes_to_hex(&md5_hash_val);
    let key = hex_str.as_bytes();
    let ciphertext = base64_decode(data_base64)?;
    let plaintext = aes_ecb_decrypt(key, &ciphertext)?;
    let text = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
    Ok(trim_json_text(&text))
}

fn trim_json_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() && bytes[start] != b'{' && bytes[start] != b'[' {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && bytes[end - 1] != b'}' && bytes[end - 1] != b']' {
        end -= 1;
    }
    text[start..end].to_string()
}

fn output_err(message: &str) -> Value {
    json!({ "success": false, "error": message })
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

fn http_request_text(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &[(String, String)],
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    // 底层 http_request 已返回原始 Vec<u8>，这里直接透传，不做 from_utf8_lossy，
    // 以免损坏二进制内容（如加密的 API 响应、图片字节）。文本由调用方按需 from_utf8。
    http_request(method, url, body, headers, bypass_url)
}

fn http_request_bytes(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &[(String, String)],
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    http_request(method, url, body, headers, bypass_url)
}

fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &[(String, String)],
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut referer: Option<String> = None;

    for _ in 0..=MAX_REDIRECTS {
        let response = match http_request_once(
            method,
            &current_url,
            body,
            headers,
            referer.as_deref(),
            bypass_url,
        ) {
            Ok(v) => v,
            Err(e) if !bypass_url.trim().is_empty() => {
                HostBridge::log(
                    2,
                    &format!(
                        "jmcomicdl bypass failed for {}, fallback direct: {}",
                        current_url, e
                    ),
                );
                http_request_once(method, &current_url, body, headers, referer.as_deref(), "")?
            }
            Err(e) => return Err(e),
        };
        if is_redirect_status(response.status) {
            let location = find_header_value(&response.headers, "location")
                .ok_or_else(|| format!("redirect {} without Location", response.status))?;
            let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
            let next = base.join(location).map_err(|e| e.to_string())?;
            referer = Some(current_url);
            current_url = next.to_string();
            continue;
        }
        return Ok(response);
    }
    Err("too many redirects".to_string())
}

fn http_request_once(
    method: &str,
    url: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
    referer: Option<&str>,
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    let (effective_url, bypass_host) = resolve_bypass_request_url(url, bypass_url)?;
    let parsed =
        Url::parse(&effective_url).map_err(|e| format!("invalid url {effective_url}: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme: {scheme}"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "url missing host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "url missing port".to_string())?;

    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut req = String::new();
    req.push_str(&format!("{} {} HTTP/1.1\r\n", method, path));
    if has_default_port(scheme, port) {
        req.push_str(&format!("Host: {}\r\n", host));
    } else {
        req.push_str(&format!("Host: {}:{}\r\n", host, port));
    }
    req.push_str(&format!("User-Agent: {}\r\n", USER_AGENT));
    req.push_str("Accept: */*\r\n");
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    if let Some(v) = referer {
        req.push_str(&format!("Referer: {}\r\n", v));
    }
    if let Some(v) = bypass_host {
        req.push_str(&format!("x-hostname: {}\r\n", v));
    }
    for (name, value) in extra_headers {
        req.push_str(&format!("{}: {}\r\n", name, value));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }

    let stream = HostTcpStream::connect(host, port, HTTP_TIMEOUT_MS)?;
    let raw = if scheme == "https" {
        read_https_response(stream, host, req.as_bytes())?
    } else {
        let mut plain_stream = stream;
        write_all_to_stream(&mut plain_stream, req.as_bytes())?;
        read_all_from_stream(&mut plain_stream)?
    };
    parse_http_response(&raw)
}

fn resolve_bypass_request_url(
    url: &str,
    bypass_url: &str,
) -> Result<(String, Option<String>), String> {
    let trimmed = bypass_url.trim();
    if trimmed.is_empty() {
        return Ok((url.to_string(), None));
    }
    let target = Url::parse(url).map_err(|e| format!("invalid target url {}: {}", url, e))?;
    let target_host = target
        .host_str()
        .ok_or_else(|| "target url missing host".to_string())?;
    let x_hostname = match target.port() {
        Some(port) => format!("{}:{}", target_host, port),
        None => target_host.to_string(),
    };
    let base = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    };
    let base = base.trim_end_matches('/').to_string();
    let mut endpoint = format!("{}{}", base, target.path());
    if let Some(query) = target.query() {
        endpoint.push('?');
        endpoint.push_str(query);
    }
    Ok((endpoint, Some(x_hostname)))
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

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let status_line = String::from_utf8_lossy(&buf[..pos])
                .split("\r\n")
                .next()
                .unwrap_or("")
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
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("proxy closed before CONNECT response".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("proxy CONNECT response too large".to_string());
        }
    }
}

fn read_https_response(
    stream: HostTcpStream,
    host: &str,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid tls server name: {}", host))?;
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
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response: missing headers".to_string())?;
    let (head, rest) = raw.split_at(header_end + 4);
    let header_text = String::from_utf8_lossy(head);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or("invalid HTTP response: empty status line")?;
    let mut status_parts = status_line.split_whitespace();
    status_parts.next();
    let status = status_parts
        .next()
        .ok_or("missing status")?
        .parse::<u16>()
        .map_err(|e| format!("invalid HTTP status: {e}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
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

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked_body(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    loop {
        let line_end = find_crlf(input, idx).ok_or("invalid chunked body")?;
        let size_line = String::from_utf8_lossy(&input[idx..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {}", size_hex))?;
        idx = line_end + 2;
        if size == 0 {
            break;
        }
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
    if start >= input.len() {
        return None;
    }
    input[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|offset| start + offset)
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    find_header_value(headers, "content-length").and_then(|v| v.parse().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    find_header_value(headers, "transfer-encoding")
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn find_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn has_default_port(scheme: &str, port: u16) -> bool {
    (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("failed to resolve {}:{}", host, port))
}

fn write_all_to_stream<T: Write>(stream: &mut T, buf: &[u8]) -> Result<(), String> {
    let mut sent = 0usize;
    let mut retries = 0usize;
    while sent < buf.len() {
        match stream.write(&buf[sent..]) {
            Ok(0) => return Err("socket write returned 0".to_string()),
            Ok(n) => {
                sent += n;
                retries = 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                retries += 1;
                if retries > 1000 {
                    return Err("socket write timed out".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    stream.flush().map_err(|e| e.to_string())
}

fn read_all_from_stream<T: Read>(stream: &mut T) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}
