use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, KeyInit};
use aes::Aes256;
use md5::{Digest, Md5};
use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Map, Value};
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
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("jmcomicmeta-rs requires wasm32-wasip1 (target_os=\"wasi\")");

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
const HTTP_TIMEOUT_MS: i32 = 15000;
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
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
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
        let _ = stream.set_nonblocking(true);
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

    let payload = build_result_payload(input);
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
        "name": "JM Comic Metadata",
        "type": "metadata",
        "namespace": "jmcomicmeta",
        "pre": ["jmcomiclogin"],
        "author": "Lanlu",
        "version": "0.2.1",
        "description": "Fetches JM Comic album metadata for Lanlu archives.",
        "parameters": [
            {"name": "fetch_cover", "type": "bool", "desc": "Fetch album cover URL", "default_value": "1"}
        ],
        "oneshot_arg": "JM Comic Album ID (e.g. 12345)",
        "cooldown": 2,
        "permissions": [
            "metadata.read_input",
            "net",
            "log.write",
            "progress.report",
            "task_kv.read"
        ],
        "update_url": ""
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    HostBridge::progress(5, "初始化 JM Comic 元数据抓取...");
    let auth = load_jm_auth()?;
    let api_base = resolve_api_base(&input.params, &auth);
    let bypass_url = resolve_bypass_url(&input.params, &auth);

    let mut metadata = ensure_metadata_object(input.metadata);
    let existing_title = metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let album_id = if let Some(id) = extract_album_id(&input.oneshot_param) {
        id
    } else if let Some(id) = extract_album_id_from_title(&existing_title) {
        id
    } else if existing_title.is_empty() {
        return Err(
            "No JM Comic album ID found. Provide an ID via oneshot argument or archive title."
                .to_string(),
        );
    } else {
        return Err(
            "Could not resolve JM Comic album ID from title or oneshot argument.".to_string(),
        );
    };

    HostBridge::log(1, &format!("jmcomicmeta resolved album_id={}", album_id));
    HostBridge::progress(30, &format!("获取专辑 {} 元数据...", album_id));

    let fetch_cover = read_bool_param(&input.params, "fetch_cover", true);
    let image_base = resolve_image_base(&api_base, &input.params, &auth, &bypass_url)?;
    let (title, tags_csv, description, cover) = fetch_album_metadata(
        &album_id,
        &auth,
        fetch_cover,
        &api_base,
        &image_base,
        &bypass_url,
    )?;

    if !title.trim().is_empty() {
        metadata.insert("title".to_string(), Value::String(title));
    }
    if !description.trim().is_empty() {
        metadata.insert("description".to_string(), Value::String(description));
    }
    if !tags_csv.is_empty() {
        metadata.insert("tags".to_string(), metadata_tags_from_csv(&tags_csv));
    }
    if fetch_cover && !cover.is_empty() {
        metadata.insert("cover".to_string(), Value::String(cover));
    }
    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "元数据获取完成");
    Ok(Value::Object(metadata))
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

fn extract_album_id(input: &str) -> Option<String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return Some(clean.to_string());
    }
    let re = Regex::new(r"jm\d+|/album\?id=(\d+)").ok()?;
    re.captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .or_else(|| {
            let re2 = Regex::new(r"^(\d+)$").ok()?;
            re2.captures(clean)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        })
}

fn extract_album_id_from_title(title: &str) -> Option<String> {
    let re = Regex::new(r"\[JM\s*(\d+)\]|\{JM\s*(\d+)\}").ok()?;
    let caps = re.captures(title)?;
    caps.get(1)
        .or_else(|| caps.get(2))
        .map(|m| m.as_str().to_string())
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    let items: Vec<Value> = csv
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(Value::String(trimmed.to_string()))
            }
        })
        .collect();
    Value::Array(items)
}

fn read_bool_param(params: &Value, name: &str, default: bool) -> bool {
    match params.get(name) {
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(v)) => v.as_i64().unwrap_or(0) != 0,
        Some(Value::String(v)) => {
            let s = v.trim().to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        }
        _ => default,
    }
}

fn fetch_album_metadata(
    album_id: &str,
    _auth: &JmAuthData,
    fetch_cover: bool,
    api_base: &str,
    image_base: &str,
    bypass_url: &str,
) -> Result<(String, String, String, String), String> {
    let time = current_timestamp();
    let url = format!("{}/album?id={}", api_base, album_id);
    let headers = build_jm_headers(time);

    HostBridge::log(1, &format!("jmcomicmeta GET {}", url));
    let response = http_request_text("GET", &url, None, &headers, bypass_url)?;
    HostBridge::log(
        1,
        &format!("jmcomicmeta response status={}", response.status),
    );

    if response.status != 200 {
        return Err(format!("Album fetch failed: HTTP {}", response.status));
    }

    let body_text = String::from_utf8_lossy(&response.body);
    let json_resp: Value = serde_json::from_str(&body_text).map_err(|e| e.to_string())?;
    let data_field = json_resp
        .get("data")
        .and_then(Value::as_str)
        .ok_or("Missing data field")?;

    let secret = format!("{}{}", time, JM_SECRET);
    let decrypted = jm_decrypt(data_field, &secret)?;
    HostBridge::log(
        1,
        &format!(
            "jmcomicmeta decrypted: {}",
            &decrypted[..decrypted.len().min(200)]
        ),
    );

    let album: Value = serde_json::from_str(&decrypted).map_err(|e| e.to_string())?;

    let title = album
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut tags = Vec::new();
    if let Some(author_arr) = album.get("author").and_then(Value::as_array) {
        for a in author_arr {
            if let Some(s) = a.as_str() {
                if !s.is_empty() {
                    tags.push(format!("author:{}", s));
                }
            }
        }
    }
    if let Some(tag_arr) = album.get("tags").and_then(Value::as_array) {
        for t in tag_arr {
            if let Some(s) = t.as_str() {
                if !s.is_empty() {
                    tags.push(format!("tag:{}", s));
                }
            }
        }
    }
    if let Some(cat) = album
        .get("category")
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
    {
        if !cat.is_empty() {
            tags.push(format!("category:{}", cat));
        }
    }
    if let Some(sub_cat) = album
        .get("category_sub")
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
    {
        if !sub_cat.is_empty() {
            tags.push(format!("category:{}", sub_cat));
        }
    }

    let description = album
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let cover = if fetch_cover {
        format!("{}/media/albums/{}_3x4.jpg", image_base, album_id)
    } else {
        String::new()
    };

    let tags_csv = tags.join(", ");
    Ok((title, tags_csv, description, cover))
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

fn resolve_api_base(params: &Value, auth: &JmAuthData) -> String {
    let index = if auth.api_domain > 0 {
        auth.api_domain
    } else {
        read_int_param(params, "api_domain", 1)
    };
    let chosen = clamp_index(index, API_DOMAINS.len());
    format!("https://{}", API_DOMAINS[chosen])
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
    let response = http_request_text("GET", &url, None, &headers, bypass_url)?;
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
    let image_base = setting
        .get("img_host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if image_base.is_empty() {
        return Ok(DEFAULT_IMAGE_BASE.to_string());
    }
    Ok(image_base.trim_end_matches('/').to_string())
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
                        "jmcomicmeta bypass failed for {}, fallback direct: {}",
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

    let text = String::from_utf8_lossy(&body).to_string();
    Ok(HttpResponse {
        status,
        headers,
        body: text.into_bytes(),
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
