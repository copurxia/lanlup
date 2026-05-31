use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, KeyInit};
use aes::Aes256;
use md5::{Digest, Md5};
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
const HTTP_TIMEOUT_MS: i32 = 15000;
const MAX_REDIRECTS: usize = 5;
const MAX_HTTP_RETRIES: usize = 3;

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
    action: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize, Clone)]
struct JmAuthData {
    #[serde(default)]
    uid: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    api_domain: i64,
    #[serde(default)]
    image_stream: i64,
    #[serde(default)]
    bypass_url: String,
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

    HostBridge::log(1, &format!("jmcomicsource action={}", input.action));

    let result = match input.action.as_str() {
        "source_home" => run_source_home(&input),
        "source_search" => run_source_search(&input),
        "source_detail" => run_source_detail(&input),
        "source_download" => run_source_download(&input),
        "source_reader" => run_source_reader(&input),
        "source_filters" => run_source_filters(&input),
        "source_page_asset" => run_source_page_asset(&input),
        "source_cover_asset" => run_source_cover_asset(&input),
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
        "name": "JM Comic Source",
        "plugin_type": "Source",
        "namespace": "jmcomicsource",
        "pre": ["jmcomiclogin"],
        "author": "Lanlu",
        "version": "0.2.1",
        "description": "Browse and search JM Comic online galleries for Lanlu.",
        "parameters": [],
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read",
            "task_kv.write",
            "asset.install_from_file"
        ],
        "update_url": ""
    })
}

fn run_source_home(_input: &PluginInput) -> Value {
    HostBridge::progress(5, "加载首页...");
    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let api_base = resolve_api_base(&_input.params, &auth);
    let bypass_url = resolve_bypass_url(&_input.params, &auth);
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_home api_base={} bypass={}",
            api_base,
            if bypass_url.trim().is_empty() {
                "off"
            } else {
                "on"
            }
        ),
    );
    let image_base = match resolve_image_base(&api_base, &_input.params, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(1, &format!("jmcomicsource image base fallback: {}", e));
            DEFAULT_IMAGE_BASE.to_string()
        }
    };

    let url = format!("{}/promote?page=0", api_base);
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_home api_base={} image_base={} bypass={}",
            api_base,
            image_base,
            if bypass_url.trim().is_empty() {
                "off"
            } else {
                "on"
            }
        ),
    );
    HostBridge::log(1, &format!("jmcomicsource GET {}", url));
    let response = match api_get(&url, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to fetch home: {e}")),
    };
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_home response status={} body_len={} time={}",
            response.0,
            response.1.len(),
            response.2
        ),
    );
    if response.0 != 200 {
        return output_err(&format!("Home API returned status {}", response.0));
    }

    let (items, debug) = match parse_promote_list(&response.1, response.2, &image_base) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse home: {e}")),
    };
    HostBridge::log(
        1,
        &format!("jmcomicsource source_home parse_debug={}", debug),
    );

    HostBridge::progress(100, "首页加载完成");
    output_ok_data(json!({
        "items": items,
        "debug": debug,
    }))
}

fn run_source_search(input: &PluginInput) -> Value {
    HostBridge::progress(5, "搜索中...");
    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let api_base = resolve_api_base(&input.params, &auth);
    let bypass_url = resolve_bypass_url(&input.params, &auth);
    let image_base = match resolve_image_base(&api_base, &input.params, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(1, &format!("jmcomicsource image base fallback: {}", e));
            DEFAULT_IMAGE_BASE.to_string()
        }
    };

    let query = input
        .params
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("");
    let page = input
        .params
        .get("page")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    if query.is_empty() {
        return output_err("query is required for search");
    }

    let encoded_query = urlencoding_encode(query);
    let url = format!(
        "{}/search?search_query={}&o=mr&page={}",
        api_base, encoded_query, page
    );
    HostBridge::log(1, &format!("jmcomicsource source_search GET {}", url));
    let response = match api_get(&url, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Search failed: {e}")),
    };
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_search response status={} body_len={} time={}",
            response.0,
            response.1.len(),
            response.2
        ),
    );
    if response.0 != 200 {
        return output_err(&format!("Search API returned status {}", response.0));
    }

    let items = match parse_search_list(&response.1, response.2, &image_base) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse search: {e}")),
    };
    let next_page = if items.is_empty() {
        None
    } else {
        Some(page + 1)
    };

    HostBridge::progress(100, "搜索完成");
    output_ok_data(json!({
        "items": items,
        "next_page": next_page,
    }))
}

fn run_source_detail(input: &PluginInput) -> Value {
    HostBridge::progress(10, "加载详情...");
    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let api_base = resolve_api_base(&input.params, &auth);
    let bypass_url = resolve_bypass_url(&input.params, &auth);

    let album_id = extract_remote_id(&input.params);
    if album_id.is_empty() {
        return output_err("remote_id (album_id) is required for detail");
    }

    let url = format!("{}/album?id={}", api_base, album_id);
    let response = match api_get(&url, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Detail fetch failed: {e}")),
    };
    if response.0 != 200 {
        return output_err(&format!("Detail API returned status {}", response.0));
    }

    let album: Value = match parse_encrypted_body(&response.1, response.2) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse detail: {e}")),
    };

    let title = album
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("Untitled")
        .to_string();
    let image_base = match resolve_image_base(&api_base, &input.params, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(1, &format!("jmcomicsource image base fallback: {}", e));
            DEFAULT_IMAGE_BASE.to_string()
        }
    };
    let cover = format!("{}/media/albums/{}_3x4.jpg", image_base, album_id);
    let description = album
        .get("description")
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

    // Build archives (chapters) list
    let mut children = Vec::new();
    if let Some(series) = album.get("series").and_then(Value::as_array) {
        for item in series {
            let ep_id = value_to_id_string(item.get("id"));
            let ep_name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if ep_id.is_empty() {
                continue;
            }
            let display_name = if ep_name.is_empty() {
                format!("第{}話", ep_id)
            } else {
                ep_name
            };
            children.push(json!({
                "kind": "archive",
                "source_namespace": "jmcomicsource",
                "remote_id": ep_id,
                "title": display_name,
                "subtitle": "",
                "cover": cover.clone(),
                "cover_asset_id": ensure_cover_asset(&cover, &ep_id),
                "tags": [],
                "downloadable": true,
                "readable": true,
                "parent_remote_id": album_id,
                "reader": {
                    "reader_action": "source_reader",
                    "download_action": "source_download",
                },
            }));
        }
    }
    if children.is_empty() {
        children.push(json!({
            "kind": "archive",
            "source_namespace": "jmcomicsource",
            "remote_id": album_id,
            "title": title.clone(),
            "subtitle": "",
            "cover": cover.clone(),
            "cover_asset_id": ensure_cover_asset(&cover, &album_id),
            "tags": [],
            "downloadable": true,
            "readable": true,
            "reader": {
                "reader_action": "source_reader",
                "download_action": "source_download",
            },
        }));
    }

    HostBridge::progress(100, "详情加载完成");
    output_ok_data(json!({
        "kind": "tankoubon",
        "source_namespace": "jmcomicsource",
        "remote_id": album_id,
        "title": title,
        "description": description,
        "cover": cover,
        "cover_asset_id": ensure_cover_asset(&cover, &album_id),
        "tags": tags,
        "downloadable": true,
        "readable": true,
        "children": children,
    }))
}

fn run_source_download(input: &PluginInput) -> Value {
    let album_id = extract_remote_id(&input.params);
    if album_id.is_empty() {
        return output_err("remote_id (album_id) is required for download");
    }

    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let api_base = resolve_api_base(&input.params, &auth);
    let gallery_url = format!("{}/album?id={}", api_base, album_id);
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_download enqueues gallery url: {}",
            gallery_url
        ),
    );

    output_ok_data(json!({
        "gallery_url": gallery_url,
        "gallery_id": album_id,
    }))
}

fn run_source_reader(input: &PluginInput) -> Value {
    let remote_id = extract_remote_id(&input.params);
    if remote_id.is_empty() {
        return output_err("remote_id is required for reader");
    }

    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let api_base = resolve_api_base(&input.params, &auth);
    let bypass_url = resolve_bypass_url(&input.params, &auth);

    let parent_remote_id = input
        .params
        .get("parent_remote_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let ep_id = if parent_remote_id.is_empty() {
        let album_url = format!("{}/album?id={}", api_base, remote_id);
        let response = match api_get(&album_url, &auth, &bypass_url) {
            Ok(v) => v,
            Err(e) => return output_err(&format!("Album fetch failed: {e}")),
        };
        if response.0 != 200 {
            return output_err(&format!("Album API returned status {}", response.0));
        }
        let album: Value = match parse_encrypted_body(&response.1, response.2) {
            Ok(v) => v,
            Err(e) => return output_err(&format!("Failed to parse album: {e}")),
        };
        if let Some(series) = album.get("series").and_then(Value::as_array) {
            if let Some(first) = series.first() {
                value_to_id_string(first.get("id"))
            } else {
                remote_id
            }
        } else {
            remote_id
        }
    } else {
        remote_id
    };

    if ep_id.is_empty() {
        return output_err("Could not determine chapter ID");
    }

    let image_base = match resolve_image_base(&api_base, &input.params, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(1, &format!("jmcomicsource image base fallback: {}", e));
            DEFAULT_IMAGE_BASE.to_string()
        }
    };

    let chapter_url = format!("{}/chapter?id={}", api_base, ep_id);
    let chapter_response = match api_get(&chapter_url, &auth, &bypass_url) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Chapter fetch failed: {e}")),
    };
    if chapter_response.0 != 200 {
        return output_err(&format!("Chapter API returned status {}", chapter_response.0));
    }

    let chapter: Value = match parse_encrypted_body(&chapter_response.1, chapter_response.2) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to parse chapter: {e}")),
    };

    let images = chapter
        .get("images")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let total_images = images.len();

    // Lazy mode: return asset_ref (image URL) for each page without downloading
    let mut pages = Vec::new();
    for (idx, img_name_val) in images.iter().enumerate() {
        let img_name = img_name_val.as_str().unwrap_or("");
        if img_name.is_empty() {
            continue;
        }
        let page_num = idx + 1;
        HostBridge::progress(50, &format!("解析第 {page_num}/{total_images} 页..."));
        let img_url = format!("{}/media/photos/{}/{}", image_base, ep_id, img_name);
        pages.push(json!({
            "asset_ref": img_url,
            "type": "image",
            "page": page_num,
        }));
    }

    if pages.is_empty() {
        return output_err("failed to resolve any pages");
    }

    output_ok_data(json!({ "pages": pages }))
}

fn run_source_page_asset(input: &PluginInput) -> Value {
    let remote_id = extract_remote_id(&input.params);
    if remote_id.is_empty() {
        return output_err("remote_id is required for page_asset");
    }
    let page = input.params.get("page").and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }).unwrap_or(0);
    if page == 0 {
        return output_err("page is required for page_asset");
    }
    let asset_ref = input.params.get("asset_ref").and_then(Value::as_str).unwrap_or("");
    if asset_ref.is_empty() {
        return output_err("asset_ref is required for page_asset");
    }

    let cached_asset_id = get_cached_page_asset_id(&remote_id, page);
    if cached_asset_id > 0 {
        return output_ok_data(json!({"asset_id": cached_asset_id}));
    }

    let auth = match load_jm_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Auth failed: {e}")),
    };
    let bypass_url = resolve_bypass_url(&input.params, &auth);

    let ep_id = remote_id.as_str();
    let ext = asset_ref.rsplit('.').next().unwrap_or("jpg").to_ascii_lowercase();
    let guest_path = format!("/plugin/jm_{ep_id}_{page}.{ext}");

    let response = match http_get(asset_ref, None, "image/*", &[], &bypass_url) {
        Ok(resp) => resp,
        Err(e) => return output_err(&format!("下载第 {page} 页失败: {e}")),
    };
    if response.status >= 400 {
        return output_err(&format!("下载第 {page} 页 HTTP {}", response.status));
    }
    if let Err(e) = fs::write(&guest_path, &response.body) {
        return output_err(&format!("写入第 {page} 页文件失败: {e}"));
    }
    match HostBridge::call(
        "asset.install_from_file",
        json!({
            "guest_path": &guest_path,
            "original_filename": &format!("{page}.{ext}"),
            "content_type": guess_content_type(&ext),
        }),
    ) {
        Ok(resp) => {
            let asset_id = resp.get("asset_id").and_then(Value::as_i64).unwrap_or(0);
            if asset_id <= 0 {
                return output_err("asset.install_from_file returned invalid asset_id");
            }
            cache_page_asset_id(&remote_id, page, asset_id);
            output_ok_data(json!({"asset_id": asset_id}))
        }
        Err(e) => output_err(&format!("asset.install_from_file failed: {e}")),
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
fn download_and_install_asset(
    url: &str,
    guest_path: &str,
    original_filename: &str,
    content_type: &str,
    bypass_url: &str,
) -> Result<i64, String> {
    let response = http_get(url, None, "image/*", &[], bypass_url)
        .map_err(|e| format!("download failed: {e}"))?;
    if response.status >= 400 {
        return Err(format!("download HTTP {}", response.status));
    }
    fs::write(guest_path, &response.body).map_err(|e| format!("write failed: {e}"))?;
    let resp = HostBridge::call("asset.install_from_file", json!({
        "guest_path": guest_path,
        "original_filename": original_filename,
        "content_type": content_type,
    }))?;
    resp.get("asset_id").and_then(Value::as_i64).ok_or_else(|| "no asset_id in response".to_string())
}

/// Ensure cover asset exists, using task_kv cache
fn ensure_cover_asset(cover_url: &str, album_id: &str) -> Option<i64> {
    if cover_url.is_empty() { return None; }
    let cache_key = jm_cover_cache_key(album_id);
    if let Some(id) = get_cached_cover_asset_id(album_id) {
        return Some(id);
    }
    let url_lower = cover_url.to_ascii_lowercase();
    let ext = if url_lower.ends_with(".png") { "png" }
              else if url_lower.ends_with(".gif") { "gif" }
              else if url_lower.ends_with(".webp") { "webp" }
              else { "jpg" };
    let guest_path = format!("/plugin/jm_cover_{album_id}.{ext}");
    match download_and_install_asset(cover_url, &guest_path, &format!("cover.{ext}"), guess_content_type(ext), "") {
        Ok(asset_id) => {
            let _ = HostBridge::task_kv_set(&cache_key, json!(asset_id));
            Some(asset_id)
        }
        Err(e) => {
            HostBridge::log(2, &format!("jm cover asset failed for {album_id}: {e}"));
            None
        }
    }
}

fn run_source_cover_asset(input: &PluginInput) -> Value {
    let album_id = extract_remote_id(&input.params);
    if album_id.is_empty() {
        return output_err("remote_id is required for cover_asset");
    }
    let cover_ref = input.params.get("cover_ref").and_then(Value::as_str).unwrap_or("");
    if cover_ref.is_empty() {
        return output_err("cover_ref is required for cover_asset");
    }
    match ensure_cover_asset(cover_ref, &album_id) {
        Some(asset_id) => output_ok_data(json!({"asset_id": asset_id})),
        None => output_err("failed to create cover asset"),
    }
}

fn jm_cover_cache_key(album_id: &str) -> String {
    format!("jm_cover_{album_id}")
}

fn jm_page_cache_key(remote_id: &str, page: u64) -> String {
    format!("jm_page_{remote_id}_{page}")
}

fn get_cached_cover_asset_id(album_id: &str) -> Option<i64> {
    let cache_key = jm_cover_cache_key(album_id);
    match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => cached.as_i64().filter(|id| *id > 0),
        _ => None,
    }
}

fn get_cached_page_asset_id(remote_id: &str, page: u64) -> i64 {
    let cache_key = jm_page_cache_key(remote_id, page);
    match HostBridge::task_kv_get(&cache_key) {
        Ok(Some(cached)) => cached.as_i64().filter(|id| *id > 0).unwrap_or(0),
        _ => 0,
    }
}

fn cache_page_asset_id(remote_id: &str, page: u64, asset_id: i64) {
    if asset_id > 0 {
        let cache_key = jm_page_cache_key(remote_id, page);
        let _ = HostBridge::task_kv_set(&cache_key, json!(asset_id));
    }
}

fn extract_remote_id(params: &Value) -> String {
    params
        .get("remote_id")
        .and_then(Value::as_str)
        .or_else(|| params.get("__target_id").and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

fn load_jm_auth() -> Result<JmAuthData, String> {
    let value = HostBridge::task_kv_get(AUTH_DATA_KEY)?
        .ok_or_else(|| "Missing JM Comic auth data. Ensure jmcomiclogin ran.".to_string())?;
    serde_json::from_value(value).map_err(|e| format!("Invalid auth data: {e}"))
}

fn api_get(url: &str, auth: &JmAuthData, bypass_url: &str) -> Result<(u16, String, u64), String> {
    let time = current_timestamp();
    let response = api_get_with_time(url, auth, bypass_url, time)?;
    let text = String::from_utf8_lossy(&response.body).to_string();
    Ok((response.status, text, time))
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
    HostBridge::log(1, &format!("jmcomicsource image_base GET {}", url));
    let response = api_get_with_time(&url, auth, bypass_url, time)?;
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource image_base response status={} body_len={}",
            response.status,
            response.body.len()
        ),
    );
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

fn parse_promote_list(
    body: &str,
    time: u64,
    image_base: &str,
) -> Result<(Vec<Value>, Value), String> {
    let promote = parse_encrypted_body(body, time)?;
    let mut items = Vec::new();
    let mut section_count = 0usize;
    let mut raw_item_count = 0usize;
    let mut skipped_item_count = 0usize;
    let mut first_id_type = String::new();
    let mut first_id_value = String::new();

    if let Some(arr) = promote.as_array() {
        section_count = arr.len();
        for section in arr {
            let _section_title = section.get("title").and_then(Value::as_str).unwrap_or("");
            if let Some(content) = section.get("content").and_then(Value::as_array) {
                raw_item_count += content.len();
                for comic in content {
                    if first_id_type.is_empty() {
                        first_id_type = value_kind(comic.get("id")).to_string();
                        first_id_value = value_to_debug_string(comic.get("id"));
                    }
                    if let Some(item) = parse_comic_item(comic, image_base) {
                        items.push(item);
                    } else {
                        skipped_item_count += 1;
                    }
                }
            }
        }
    }
    let debug = json!({
        "sections": section_count,
        "raw_items": raw_item_count,
        "parsed_items": items.len(),
        "skipped_items": skipped_item_count,
        "first_id_type": first_id_type,
        "first_id_value": first_id_value,
    });
    Ok((items, debug))
}

fn parse_search_list(body: &str, time: u64, image_base: &str) -> Result<Vec<Value>, String> {
    let search_data = parse_encrypted_body(body, time)?;
    let mut items = Vec::new();
    let mut raw_item_count = 0usize;
    let mut skipped_item_count = 0usize;

    if let Some(content) = search_data.get("content").and_then(Value::as_array) {
        raw_item_count = content.len();
        for comic in content {
            if let Some(item) = parse_comic_item(comic, image_base) {
                items.push(item);
            } else {
                skipped_item_count += 1;
            }
        }
    }
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource source_search parsed raw_items={} parsed_items={} skipped_items={}",
            raw_item_count,
            items.len(),
            skipped_item_count
        ),
    );
    Ok(items)
}

fn parse_encrypted_body(body: &str, time: u64) -> Result<Value, String> {
    let json_resp: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let data_field = json_resp
        .get("data")
        .and_then(Value::as_str)
        .ok_or("Missing data field")?;

    let secret = format!("{}{}", time, JM_SECRET);
    let decrypted = jm_decrypt(data_field, &secret)?;
    serde_json::from_str(&decrypted).map_err(|e| e.to_string())
}

fn parse_comic_item(comic: &Value, image_base: &str) -> Option<Value> {
    let id = value_to_id_string(comic.get("id"));
    if id.is_empty() {
        return None;
    }
    let title = comic
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("Untitled")
        .to_string();
    let author = match comic.get("author") {
        Some(Value::String(v)) => v.to_string(),
        Some(Value::Array(arr)) => arr.get(0).and_then(Value::as_str).unwrap_or("").to_string(),
        _ => String::new(),
    };
    let cover = format!(
        "{}/media/albums/{}_3x4.jpg",
        image_base.trim_end_matches('/'),
        id
    );

    let mut tags = Vec::new();
    if let Some(cat) = comic
        .get("category")
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
    {
        if !cat.is_empty() {
            tags.push(cat.to_string());
        }
    }
    if let Some(sub) = comic
        .get("category_sub")
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
    {
        if !sub.is_empty() {
            tags.push(sub.to_string());
        }
    }

    Some(json!({
        "kind": "tankoubon",
        "source_namespace": "jmcomicsource",
        "remote_id": id,
        "title": title,
        "subtitle": author,
        "cover": cover,
        "cover_asset_id": get_cached_cover_asset_id(&id),
        "tags": tags,
        "downloadable": true,
        "readable": true,
    }))
}

fn value_to_id_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(v)) => v.trim().to_string(),
        Some(Value::Number(v)) => v.as_i64().map(|n| n.to_string()).unwrap_or_default(),
        _ => String::new(),
    }
}

fn value_kind(value: Option<&Value>) -> &'static str {
    match value {
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "bool",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        None => "missing",
    }
}

fn value_to_debug_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(v)) => v.chars().take(80).collect(),
        Some(Value::Number(v)) => v.to_string(),
        Some(Value::Bool(v)) => v.to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Array(v)) => format!("array(len={})", v.len()),
        Some(Value::Object(v)) => format!("object(keys={})", v.len()),
        None => "missing".to_string(),
    }
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
        ("Connection".to_string(), "close".to_string()),
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

fn run_source_filters(_input: &PluginInput) -> Value {
    output_ok_data(json!({
        "filters": [
            {
                "key": "category",
                "label": "分类",
                "type": "select",
                "options": [
                    { "label": "全部", "value": "" },
                    { "label": "單行本", "value": "single" },
                    { "label": "同人", "value": "doujin" },
                    { "label": "韓漫", "value": "korean" },
                    { "label": "美漫", "value": "western" },
                    { "label": "連載", "value": "serial" }
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

fn http_get_with_retry(
    url: &str,
    referer: Option<&str>,
    _cookies: &[&str],
    accept: &str,
    extra_headers: &[(String, String)],
    max_retries: usize,
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_get(url, referer, accept, extra_headers, bypass_url) {
            Ok(response) => {
                if response.status == 429 {
                    if attempt >= max_retries {
                        return Err(format!("HTTP 429 for {}. Retry later.", url));
                    }
                    let wait_ms = 1000u64.saturating_mul(attempt as u64 + 1);
                    HostBridge::log(
                        1,
                        &format!("jmcomicsource hit HTTP 429 attempt={} url={}", attempt, url),
                    );
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms.min(60_000)));
                    continue;
                }
                if is_retryable_status(response.status) {
                    if attempt >= max_retries {
                        return Ok(response);
                    }
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

fn api_get_with_time(
    url: &str,
    auth: &JmAuthData,
    bypass_url: &str,
    time: u64,
) -> Result<HttpResponse, String> {
    let headers = build_jm_headers(time);
    let url_with_uid = if auth.uid.is_empty() {
        url.to_string()
    } else {
        let sep = if url.contains('?') { "&" } else { "?" };
        format!("{}{}uid={}", url, sep, auth.uid)
    };
    http_get_with_retry(
        &url_with_uid,
        None,
        &[],
        "application/json",
        &headers,
        MAX_HTTP_RETRIES,
        bypass_url,
    )
}

fn http_get(
    url: &str,
    referer: Option<&str>,
    accept: &str,
    extra_headers: &[(String, String)],
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut current_referer = referer.map(|v| v.to_string());
    for _ in 0..=MAX_REDIRECTS {
        let response = match http_get_once(
            &current_url,
            current_referer.as_deref(),
            accept,
            extra_headers,
            bypass_url,
        ) {
            Ok(v) => v,
            Err(e) if !bypass_url.trim().is_empty() => {
                HostBridge::log(
                    2,
                    &format!(
                        "jmcomicsource bypass failed for {}, fallback direct: {}",
                        current_url, e
                    ),
                );
                http_get_once(
                    &current_url,
                    current_referer.as_deref(),
                    accept,
                    extra_headers,
                    "",
                )?
            }
            Err(e) => return Err(e),
        };
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
    bypass_url: &str,
) -> Result<HttpResponse, String> {
    let (effective_url, bypass_host) = resolve_bypass_request_url(url, bypass_url)?;
    HostBridge::log(
        1,
        &format!(
            "jmcomicsource http_get_once url={} effective_url={} x_hostname={}",
            url,
            effective_url,
            bypass_host.as_deref().unwrap_or("")
        ),
    );
    let parsed =
        Url::parse(&effective_url).map_err(|e| format!("invalid url {}: {}", effective_url, e))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme: {}", scheme));
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
    req.push_str(&format!("GET {} HTTP/1.1\r\n", path));
    if has_default_port(scheme, port) {
        req.push_str(&format!("Host: {}\r\n", host));
    } else {
        req.push_str(&format!("Host: {}:{}\r\n", host, port));
    }
    req.push_str(&format!("User-Agent: {}\r\n", USER_AGENT));
    req.push_str(&format!("Accept: {}\r\n", accept));
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
    req.push_str("\r\n");

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

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 500 | 502 | 503 | 504)
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
    let max_retries = 1000;
    let mut retries = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                retries = 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                retries += 1;
                if retries > max_retries {
                    return Err(format!(
                        "read timed out after {} WouldBlock retries",
                        max_retries
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(data)
}
