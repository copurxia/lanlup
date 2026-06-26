use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("ehentaisource-rs requires wasm32-wasip1 for socket support.");
#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;
const AUTH_DATA_KEY: &str = "__lanlu.phase.ehlogin.data";

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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LoginCookie {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    path: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct EhAuthData {
    #[serde(default)]
    ipb_member_id: String,
    #[serde(default)]
    ipb_pass_hash: String,
    #[serde(default)]
    star: String,
    #[serde(default)]
    igneous: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct EhListItem {
    gid: String,
    token: String,
    url: String,
    title: String,
    cover: String,
    pages: u64,
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

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
#[derive(Debug)]
struct HostTcpStream {
    stream: WasiTcpStream,
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
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
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stream.read(buf) }
}

#[cfg(not(target_arch = "wasm32"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.stream.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
}

enum HttpStream {
    Plain(HostTcpStream),
    Tls(Box<StreamOwned<ClientConnection, HostTcpStream>>),
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self { HttpStream::Plain(s) => s.read(buf), HttpStream::Tls(s) => s.read(buf) }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self { HttpStream::Plain(s) => s.write(buf), HttpStream::Tls(s) => s.write(buf) }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self { HttpStream::Plain(s) => s.flush(), HttpStream::Tls(s) => s.flush() }
    }
}

#[derive(Debug)]
struct RawHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpTextResponse {
    status: u16,
    text: String,
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

    HostBridge::log(1, &format!("ehentaisource action={}", input.action));

    let result = match input.action.as_str() {
        "source_home" => run_source_home(&input),
        "source_search" => run_source_search(&input),
        "source_filters" => run_source_filters(&input),
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
        "name": "E-Hentai Source (Rust)",
        "plugin_type": "Source",
        "namespace": "ehentaisource",
        "pre": ["ehlogin"],
        "author": "Lanlu",
        "version": "0.2.0",
        "description": "Browse and search E-Hentai galleries for Lanlu.",
        "parameters": [],
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read",
            "task_kv.write"
        ]
    })
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
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.error = message.into_bytes();
        0
    })
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 { return &[]; }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}

fn output_err(message: &str) -> Value {
    json!({ "success": false, "error": message })
}

fn output_ok_data(data: Value) -> Value {
    json!({ "success": true, "data": data })
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
                    { "label": "画集(CG)", "value": "artistcg" },
                    { "label": "游戏CG", "value": "game" },
                    { "label": "非H", "value": "non-h" },
                    { "label": "图集", "value": "image-set" },
                    { "label": "Cosplay", "value": "cosplay" },
                    { "label": "亚洲色情", "value": "asian-porn" },
                    { "label": "其他", "value": "misc" }
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
                    { "label": "热门", "value": "popular" },
                    { "label": "评分", "value": "rating" }
                ]
            }
        ]
    }))
}

fn resolve_domain(params: &Value) -> String {
    let raw = params.get("domain").and_then(Value::as_str).unwrap_or("e-hentai.org");
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

fn load_eh_auth() -> Result<EhAuthData, String> {
    let Some(value) = HostBridge::task_kv_get(AUTH_DATA_KEY)? else {
        return Ok(EhAuthData::default());
    };
    serde_json::from_value(value).map_err(|e| format!("invalid auth data: {e}"))
}

fn build_eh_login_cookies(auth: &EhAuthData) -> Vec<LoginCookie> {
    let member_id = auth.ipb_member_id.trim();
    let pass_hash = auth.ipb_pass_hash.trim();
    let mut cookies = Vec::new();
    for domain in ["e-hentai.org", "exhentai.org"] {
        // EH/ExHentai 需要 nw=1 才能跳过警告/熊猫页面；无登录态时也需要它。
        cookies.push(LoginCookie { name: "nw".to_string(), value: "1".to_string(), domain: domain.to_string(), path: "/".to_string() });
        if !member_id.is_empty() && !pass_hash.is_empty() {
            cookies.push(LoginCookie { name: "ipb_member_id".to_string(), value: member_id.to_string(), domain: domain.to_string(), path: "/".to_string() });
            cookies.push(LoginCookie { name: "ipb_pass_hash".to_string(), value: pass_hash.to_string(), domain: domain.to_string(), path: "/".to_string() });
        }
        if !auth.star.trim().is_empty() {
            cookies.push(LoginCookie { name: "star".to_string(), value: auth.star.trim().to_string(), domain: domain.to_string(), path: "/".to_string() });
        }
        if !auth.igneous.trim().is_empty() {
            cookies.push(LoginCookie { name: "igneous".to_string(), value: auth.igneous.trim().to_string(), domain: domain.to_string(), path: "/".to_string() });
        }
    }
    cookies
}

fn run_source_home(input: &PluginInput) -> Value {
    HostBridge::progress(5, "Loading home...");
    let domain = resolve_domain(&input.params);
    let page = input.params.get("page").and_then(|v| v.as_u64()).unwrap_or(1).max(1);
    let auth = match load_eh_auth() { Ok(v) => v, Err(e) => return output_err(&e) };
    let cookies = build_eh_login_cookies(&auth);

    let url = if page == 1 {
        format!("{domain}/")
    } else {
        format!("{domain}/?page={}", page - 1)
    };

    let response = match http_request_text("GET", &url, None, None, &cookies, &[]) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("home request failed: {e}")),
    };
    if response.status >= 400 {
        return output_err(&format!("home HTTP {}", response.status));
    }

    let items = parse_eh_list_html(&response.text, &domain);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };
    HostBridge::progress(100, "Home loaded");
    output_ok_data(json!({
        "items": items.into_iter().map(|item| eh_item_to_json(item)).collect::<Vec<Value>>(),
        "next_page": next_page,
    }))
}

fn run_source_search(input: &PluginInput) -> Value {
    HostBridge::progress(5, "Searching...");
    let domain = resolve_domain(&input.params);
    let query = input.params.get("query").and_then(Value::as_str).unwrap_or("");
    let page = input.params.get("page").and_then(|v| v.as_u64()).unwrap_or(1).max(1);
    let auth = match load_eh_auth() { Ok(v) => v, Err(e) => return output_err(&e) };
    let cookies = build_eh_login_cookies(&auth);

    let encoded = urlencoding::encode(query);
    let url = if page == 1 {
        format!("{domain}/?f_search={encoded}")
    } else {
        format!("{domain}/?f_search={encoded}&page={}", page - 1)
    };

    let response = match http_request_text("GET", &url, None, None, &cookies, &[]) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("search request failed: {e}")),
    };
    if response.status >= 400 {
        return output_err(&format!("search HTTP {}", response.status));
    }

    let items = parse_eh_list_html(&response.text, &domain);
    let next_page = if items.is_empty() { None } else { Some(page + 1) };
    HostBridge::progress(100, "Search complete");
    output_ok_data(json!({
        "items": items.into_iter().map(|item| eh_item_to_json(item)).collect::<Vec<Value>>(),
        "next_page": next_page,
    }))
}

fn eh_item_to_json(item: EhListItem) -> Value {
    json!({
        "kind": "archive",
        "source_namespace": "ehentaisource",
        "remote_id": format!("{}/{}", item.gid, item.token),
        "title": item.title,
        "subtitle": "",
        "cover": item.cover,
        "tags": [],
        "page_count": item.pages,
    })
}

fn parse_eh_list_html(html: &str, domain: &str) -> Vec<EhListItem> {
    let mut items = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Strategy 1: Compact / Extended / Minimal mode via <tr> rows
    let row_re = regex(r#"<tr[^>]*>([\s\S]*?)</tr>"#);
    let href_re = regex(r#"href=["']([^"']*/g/(\d+)/([0-9A-Za-z]+)/?)["']"#);
    let glink_re = regex(r#"<div[^>]*class=["']glink["'][^>]*>([\s\S]*?)</div>"#);
    let page_re = regex(r#"(\d+)(?:\s*pages?|\s*page)"#);

    for row_cap in row_re.captures_iter(html) {
        let row = row_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let hc = match href_re.captures(row) {
            Some(v) => v,
            None => continue,
        };
        let mut url = hc.get(1).unwrap().as_str().to_string();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("{domain}{}{}", if url.starts_with('/') { "" } else { "/" }, url);
        }
        let gid = hc.get(2).unwrap().as_str().to_string();
        let token = hc.get(3).unwrap().as_str().to_string();
        if !seen.insert(gid.clone()) { continue; }

        let title = if let Some(tc) = glink_re.captures(row) {
            strip_html_tags(tc.get(1).unwrap().as_str())
        } else {
            "Unknown".to_string()
        };

        let cover = extract_cover_from_row(row, &url);
        let pages = if let Some(pc) = page_re.captures(row) {
            pc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0)
        } else {
            0
        };

        items.push(EhListItem { gid, token, url, title, cover, pages });
    }

    if items.is_empty() {
        // Strategy 2: Thumbnail mode fallback
        let thumb_re = regex(r#"<div[^>]*class=["']gl1t["'][^>]*>([\s\S]*?)</div>"#);
        for cap in thumb_re.captures_iter(html) {
            let block = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let href_re = regex(r#"<a[^>]+href=["']([^"']*/g/(\d+)/([0-9A-Za-z]+)/?)["']"#);
            if let Some(hc) = href_re.captures(block) {
                let mut url = hc.get(1).unwrap().as_str().to_string();
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    url = format!("{domain}{}{}", if url.starts_with('/') { "" } else { "/" }, url);
                }
                let gid = hc.get(2).unwrap().as_str().to_string();
                let token = hc.get(3).unwrap().as_str().to_string();
                if !seen.insert(gid.clone()) { continue; }

                let title = if let Some(tc) = regex(r#"<div[^>]*class=["']glink["'][^>]*>([\s\S]*?)</div>"#).captures(block) {
                    strip_html_tags(tc.get(1).unwrap().as_str())
                } else if let Some(tc) = regex(r#"<div[^>]*class=["']glname["'][^>]*>([\s\S]*?)</div>"#).captures(block) {
                    strip_html_tags(tc.get(1).unwrap().as_str())
                } else {
                    "Unknown".to_string()
                };

                let cover = extract_cover_from_block(block, &url);
                let pages = extract_pages_from_block(block);

                items.push(EhListItem { gid, token, url, title, cover, pages });
            }
        }
    }

    items
}

fn extract_cover_from_row(row: &str, base_url: &str) -> String {
    // Prefer the image inside div.glthumb (compact/extended/minimal)
    let thumb_re = regex(r#"<div[^>]*class=["']glthumb["'][^>]*>[\s\S]*?<img[^>]+src=["']([^"']+)["']"#);
    if let Some(caps) = thumb_re.captures(row) {
        let src = caps.get(1).unwrap().as_str();
        if !src.is_empty() && !is_icon_image(src) {
            return normalize_cover_url(src, base_url);
        }
    }
    // Fallback: first non-icon img src in the row
    let img_re = regex(r#"<img[^>]+src=["']([^"']+)["']"#);
    for caps in img_re.captures_iter(row) {
        let src = caps.get(1).unwrap().as_str();
        if !src.is_empty() && !is_icon_image(src) {
            return normalize_cover_url(src, base_url);
        }
    }
    String::new()
}

fn extract_cover_from_block(block: &str, base_url: &str) -> String {
    // Thumbnail mode: first non-icon img
    let img_re = regex(r#"<img[^>]+(?:data-src|src)=["']([^"']+)["']"#);
    for caps in img_re.captures_iter(block) {
        let src = caps.get(1).unwrap().as_str();
        if !src.is_empty() && !is_icon_image(src) {
            return normalize_cover_url(src, base_url);
        }
    }
    // CSS background fallback
    if let Some(caps) = regex(r#"url\(\s*['"]?([^'"\)]+)['"]?\s*\)"#).captures(block) {
        if let Some(raw) = caps.get(1) {
            return normalize_cover_url(raw.as_str(), base_url);
        }
    }
    String::new()
}

fn is_icon_image(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    lower.starts_with("data:")
        || lower.contains("/g/td.png")
        || lower.contains("/g/tf.png")
        || lower.contains("/g/torrent.png")
        || lower.ends_with("/td.png")
        || lower.ends_with("/tf.png")
}

fn extract_pages_from_block(block: &str) -> u64 {
    let page_re = regex(r#"(\d+)(?:\s*pages?|\s*page)"#);
    if let Some(cap) = page_re.captures(block) {
        cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0)
    } else {
        0
    }
}

fn normalize_cover_url(raw: &str, base_url: &str) -> String {
    let value = html_unescape(raw.trim());
    if value.is_empty() { return String::new(); }
    if value.starts_with("data:image/") { return value; }
    if value.starts_with("//") { return format!("https:{value}"); }
    if let Ok(parsed) = Url::parse(&value) { return parsed.to_string(); }
    if let Ok(base) = Url::parse(base_url) {
        if let Ok(joined) = base.join(&value) { return joined.to_string(); }
    }
    String::new()
}

fn strip_html_tags(input: &str) -> String {
    let re = regex(r"(?is)<[^>]+>");
    re.replace_all(input, " ").trim().to_string()
}

fn html_unescape(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

// HTTP stack (from ehdl-rs / ehentai-rs)

fn http_request_text(
    method: &str,
    url: &str,
    body: Option<&str>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<HttpTextResponse, String> {
    let resp = http_request_bytes_follow_redirects_with_headers(
        method, url, body.map(str::as_bytes), referer, cookies, extra_headers,
    )?;
    Ok(HttpTextResponse { status: resp.status, text: String::from_utf8_lossy(&resp.body).to_string() })
}

fn http_request_bytes_follow_redirects_with_headers(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<RawHttpResponse, String> {
    let mut current_method = method.to_ascii_uppercase();
    let mut current_url = url.to_string();
    let mut current_body = body.map(|v| v.to_vec());
    for _ in 0..=MAX_REDIRECTS {
        let resp = http_request_once(&current_method, &current_url, current_body.as_deref(), referer, cookies, extra_headers)?;
        if !is_redirect_status(resp.status) { return Ok(resp); }
        let Some(location) = header_value(&resp.headers, "Location") else { return Ok(resp); };
        let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
        let resolved = base.join(location).map_err(|e| e.to_string())?;
        if resp.status == 303 || ((resp.status == 301 || resp.status == 302) && current_method == "POST") {
            current_method = "GET".to_string();
            current_body = None;
        }
        current_url = resolved.to_string();
    }
    Err(format!("too many redirects while requesting {url}"))
}

fn http_request_once(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<RawHttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or_else(|| format!("missing host: {url}"))?.to_string();
    let scheme = parsed.scheme().to_ascii_lowercase();
    let port = parsed.port_or_known_default().ok_or_else(|| format!("missing port: {url}"))?;
    let mut stream = connect_http_stream(&scheme, &host, port)?;
    let path = request_path(&parsed);
    let mut req = Vec::with_capacity(1024 + body.map(|v| v.len()).unwrap_or(0));

    req.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        req.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    } else {
        req.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
    }
    req.extend_from_slice(format!("User-Agent: {USER_AGENT}\r\n").as_bytes());
    req.extend_from_slice(b"Accept: */*\r\n");
    req.extend_from_slice(b"Accept-Encoding: identity\r\n");
    req.extend_from_slice(b"Connection: close\r\n");
    if let Some(v) = referer {
        req.extend_from_slice(format!("Referer: {v}\r\n").as_bytes());
    }
    for (k, v) in extra_headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    let cookie_header = build_cookie_header(url, cookies);
    if !cookie_header.is_empty() {
        req.extend_from_slice(format!("Cookie: {cookie_header}\r\n").as_bytes());
    }
    if method.eq_ignore_ascii_case("POST") && !extra_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Content-Type")) {
        req.extend_from_slice(b"Content-Type: application/x-www-form-urlencoded\r\n");
    }
    if let Some(v) = body {
        req.extend_from_slice(format!("Content-Length: {}\r\n", v.len()).as_bytes());
    } else if method.eq_ignore_ascii_case("POST") {
        req.extend_from_slice(b"Content-Length: 0\r\n");
    }
    req.extend_from_slice(b"\r\n");
    stream.write_all(&req).map_err(|e| e.to_string())?;
    if let Some(v) = body { if !v.is_empty() { stream.write_all(v).map_err(|e| e.to_string())?; } }
    stream.flush().map_err(|e| e.to_string())?;
    read_http_response(&mut stream)
}

fn connect_http_stream(scheme: &str, host: &str, port: u16) -> Result<HttpStream, String> {
    let tcp = if scheme.eq_ignore_ascii_case("https") {
        if let Some(proxy) = resolve_proxy_for_scheme(scheme) {
            let mut proxy_stream = HostTcpStream::connect(&proxy.host, proxy.port, DEFAULT_TIMEOUT_MS)?;
            let auth = proxy.username.as_deref().zip(proxy.password.as_deref());
            establish_proxy_connect_tunnel(&mut proxy_stream, host, port, auth)?;
            proxy_stream
        } else {
            HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
        }
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
    };
    if scheme.eq_ignore_ascii_case("https") {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let server_name = ServerName::try_from(host.to_string()).map_err(|_| format!("invalid dns name: {host}"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
        Ok(HttpStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
    } else if scheme.eq_ignore_ascii_case("http") {
        Ok(HttpStream::Plain(tcp))
    } else {
        Err(format!("unsupported scheme: {scheme}"))
    }
}

fn resolve_proxy_for_scheme(scheme: &str) -> Option<ProxyEndpoint> {
    let keys: &[&str] = if scheme.eq_ignore_ascii_case("https") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            if let Some(parsed) = parse_proxy_endpoint(&raw) { return Some(parsed); }
        }
    }
    None
}

struct ProxyEndpoint {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

fn parse_proxy_endpoint(raw: &str) -> Option<ProxyEndpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() { return None; }
    let normalized = if trimmed.contains("://") { trimmed.to_string() } else { format!("http://{trimmed}") };
    let parsed = Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(8080);
    let username = if parsed.username().is_empty() { None } else { Some(parsed.username().to_string()) };
    let password = parsed.password().map(|s| s.to_string());
    Some(ProxyEndpoint { host, port, username, password })
}

fn establish_proxy_connect_tunnel(stream: &mut HostTcpStream, target_host: &str, target_port: u16, proxy_auth: Option<(&str, &str)>) -> Result<(), String> {
    let auth_header = if let Some((user, pass)) = proxy_auth {
        let creds = format!("{user}:{pass}");
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        format!("Proxy-Authorization: Basic {encoded}\r\n")
    } else {
        String::new()
    };
    let req = format!("CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(req.as_bytes()).and_then(|_| stream.flush()).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) { break pos; }
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 { return Err("proxy closed before CONNECT response".to_string()); }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 { return Err("proxy CONNECT response too large".to_string()); }
    };
    let (status, _) = parse_response_headers(&buf[..header_end])?;
    if !(200..300).contains(&status) { return Err(format!("proxy CONNECT failed: HTTP {status}")); }
    Ok(())
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() { path.push('/'); }
    if let Some(q) = url.query() { path.push('?'); path.push_str(q); }
    path
}

fn read_http_response(stream: &mut HttpStream) -> Result<RawHttpResponse, String> {
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) { break pos; }
        let n = read_stream_chunk(stream, &mut chunk, false)?;
        if n == 0 { return Err("connection closed before headers".to_string()); }
        buf.extend_from_slice(&chunk[..n]);
    };
    let header_bytes = &buf[..header_end];
    let pending = buf[header_end + 4..].to_vec();
    let (status, headers) = parse_response_headers(header_bytes)?;
    let body = read_response_body(stream, &headers, pending)?;
    Ok(RawHttpResponse { status, headers, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|v| v == b"\r\n\r\n")
}

fn parse_response_headers(raw: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| "missing status line".to_string())?;
    let mut parts = status_line.split_whitespace();
    let _ = parts.next();
    let status = parts.next().and_then(|v| v.parse::<u16>().ok()).ok_or_else(|| format!("invalid HTTP status: {status_line}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        if let Some((k, v)) = line.split_once(':') { headers.push((k.trim().to_string(), v.trim().to_string())); }
    }
    Ok((status, headers))
}

fn read_response_body(stream: &mut HttpStream, headers: &[(String, String)], pending: Vec<u8>) -> Result<Vec<u8>, String> {
    if is_chunked(headers) {
        let mut raw = Vec::new();
        if !pending.is_empty() { raw.extend_from_slice(&pending); }
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = read_stream_chunk(stream, &mut buf, true)?;
            if n == 0 { break; }
            raw.extend_from_slice(&buf[..n]);
        }
        return decode_chunked_lenient(&raw);
    }
    if let Some(v) = header_value(headers, "Content-Length") {
        if let Ok(total) = v.parse::<usize>() {
            let mut out = Vec::with_capacity(total);
            let take = pending.len().min(total);
            out.extend_from_slice(&pending[..take]);
            let mut remaining = total - take;
            while remaining > 0 {
                let mut buf = vec![0u8; remaining.min(16 * 1024)];
                let n = read_stream_chunk(stream, &mut buf, true)?;
                if n == 0 { break; }
                out.extend_from_slice(&buf[..n]);
                remaining -= n;
            }
            return Ok(out);
        }
    }
    let mut out = Vec::new();
    if !pending.is_empty() { out.extend_from_slice(&pending); }
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = read_stream_chunk(stream, &mut buf, true)?;
        if n == 0 { break; }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn read_stream_chunk(stream: &mut HttpStream, buf: &mut [u8], allow_tls_eof: bool) -> Result<usize, String> {
    match stream.read(buf) {
        Ok(n) => Ok(n),
        Err(e) => {
            if allow_tls_eof && is_tls_close_notify_eof(&e) { return Ok(0); }
            Err(e.to_string())
        }
    }
}

fn is_tls_close_notify_eof(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::UnexpectedEof { return true; }
    err.to_string().to_ascii_lowercase().contains("peer closed connection without sending tls close_notify")
}

fn decode_chunked_lenient(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut pending = raw.to_vec();
    let mut out = Vec::new();
    loop {
        let line = match extract_line_crlf(&mut pending) {
            Some(v) => v,
            None => { if pending.is_empty() { return Ok(out); } String::from_utf8_lossy(&pending).to_string() }
        };
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| format!("invalid chunk size: {size_hex}"))?;
        if size == 0 { return Ok(out); }
        if pending.len() < size { return Err("truncated chunk".to_string()); }
        out.extend_from_slice(&pending[..size]);
        pending.drain(..size);
        if pending.len() >= 2 && &pending[..2] == b"\r\n" { pending.drain(..2); }
    }
}

fn extract_line_crlf(pending: &mut Vec<u8>) -> Option<String> {
    if let Some(pos) = pending.windows(2).position(|v| v == b"\r\n") {
        let line = String::from_utf8_lossy(&pending[..pos]).to_string();
        pending.drain(..pos + 2);
        Some(line)
    } else { None }
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked")))
        .unwrap_or(false)
}

fn build_cookie_header(url: &str, cookies: &[LoginCookie]) -> String {
    let host = Url::parse(url).ok().and_then(|u| u.host_str().map(|v| v.to_ascii_lowercase())).unwrap_or_default();
    let mut pairs = Vec::new();
    for c in cookies {
        let name = c.name.trim();
        let value = c.value.trim();
        if name.is_empty() { continue; }
        let domain = c.domain.trim().trim_start_matches('.').to_ascii_lowercase();
        if !domain.is_empty() && !host.is_empty() && host != domain && !host.ends_with(&format!(".{domain}")) { continue; }
        pairs.push(format!("{name}={value}"));
    }
    pairs.join("; ")
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = format!("{host}:{port}").to_socket_addrs().map_err(|e| e.to_string())?;
    addrs.next().ok_or_else(|| format!("failed to resolve {host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_real_eh_html() {
        let html = std::fs::read_to_string("/tmp/eh_sample.html").expect("need /tmp/eh_sample.html");
        let items = parse_eh_list_html(&html, "https://e-hentai.org");
        assert!(!items.is_empty(), "should parse at least one gallery");
        println!("Parsed {} galleries", items.len());

        for item in &items {
            println!("title={} cover={} pages={}", item.title, item.cover, item.pages);
        }

        // Check that all items have non-empty covers
        for item in &items {
            assert!(!item.cover.is_empty(), "cover should not be empty for '{}'", item.title);
        }

        // Check that first item looks reasonable
        let first = &items[0];
        assert!(first.cover.starts_with("http"), "cover should be a URL: {}", first.cover);
        assert!(first.pages > 0, "pages should be > 0");
    }
}
