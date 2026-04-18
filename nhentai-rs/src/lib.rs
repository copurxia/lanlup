use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::slice;
use std::sync::{Arc, OnceLock};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str = "Lanlu/v1.00 (https://github.com/copurxia/lanlu)";
const HTTP_TIMEOUT_MS: i32 = 15000;
const MAX_REDIRECTS: usize = 5;
const AUTH_DATA_KEY: &str = "__lanlu.phase.nhlogin.data";

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
    url: String,
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
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
struct NhAuthData {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    api_key: String,
}

#[derive(Clone, Debug)]
struct GalleryData {
    id: i64,
    name: String,
    pretty_name: String,
    page_paths: Vec<String>,
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
            return Err("host_response_len returned negative length".to_string());
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(target_arch = "wasm32")]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
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
    let _ = &input.plugin_type;

    let result = run_download(&input);
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

fn run_download(input: &PluginInput) -> Value {
    let gallery_id = match extract_gallery_id(&input.url) {
        Some(v) => v,
        None => return output_err("Invalid nhentai URL. Use https://nhentai.net/g/123456/"),
    };
    let gallery_url = format!("https://nhentai.net/g/{gallery_id}/");
    let gallery_api_url = format!("https://nhentai.net/api/v2/galleries/{gallery_id}");
    let auth = match load_nh_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };
    let login_cookies = build_nh_login_cookies(&auth);
    let auth_headers = build_nh_api_auth_headers(&auth);
    HostBridge::progress(1, "Fetching gallery metadata...");
    let resp = match fetch_text_direct(
        &gallery_api_url,
        Some("https://nhentai.net/"),
        &login_cookies,
        &auth_headers,
    ) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to fetch gallery: {e}")),
    };
    if resp.0 == 404 {
        return output_err(&format!("Gallery not found: {gallery_id}"));
    }
    if resp.0 >= 400 {
        return output_err(&format!("Failed to fetch gallery: status {}", resp.0));
    }

    let gallery = match parse_gallery(&resp.1, gallery_id) {
        Some(v) => v,
        None => return output_err("Failed to parse gallery information"),
    };
    HostBridge::log(
        1,
        &format!(
            "parsed gallery name={} pages={}",
            gallery.name,
            gallery.page_paths.len()
        ),
    );

    let safe = sanitize_filename(if gallery.pretty_name.is_empty() {
        &gallery.name
    } else {
        &gallery.pretty_name
    });
    let folder_name = format!("{} {}", gallery.id, safe);
    let plugin_base = resolve_plugin_dir(&input.plugin_dir, "nhentai");
    let plugin_dir = format!("{plugin_base}/{folder_name}");
    if let Err(e) = fs::create_dir_all(&plugin_dir) {
        return output_err(&format!("Failed to prepare plugin dir: {e}"));
    }

    let mut downloaded_count = 0usize;
    let mut failed_count = 0usize;
    let total = gallery.page_paths.len().max(1);
    for (offset, page_path) in gallery.page_paths.iter().enumerate() {
        let idx = offset + 1;
        let file_name = gallery_page_filename(page_path, idx);
        let image_url = gallery_page_url(page_path);
        let mut local_path = PathBuf::from(&plugin_dir);
        local_path.push(file_name);
        match download_file_direct(
            &image_url,
            &gallery_url,
            &login_cookies,
            &local_path,
            &[],
        ) {
            Ok(()) => downloaded_count += 1,
            Err(_) => failed_count += 1,
        }
        let percent = ((idx * 100) / total).clamp(1, 99) as i32;
        HostBridge::progress(percent, &format!("Downloading page {idx}/{total}..."));
    }

    HostBridge::progress(
        100,
        &format!(
            "Download complete: {} succeeded, {} failed",
            downloaded_count, failed_count
        ),
    );

    if downloaded_count == 0 {
        return output_err(&format!(
            "No images were downloaded for gallery: {}",
            gallery_id
        ));
    }

    json!({
        "success": true,
        "data": [{
            "plugin_relative_path": folder_name,
            "relative_path": folder_name,
            "filename": folder_name,
            "source": format!("https://nhentai.net/g/{gallery_id}/"),
            "downloaded_count": downloaded_count,
            "failed_count": failed_count,
            "archive_type": "folder"
        }]
    })
}

fn load_nh_auth() -> Result<NhAuthData, String> {
    let Some(value) = HostBridge::task_kv_get(AUTH_DATA_KEY)? else {
        return Err("Missing nHentai auth data in task KV. Ensure nhlogin ran as a pre hook.".to_string());
    };
    serde_json::from_value(value).map_err(|e| format!("Invalid nHentai auth data in task KV: {e}"))
}

fn build_nh_login_cookies(_: &NhAuthData) -> Vec<LoginCookie> {
    Vec::new()
}

fn extract_gallery_id(url: &str) -> Option<i64> {
    let reg = Regex::new(r"nhentai\.net/g/(\d+)").ok()?;
    let caps = reg.captures(url)?;
    caps.get(1)?.as_str().parse::<i64>().ok()
}

fn parse_gallery(json_text: &str, gallery_id: i64) -> Option<GalleryData> {
    let gallery: Value = serde_json::from_str(json_text).ok()?;
    let title = gallery.get("title").cloned().unwrap_or(Value::Null);
    let pretty_name = title
        .get("pretty")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let name = title
        .get("english")
        .and_then(Value::as_str)
        .or_else(|| title.get("japanese").and_then(Value::as_str))
        .unwrap_or("Untitled")
        .to_string();

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
        let media_id = gallery.get("media_id")?.as_str()?.to_string();
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

    if page_paths.is_empty() {
        return None;
    }

    Some(GalleryData {
        id: gallery_id,
        name,
        pretty_name,
        page_paths,
    })
}

fn gallery_page_url(page_path: &str) -> String {
    let normalized = page_path.trim();
    if normalized.starts_with("https://") || normalized.starts_with("http://") {
        return normalized.to_string();
    }
    format!(
        "https://i.nhentai.net/{}",
        normalized.trim_start_matches('/')
    )
}

fn gallery_page_filename(page_path: &str, index: usize) -> String {
    let normalized = page_path
        .trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .trim();
    if normalized.is_empty() {
        format!("{index}.jpg")
    } else {
        normalized.to_string()
    }
}

fn sanitize_filename(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch == '<'
            || ch == '>'
            || ch == ':'
            || ch == '"'
            || ch == '/'
            || ch == '\\'
            || ch == '|'
            || ch == '?'
            || ch == '*'
            || ch == '['
            || ch == ']'
            || ch == '「'
            || ch == '」'
        {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        return "Gallery".to_string();
    }
    trimmed.chars().take(80).collect()
}

fn resolve_plugin_dir(raw: &str, ns: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return format!("./data/cache/plugins/{ns}");
    }
    trimmed.to_string()
}

fn build_cookie_header(url: &str, cookies: &[LoginCookie]) -> String {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|v| v.to_ascii_lowercase()))
        .unwrap_or_default();
    let mut pairs = Vec::new();
    for c in cookies {
        let name = c.name.trim();
        let value = c.value.trim();
        if name.is_empty() || name.starts_with("__lanlu_") {
            continue;
        }
        let domain = c.domain.trim().trim_start_matches('.').to_ascii_lowercase();
        if !domain.is_empty()
            && !host.is_empty()
            && host != domain
            && !host.ends_with(&format!(".{domain}"))
        {
            continue;
        }
        pairs.push(format!("{name}={value}"));
    }
    pairs.join("; ")
}

fn build_nh_api_auth_headers(auth: &NhAuthData) -> Vec<(String, String)> {
    if auth.mode.trim() == "key" && !auth.api_key.trim().is_empty() {
        vec![("Authorization".to_string(), format!("Key {}", auth.api_key.trim()))]
    } else {
        Vec::new()
    }
}

fn fetch_text_direct(
    url: &str,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<(u16, String), String> {
    let response = http_get(
        url,
        referer,
        cookies,
        "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        extra_headers,
    )?;
    let text = String::from_utf8_lossy(&response.body).to_string();
    Ok((response.status, text))
}

fn download_file_direct(
    url: &str,
    referer: &str,
    cookies: &[LoginCookie],
    output: &PathBuf,
    extra_headers: &[(String, String)],
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let resp = http_get(url, Some(referer), cookies, "image/*,*/*", extra_headers)?;
    if resp.status >= 400 {
        return Err(format!("HTTP {}", resp.status));
    }
    let mut file = File::create(output).map_err(|e| e.to_string())?;
    file.write_all(&resp.body).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_get(
    url: &str,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    accept: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut current_referer = referer.map(|v| v.to_string());
    for _ in 0..=MAX_REDIRECTS {
        let response = http_get_once(
            &current_url,
            current_referer.as_deref(),
            cookies,
            accept,
            extra_headers,
        )?;
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
    cookies: &[LoginCookie],
    accept: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid url {url}: {e}"))?;
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

    let cookie_header = build_cookie_header(url, cookies);
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
    if !cookie_header.is_empty() {
        req.push_str(&format!("Cookie: {cookie_header}\r\n"));
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

fn write_all_to_stream<T: Write>(stream: &mut T, buf: &[u8]) -> Result<(), String> {
    let mut sent = 0usize;
    while sent < buf.len() {
        let n = stream.write(&buf[sent..]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("socket write returned 0".to_string());
        }
        sent += n;
    }
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
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

fn read_https_response(
    stream: HostTcpStream,
    host: &str,
    request: &[u8],
) -> Result<Vec<u8>, String> {
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
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response: missing headers".to_string())?;
    let (head, rest) = raw.split_at(header_end + 4);
    let header_text = String::from_utf8_lossy(head);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "invalid HTTP response: empty status line".to_string())?;
    let mut status_parts = status_line.split_whitespace();
    let _http_ver = status_parts.next();
    let status = status_parts
        .next()
        .ok_or_else(|| "invalid HTTP response: missing status".to_string())?
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
        let line_end = find_crlf(input, idx).ok_or_else(|| "invalid chunked body".to_string())?;
        let size_line = String::from_utf8_lossy(&input[idx..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {size_hex}"))?;
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
    find_header_value(headers, "content-length").and_then(|v| v.parse::<usize>().ok())
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
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("failed to resolve {host}:{port}"))
}

fn output_err(message: &str) -> Value {
    json!({
        "success": false,
        "error": message
    })
}

fn plugin_info_json() -> Value {
    json!({
        "name": "nhentai Downloader (Rust)",
        "type": "download",
        "namespace": "nhentai",
        "pre": ["nhlogin"],
        "author": "Lanlu",
        "version": "0.2.0",
        "description": "Rust/WASM nhentai downloader using the nHentai API.",
        "parameters": [],
        "url_regex": "https?://nhentai\\.net/g/\\d+/?",
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect",
            "task_kv.read"
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
    if ptr == 0 || len <= 0 {
        return &[];
    }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}
