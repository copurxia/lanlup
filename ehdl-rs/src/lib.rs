use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::sync::Arc;
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wasmedge_host")]
extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32) -> i32;
    fn host_progress(percent: i32, ptr: i32, len: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 {
    0
}

thread_local! {
    static STATE: RefCell<PluginState> = RefCell::new(PluginState::default());
    static DOWNLOAD_PROGRESS: RefCell<DownloadProgressState> = RefCell::new(DownloadProgressState::default());
}

#[derive(Default)]
struct PluginState {
    info: Vec<u8>,
    result: Vec<u8>,
    error: Vec<u8>,
}

#[derive(Default)]
struct DownloadProgressState {
    active: bool,
    base_downloaded: u64,
    total_expected: u64,
    last_percent: i32,
    last_bytes: u64,
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
    #[serde(rename = "loginCookies", default)]
    login_cookies: Vec<LoginCookie>,
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
    let url = input.url.trim();
    if url.is_empty() {
        return output_err("No URL provided.");
    }

    let forceresampled = read_forceresampled(&input.params);
    HostBridge::progress(1, "Starting E-Hentai download...");

    let reg = Regex::new(r"^https?://e(-|x)hentai\.org/g/([0-9]+)/([0-9A-Za-z]+)/?.*$")
        .expect("valid regex");
    let caps = match reg.captures(url) {
        Some(c) => c,
        None => return output_err("Not a valid E-H URL!"),
    };
    let domain_prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
    let gid = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
    let token = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
    let domain = if domain_prefix == "x" {
        "https://exhentai.org"
    } else {
        "https://e-hentai.org"
    };
    let archiver_url = format!("{domain}/archiver.php?gid={gid}&token={token}");
    HostBridge::log(1, &format!("resolved gallery gid={gid} token={token}"));

    HostBridge::progress(15, "Checking archiver page...");
    let check = match http_request_text("GET", &archiver_url, None, None, &input.login_cookies) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Archiver check failed: {e}")),
    };
    if check.0 >= 400 {
        return output_err(&format!("Failed to access archiver: HTTP {}", check.0));
    }
    if check.1.contains("Invalid archiver key") {
        return output_err(&format!("Invalid archiver key. ({archiver_url})"));
    }
    if check.1.contains("This page requires you to log on.") {
        return output_err(
            "Invalid E*Hentai login credentials. Please make sure the login plugin has proper settings set.",
        );
    }

    HostBridge::progress(25, "Requesting archive download link...");
    let dltype = if forceresampled { "res" } else { "org" };
    let dlcheck = if forceresampled {
        "Download+Resample+Archive"
    } else {
        "Download+Original+Archive"
    };
    let body = format!("dltype={dltype}&dlcheck={dlcheck}");
    let req = match http_request_text(
        "POST",
        &archiver_url,
        Some(&body),
        Some(&archiver_url),
        &input.login_cookies,
    ) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Download URL generation failed: {e}")),
    };
    if req.0 >= 400 {
        return output_err(&format!("POST request failed: HTTP {}", req.0));
    }
    if req.1.contains("Insufficient funds") {
        return output_err("You do not have enough GP to download this URL.");
    }

    let final_reg = Regex::new(r#"document\.location\s*=\s*"([^"]+)""#).expect("valid regex");
    let final_match = match final_reg.captures(&req.1) {
        Some(c) => c,
        None => {
            let archive_type = if forceresampled {
                "resampled"
            } else {
                "original size"
            };
            return output_err(&format!(
                "Couldn't proceed with {archive_type} download: <pre>{}</pre>",
                req.1
            ));
        }
    };
    let mut final_url = final_match
        .get(1)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    if let Ok(mut parsed) = Url::parse(&final_url) {
        parsed.query_pairs_mut().append_pair("start", "1");
        final_url = parsed.to_string();
    }

    HostBridge::progress(30, "Downloading archive...");
    let file_name_hint = format!(
        "ehdl_{}_{}_{}.zip",
        gid,
        token,
        if forceresampled { "res" } else { "org" }
    );
    let plugin_dir = resolve_plugin_dir(&input.plugin_dir, "ehdl");
    let title_hint = extract_gallery_title_hint(&check.1)
        .or_else(|| extract_gallery_title_hint(&req.1));
    let (final_relative_path, final_filename) = match download_archive_direct(
        &final_url,
        domain,
        &input.login_cookies,
        &plugin_dir,
        title_hint.as_deref(),
        &file_name_hint,
    ) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Archive download failed: {e}")),
    };
    HostBridge::progress(100, "Download complete");
    json!({
        "success": true,
        "data": [{
            "plugin_relative_path": final_relative_path,
            "relative_path": final_relative_path,
            "filename": final_filename,
            "source": format!("https://e-hentai.org/g/{gid}/{token}"),
            "archive_size": if forceresampled { "resampled" } else { "original" },
            "archive_type": "archive"
        }]
    })
}

fn read_forceresampled(params: &Value) -> bool {
    let value = params.get("forceresampled");
    match value {
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(v)) => v.as_i64().unwrap_or(0) != 0,
        Some(Value::String(v)) => {
            let s = v.trim().to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        }
        _ => false,
    }
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
        if name.is_empty() {
            continue;
        }
        let domain = c.domain.trim().trim_start_matches('.').to_ascii_lowercase();
        if !domain.is_empty() && !host.is_empty() && host != domain && !host.ends_with(&format!(".{domain}")) {
            continue;
        }
        pairs.push(format!("{name}={value}"));
    }
    pairs.join("; ")
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
struct HostTcpStream {
    stream: WasiTcpStream,
}

#[cfg(target_arch = "wasm32")]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
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
        Ok(())
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

enum HttpStream {
    Plain(HostTcpStream),
    Tls(Box<StreamOwned<ClientConnection, HostTcpStream>>),
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            HttpStream::Plain(s) => s.read(buf),
            HttpStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            HttpStream::Plain(s) => s.write(buf),
            HttpStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            HttpStream::Plain(s) => s.flush(),
            HttpStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_request_text(
    method: &str,
    url: &str,
    body: Option<&str>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
) -> Result<(u16, String), String> {
    let resp = http_request_bytes_follow_redirects(
        method,
        url,
        body.map(str::as_bytes),
        referer,
        cookies,
    )?;
    let text = String::from_utf8_lossy(&resp.body).to_string();
    Ok((resp.status, text))
}

fn http_request_bytes_follow_redirects(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
) -> Result<HttpResponse, String> {
    http_request_bytes_follow_redirects_with_headers(method, url, body, referer, cookies, &[])
}

fn http_request_bytes_follow_redirects_with_headers(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, String> {
    let mut current_method = method.to_ascii_uppercase();
    let mut current_url = url.to_string();
    let mut current_body = body.map(|v| v.to_vec());
    for _ in 0..=MAX_REDIRECTS {
        let resp = http_request_once(
            &current_method,
            &current_url,
            current_body.as_deref(),
            referer,
            cookies,
            extra_headers,
        )?;
        if !is_redirect_status(resp.status) {
            return Ok(resp);
        }
        let Some(location) = header_value(&resp.headers, "Location") else {
            return Ok(resp);
        };
        let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
        let resolved = base.join(location).map_err(|e| e.to_string())?;
        if resp.status == 303 || ((resp.status == 301 || resp.status == 302) && current_method == "POST")
        {
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
) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("missing host in URL: {url}"))?
        .to_string();
    let scheme = parsed.scheme().to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("missing port for URL: {url}"))?;
    let mut stream = connect_http_stream(&scheme, &host, port)?;
    let mut req = Vec::with_capacity(1024 + body.map(|v| v.len()).unwrap_or(0));
    let path = request_path(&parsed);
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
    if method.eq_ignore_ascii_case("POST") {
        req.extend_from_slice(b"Content-Type: application/x-www-form-urlencoded\r\n");
    }
    if let Some(v) = body {
        req.extend_from_slice(format!("Content-Length: {}\r\n", v.len()).as_bytes());
    } else if method.eq_ignore_ascii_case("POST") {
        req.extend_from_slice(b"Content-Length: 0\r\n");
    }
    req.extend_from_slice(b"\r\n");
    stream.write_all(&req).map_err(|e| e.to_string())?;
    if let Some(v) = body {
        if !v.is_empty() {
            stream.write_all(v).map_err(|e| e.to_string())?;
        }
    }
    stream.flush().map_err(|e| e.to_string())?;
    read_http_response(&mut stream)
}

fn connect_http_stream(scheme: &str, host: &str, port: u16) -> Result<HttpStream, String> {
    let tcp = if scheme.eq_ignore_ascii_case("https") {
        if let Some((proxy_host, proxy_port)) = resolve_proxy_for_scheme(scheme) {
            let mut proxy_stream = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
            establish_proxy_connect_tunnel(&mut proxy_stream, host, port)?;
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
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| format!("invalid dns name: {host}"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
        Ok(HttpStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
    } else if scheme.eq_ignore_ascii_case("http") {
        Ok(HttpStream::Plain(tcp))
    } else {
        Err(format!("unsupported URL scheme: {scheme}"))
    }
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
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("proxy closed before CONNECT response".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("proxy CONNECT response too large".to_string());
        }
    };
    let (status, _) = parse_response_headers(&buf[..header_end])?;
    if !(200..300).contains(&status) {
        return Err(format!("proxy CONNECT failed: HTTP {status}"));
    }
    Ok(())
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    path
}

fn read_http_response(stream: &mut HttpStream) -> Result<HttpResponse, String> {
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        let n = read_stream_chunk(stream, &mut chunk, false)?;
        if n == 0 {
            return Err("connection closed before response headers".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let header_bytes = &buf[..header_end];
    let pending = buf[header_end + 4..].to_vec();
    let (status, headers) = parse_response_headers(header_bytes)?;
    HostBridge::log(
        1,
        &format!(
            "http response status={} te={:?} cl={:?}",
            status,
            header_value(&headers, "Transfer-Encoding"),
            header_value(&headers, "Content-Length")
        ),
    );
    let body = read_response_body(stream, &headers, pending)?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|v| v == b"\r\n\r\n")
}

fn parse_response_headers(raw: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "missing response status line".to_string())?;
    let mut parts = status_line.split_whitespace();
    let _http_ver = parts
        .next()
        .ok_or_else(|| "invalid response status line".to_string())?;
    let status = parts
        .next()
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status: {status_line}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

fn read_response_body(
    stream: &mut HttpStream,
    headers: &[(String, String)],
    pending: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if is_chunked(headers) {
        let mut raw = Vec::new();
        if !pending.is_empty() {
            raw.extend_from_slice(&pending);
        }
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = read_stream_chunk(stream, &mut buf, true)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        return decode_chunked_lenient(&raw);
    }
    if let Some(v) = header_value(headers, "Content-Length") {
        if let Ok(total) = v.parse::<usize>() {
            let mut out = Vec::with_capacity(total);
            let take = pending.len().min(total);
            out.extend_from_slice(&pending[..take]);
            report_download_network_progress(out.len() as u64, total as u64);
            let mut remaining = total - take;
            HostBridge::log(
                1,
                &format!(
                    "reading fixed body total={} pending={} remaining={}",
                    total, take, remaining
                ),
            );
            while remaining > 0 {
                let mut buf = vec![0u8; remaining.min(16 * 1024)];
                let n = read_stream_chunk(stream, &mut buf, true)?;
                if n == 0 {
                    HostBridge::log(
                        2,
                        &format!(
                            "fixed body eof before completion total={} read={} remaining={}",
                            total,
                            out.len(),
                            remaining
                        ),
                    );
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                report_download_network_progress(out.len() as u64, total as u64);
                remaining -= n;
            }
            HostBridge::log(1, &format!("fixed body consumed total={}", out.len()));
            return Ok(out);
        }
    }
    let mut out = Vec::new();
    if !pending.is_empty() {
        out.extend_from_slice(&pending);
    }
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = read_stream_chunk(stream, &mut buf, true)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn read_stream_chunk(stream: &mut HttpStream, buf: &mut [u8], allow_tls_eof: bool) -> Result<usize, String> {
    match stream.read(buf) {
        Ok(n) => Ok(n),
        Err(e) => {
            if allow_tls_eof && is_tls_close_notify_eof(&e) {
                return Ok(0);
            }
            Err(e.to_string())
        }
    }
}

fn is_tls_close_notify_eof(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return true;
    }
    err.to_string()
        .to_ascii_lowercase()
        .contains("peer closed connection without sending tls close_notify")
}

fn decode_chunked_lenient(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut pending = raw.to_vec();
    let mut out = Vec::new();
    loop {
        let line = match extract_line_crlf(&mut pending) {
            Some(v) => v,
            None => {
                if pending.is_empty() {
                    return Ok(out);
                }
                let v = String::from_utf8_lossy(&pending).to_string();
                pending.clear();
                v
            }
        };
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {size_hex}"))?;
        if size == 0 {
            return Ok(out);
        }
        if pending.len() < size {
            return Err("invalid chunked body: truncated chunk".to_string());
        }
        out.extend_from_slice(&pending[..size]);
        pending.drain(..size);
        if pending.len() >= 2 && &pending[..2] == b"\r\n" {
            pending.drain(..2);
        }
    }
}

fn extract_line_crlf(pending: &mut Vec<u8>) -> Option<String> {
    if let Some(pos) = pending.windows(2).position(|v| v == b"\r\n") {
        let line = String::from_utf8_lossy(&pending[..pos]).to_string();
        pending.drain(..pos + 2);
        Some(line)
    } else {
        None
    }
}

fn extract_gallery_title_hint(html: &str) -> Option<String> {
    let patterns = [
        r#"(?is)<h1[^>]*\bid\s*=\s*["']?gj["']?[^>]*>(.*?)</h1>"#,
        r#"(?is)<h1[^>]*\bid\s*=\s*["']?gn["']?[^>]*>(.*?)</h1>"#,
        r#"(?is)<title[^>]*>(.*?)</title>"#,
    ];
    for pattern in patterns {
        let re = match Regex::new(pattern) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(caps) = re.captures(html) else {
            continue;
        };
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let stripped = strip_html_tags(raw);
        let decoded = decode_basic_html_entities(&stripped);
        let mut title = decoded.trim().to_string();
        if title.is_empty() {
            continue;
        }
        if title.to_ascii_lowercase().contains("e-hentai") {
            for suffix in [" - E-Hentai Galleries", " - ExHentai.org"] {
                if title.ends_with(suffix) {
                    title = title.trim_end_matches(suffix).trim().to_string();
                }
            }
        }
        if !title.is_empty() {
            return Some(title);
        }
    }
    None
}

fn strip_html_tags(input: &str) -> String {
    let re = Regex::new(r"(?is)<[^>]+>").expect("valid regex");
    re.replace_all(input, " ").to_string()
}

fn decode_basic_html_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn ensure_unique_path(base_dir: &str, file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(base_dir);
    path.push(file_name);
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_stem()
        .and_then(|v| v.to_str())
        .unwrap_or("download")
        .to_string();
    let ext = path.extension().and_then(|v| v.to_str()).unwrap_or("");
    for i in 1..10000 {
        let candidate = if ext.is_empty() {
            format!("{stem}.{i}")
        } else {
            format!("{stem}.{i}.{ext}")
        };
        let mut p = PathBuf::from(base_dir);
        p.push(candidate);
        if !p.exists() {
            return p;
        }
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fallback = if ext.is_empty() {
        format!("{stem}.{ts}")
    } else {
        format!("{stem}.{ts}.{ext}")
    };
    let mut p = PathBuf::from(base_dir);
    p.push(fallback);
    p
}

fn resolve_archive_filename(
    headers: &[(String, String)],
    title_hint: Option<&str>,
    fallback_hint: &str,
) -> String {
    if let Some(v) = header_value(headers, "Content-Disposition")
        .and_then(parse_content_disposition_filename)
    {
        let safe = sanitize_filename_for_fs(&v);
        if !safe.is_empty() {
            return ensure_zip_extension(safe);
        }
    }
    if let Some(v) = title_hint {
        let safe = sanitize_filename_for_fs(v);
        if !safe.is_empty() {
            return ensure_zip_extension(safe);
        }
    }
    fallback_hint.to_string()
}

fn parse_content_disposition_filename(raw: &str) -> Option<String> {
    for token in raw.split(';') {
        let part = token.trim();
        let lower = part.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("filename*=") {
            let original = &part[part.len() - rest.len()..];
            let value = strip_surrounding_quotes(original);
            let encoded = value.split("''").nth(1).unwrap_or(value);
            let decoded = percent_decode_lossy(encoded);
            let candidate = decoded.trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }
    for token in raw.split(';') {
        let part = token.trim();
        let lower = part.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("filename=") {
            let original = &part[part.len() - rest.len()..];
            let candidate = strip_surrounding_quotes(original).trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn strip_surrounding_quotes(input: &str) -> &str {
    let s = input.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1] as char;
            let h2 = bytes[i + 2] as char;
            if let (Some(a), Some(b)) = (h1.to_digit(16), h2.to_digit(16)) {
                out.push(((a << 4) | b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn sanitize_filename_for_fs(input: &str) -> String {
    let leaf = input
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(input)
        .trim();
    let mut out = String::with_capacity(leaf.len());
    for ch in leaf.chars() {
        let bad = matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || ch.is_control();
        if bad {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    out.trim_matches([' ', '.']).trim().to_string()
}

fn ensure_zip_extension(name: String) -> String {
    if name.to_ascii_lowercase().ends_with(".zip") {
        name
    } else {
        format!("{name}.zip")
    }
}

fn download_archive_direct(
    url: &str,
    referer: &str,
    cookies: &[LoginCookie],
    plugin_dir: &str,
    title_hint: Option<&str>,
    file_name_hint: &str,
) -> Result<(String, String), String> {
    fs::create_dir_all(plugin_dir).map_err(|e| e.to_string())?;
    let mut target: Option<PathBuf> = None;
    let mut downloaded = 0u64;
    let mut expected_total: Option<u64> = None;
    for attempt in 0..6 {
        let mut extra_headers = Vec::new();
        if downloaded > 0 {
            extra_headers.push(("Range".to_string(), format!("bytes={downloaded}-")));
            HostBridge::log(
                1,
                &format!("archive resume attempt={} range=bytes={downloaded}-", attempt + 1),
            );
        } else {
            HostBridge::log(1, &format!("archive request attempt={}", attempt + 1));
        }
        begin_download_progress(downloaded, expected_total.unwrap_or(0));
        let resp = http_request_bytes_follow_redirects_with_headers(
            "GET",
            url,
            None,
            Some(referer),
            cookies,
            &extra_headers,
        )?;
        end_download_progress();
        if resp.status >= 400 {
            return Err(format!("HTTP {}", resp.status));
        }
        if downloaded > 0 && resp.status != 206 {
            return Err(format!(
                "resume not supported by upstream (status {})",
                resp.status
            ));
        }
        if downloaded == 0 && resp.status == 206 {
            downloaded = 0;
            expected_total = None;
        }
        if expected_total.is_none() {
            if resp.status == 206 {
                if let Some(v) = header_value(&resp.headers, "Content-Range") {
                    expected_total = parse_content_range_total(v);
                }
            }
            if expected_total.is_none() {
                if let Some(v) = header_value(&resp.headers, "Content-Length") {
                    expected_total = v.parse::<u64>().ok();
                }
            }
        }
        if target.is_none() {
            let preferred_name =
                resolve_archive_filename(&resp.headers, title_hint, file_name_hint);
            target = Some(ensure_unique_path(plugin_dir, &preferred_name));
        }
        let target_path = target
            .as_ref()
            .ok_or_else(|| "missing download target path".to_string())?;
        let mut file = if downloaded == 0 {
            File::create(target_path).map_err(|e| e.to_string())?
        } else {
            OpenOptions::new()
                .append(true)
                .open(target_path)
                .map_err(|e| e.to_string())?
        };
        file.write_all(&resp.body).map_err(|e| e.to_string())?;
        downloaded += resp.body.len() as u64;
        let total = expected_total.unwrap_or(downloaded.max(1));
        let pct = 30 + ((downloaded.saturating_mul(69) / total) as i32).clamp(0, 69);
        HostBridge::progress(pct.clamp(30, 99), "Downloading archive...");
        HostBridge::log(
            1,
            &format!(
                "archive progress attempt={} status={} got={} downloaded={} expected_total={}",
                attempt + 1,
                resp.status,
                resp.body.len(),
                downloaded,
                expected_total.unwrap_or(0)
            ),
        );
        if let Some(total) = expected_total {
            if downloaded >= total {
                break;
            }
        } else {
            // No total means server closed-delimited body; single request is enough.
            break;
        }
        if attempt == 5 {
            return Err(format!(
                "incomplete archive download after retries (downloaded={}, expected={})",
                downloaded,
                expected_total.unwrap_or(0)
            ));
        }
    }

    let target_path = target
        .as_ref()
        .ok_or_else(|| "missing download target path".to_string())?;
    let filename = target_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(file_name_hint)
        .to_string();
    Ok((filename.clone(), filename))
}

fn parse_content_range_total(v: &str) -> Option<u64> {
    // e.g. "bytes 100-199/1000"
    let total_part = v.split('/').nth(1)?.trim();
    if total_part == "*" {
        return None;
    }
    total_part.parse::<u64>().ok()
}

fn begin_download_progress(base_downloaded: u64, total_expected: u64) {
    DOWNLOAD_PROGRESS.with(|state| {
        let mut st = state.borrow_mut();
        st.active = true;
        st.base_downloaded = base_downloaded;
        st.total_expected = total_expected;
        st.last_percent = 30;
        st.last_bytes = base_downloaded;
    });
}

fn end_download_progress() {
    DOWNLOAD_PROGRESS.with(|state| {
        let mut st = state.borrow_mut();
        st.active = false;
    });
}

fn report_download_network_progress(read_in_current_response: u64, response_total: u64) {
    let mut emit: Option<(i32, String)> = None;
    DOWNLOAD_PROGRESS.with(|state| {
        let mut st = state.borrow_mut();
        if !st.active {
            return;
        }
        if st.total_expected == 0 && response_total > 0 {
            st.total_expected = st.base_downloaded.saturating_add(response_total);
        }
        let global_read = st.base_downloaded.saturating_add(read_in_current_response);
        let percent = if st.total_expected > 0 {
            30 + ((global_read.saturating_mul(69) / st.total_expected) as i32).clamp(0, 69)
        } else {
            30
        };
        let should_emit = percent > st.last_percent
            || global_read.saturating_sub(st.last_bytes) >= 1024 * 1024;
        if !should_emit {
            return;
        }
        st.last_percent = percent;
        st.last_bytes = global_read;
        let message = if st.total_expected > 0 {
            format!(
                "Downloading archive... {:.1}MiB / {:.1}MiB",
                global_read as f64 / 1024.0 / 1024.0,
                st.total_expected as f64 / 1024.0 / 1024.0
            )
        } else {
            format!(
                "Downloading archive... {:.1}MiB",
                global_read as f64 / 1024.0 / 1024.0
            )
        };
        emit = Some((percent.clamp(30, 99), message));
    });
    if let Some((percent, message)) = emit {
        HostBridge::progress(percent, &message);
    }
}

fn output_err(message: &str) -> Value {
    json!({
        "success": false,
        "error": message
    })
}

fn plugin_info_json() -> Value {
    json!({
        "name": "E*Hentai Downloader (Rust)",
        "type": "download",
        "namespace": "ehdl",
        "login_from": "ehlogin",
        "author": "Lanlu",
        "version": "0.1.0",
        "description": "Rust/WASM port of EHentai download plugin.",
        "parameters": [
            {
                "name": "forceresampled",
                "type": "bool",
                "desc": "Force resampled archive download",
                "default_value": "0"
            }
        ],
        "url_regex": "https?://e(-|x)hentai.org/g/.*/.*",
        "permissions": [
            "log.write",
            "progress.report",
            "tcp.connect"
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

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| e.to_string())?;
    addrs
        .next()
        .ok_or_else(|| format!("unable to resolve host: {host}:{port}"))
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}
