use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::slice;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("ehlogin-rs requires wasm32-wasip1 (target_os = \"wasi\") for socket support.");

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
const EXHENTAI_URL: &str = "https://exhentai.org";
const INVALID_LOGIN_MARKER: &str = "You need to be logged in to view this page.";
const MAX_REDIRECTS: usize = 5;
const DEFAULT_TIMEOUT_MS: i32 = 30_000;

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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct LoginCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
}

#[derive(Debug)]
enum ValidationFailure {
    Invalid(String),
    Warning(String),
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
        Ok(value) => value,
        Err(err) => return set_error_and_zero(format!("invalid plugin input: {err}")),
    };

    let payload = build_result_payload(input);
    let result = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(err) => return set_error_and_zero(format!("failed to encode result: {err}")),
    };

    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = result;
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
        "name": "E-Hentai",
        "type": "login",
        "namespace": "ehlogin",
        "author": "Difegue",
        "version": "2.3",
        "description": "Handles login to E-H. If you have an account that can access fjorded content or exhentai, adding the credentials here will make more archives available for parsing.",
        "icon": "https://e-hentai.org/favicon.ico",
        "permissions": [
            "net=exhentai.org",
            "net=e-hentai.org",
            "net=forums.e-hentai.org",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "ipb_member_id", "type": "string", "desc": "ipb_member_id cookie"},
            {"name": "ipb_pass_hash", "type": "string", "desc": "ipb_pass_hash cookie"},
            {"name": "star", "type": "string", "desc": "star cookie (optional, if present you can view fjorded content without exhentai)"},
            {"name": "igneous", "type": "string", "desc": "igneous cookie(optional, if present you can view exhentai without Europe and America IP)"}
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Login/EHentai.ts",
        "runtime": "wamr",
        "abi_version": 1
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(data) => json!({
            "success": true,
            "data": data,
        }),
        Err(error) => json!({
            "success": false,
            "error": error,
        }),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    if !input.plugin_type.trim().is_empty() && !input.plugin_type.trim().eq_ignore_ascii_case("login")
    {
        return Err("ehlogin-rs only supports Login plugins".to_string());
    }

    HostBridge::progress(10, "读取登录参数...");
    let ipb_member_id = read_string_param(&input.params, "ipb_member_id");
    let ipb_pass_hash = read_string_param(&input.params, "ipb_pass_hash");
    let star = read_string_param(&input.params, "star");
    let igneous = read_string_param(&input.params, "igneous");

    HostBridge::progress(30, "验证登录凭据...");
    let result = do_login(&ipb_member_id, &ipb_pass_hash, &star, &igneous)?;
    HostBridge::progress(100, "登录完成");
    Ok(result)
}

fn do_login(
    ipb_member_id: &str,
    ipb_pass_hash: &str,
    star: &str,
    igneous: &str,
) -> Result<Value, String> {
    if ipb_member_id.is_empty() || ipb_pass_hash.is_empty() {
        return Ok(json!({
            "cookies": [],
            "message": "No cookies provided, returning blank UserAgent."
        }));
    }

    let cookies = build_cookies(ipb_member_id, ipb_pass_hash, star, igneous);
    match validate_cookies(&cookies) {
        Ok(()) => Ok(success_data(cookies, None)),
        Err(ValidationFailure::Invalid(error)) => Err(error),
        Err(ValidationFailure::Warning(warning)) => {
            HostBridge::log(2, &warning);
            Ok(success_data(cookies, Some(warning)))
        }
    }
}

fn success_data(cookies: Vec<LoginCookie>, warning: Option<String>) -> Value {
    let mut data = Map::new();
    data.insert("cookies".to_string(), json!(cookies));
    data.insert(
        "message".to_string(),
        Value::String("Successfully configured E-Hentai authentication cookies.".to_string()),
    );
    if let Some(warning) = warning {
        data.insert("warning".to_string(), Value::String(warning));
    }
    Value::Object(data)
}

fn build_cookies(
    ipb_member_id: &str,
    ipb_pass_hash: &str,
    star: &str,
    igneous: &str,
) -> Vec<LoginCookie> {
    let mut cookies = Vec::new();

    for domain in ["e-hentai.org", "exhentai.org"] {
        cookies.push(LoginCookie {
            name: "ipb_member_id".to_string(),
            value: ipb_member_id.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
        });
        cookies.push(LoginCookie {
            name: "ipb_pass_hash".to_string(),
            value: ipb_pass_hash.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
        });

        if !star.is_empty() {
            cookies.push(LoginCookie {
                name: "star".to_string(),
                value: star.to_string(),
                domain: domain.to_string(),
                path: "/".to_string(),
            });
        }

        if !igneous.is_empty() {
            cookies.push(LoginCookie {
                name: "igneous".to_string(),
                value: igneous.to_string(),
                domain: domain.to_string(),
                path: "/".to_string(),
            });
        }
    }

    cookies.push(LoginCookie {
        name: "ipb_coppa".to_string(),
        value: "0".to_string(),
        domain: "forums.e-hentai.org".to_string(),
        path: "/".to_string(),
    });
    cookies.push(LoginCookie {
        name: "nw".to_string(),
        value: "1".to_string(),
        domain: "exhentai.org".to_string(),
        path: "/".to_string(),
    });
    cookies.push(LoginCookie {
        name: "nw".to_string(),
        value: "1".to_string(),
        domain: "e-hentai.org".to_string(),
        path: "/".to_string(),
    });

    cookies
}

fn validate_cookies(cookies: &[LoginCookie]) -> Result<(), ValidationFailure> {
    let cookie_header = cookies
        .iter()
        .filter(|cookie| cookie.domain == "exhentai.org")
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ");

    let mut headers = Vec::new();
    headers.push(("User-Agent".to_string(), USER_AGENT.to_string()));
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header));
    }

    let response = http_get_text(EXHENTAI_URL, &headers).map_err(|err| {
        ValidationFailure::Warning(format!(
            "Could not validate cookies: {err}. Assuming they are correct."
        ))
    })?;

    if !(200..300).contains(&response.status) {
        return Err(ValidationFailure::Invalid(format!(
            "HTTP {}: Failed to access ExHentai",
            response.status
        )));
    }

    if response.body_text.contains(INVALID_LOGIN_MARKER) {
        return Err(ValidationFailure::Invalid(
            "Invalid E*Hentai login credentials.".to_string(),
        ));
    }

    Ok(())
}

fn read_string_param(params: &Value, name: &str) -> String {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
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
    });
    0
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) }
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
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
    Tls(Box<StreamOwned<ClientConnection, HostTcpStream>>),
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            HttpStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            HttpStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            HttpStream::Tls(s) => s.flush(),
        }
    }
}

struct HttpTextResponse {
    status: u16,
    body_text: String,
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
}

fn http_get_text(url: &str, headers: &[(String, String)]) -> Result<HttpTextResponse, String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let parsed = parse_url(&current)?;
        if !parsed.scheme.eq_ignore_ascii_case("https") {
            return Err(format!("unsupported URL scheme: {}", parsed.scheme));
        }

        let mut stream = connect_tls_stream(&parsed.host, parsed.port)?;
        let mut req = String::new();
        req.push_str(&format!("GET {} HTTP/1.1\r\n", parsed.path_and_query));
        if parsed.port == 443 {
            req.push_str(&format!("Host: {}\r\n", parsed.host));
        } else {
            req.push_str(&format!("Host: {}:{}\r\n", parsed.host, parsed.port));
        }
        req.push_str("Accept: */*\r\n");
        req.push_str("Accept-Encoding: identity\r\n");
        req.push_str("Connection: close\r\n");
        for (key, value) in headers {
            req.push_str(&format!("{key}: {value}\r\n"));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .and_then(|_| stream.flush())
            .map_err(|e| e.to_string())?;

        let (status, response_headers, body) = read_http_response(&mut stream)?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let Some(location) = header_value(&response_headers, "Location") else {
                return Ok(HttpTextResponse {
                    status,
                    body_text: String::from_utf8_lossy(&body).to_string(),
                });
            };
            current = resolve_redirect_url(&parsed, location)?;
            continue;
        }
        return Ok(HttpTextResponse {
            status,
            body_text: String::from_utf8_lossy(&body).to_string(),
        });
    }
    Err(format!("too many redirects while requesting {url}"))
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid URL: {url}"))?;
    let (authority, path_query) = if let Some((a, b)) = rest.split_once('/') {
        (a, format!("/{}", b))
    } else {
        (rest, "/".to_string())
    };
    if authority.is_empty() {
        return Err(format!("missing host in URL: {url}"));
    }
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(']') || h.contains('[') {
            (authority.to_string(), default_port_for_scheme(scheme)?)
        } else if p.chars().all(|c| c.is_ascii_digit()) {
            let parsed = p
                .parse::<u16>()
                .map_err(|_| format!("invalid port in URL: {url}"))?;
            (h.to_string(), parsed)
        } else {
            (authority.to_string(), default_port_for_scheme(scheme)?)
        }
    } else {
        (authority.to_string(), default_port_for_scheme(scheme)?)
    };
    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host,
        port,
        path_and_query: path_query,
    })
}

fn default_port_for_scheme(scheme: &str) -> Result<u16, String> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(443),
        "http" => Ok(80),
        _ => Err(format!("unsupported URL scheme: {scheme}")),
    }
}

fn resolve_redirect_url(base: &ParsedUrl, location: &str) -> Result<String, String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_string());
    }
    if location.starts_with("//") {
        return Ok(format!("{}:{}", base.scheme, location));
    }
    let origin = if (base.scheme.eq_ignore_ascii_case("https") && base.port == 443)
        || (base.scheme.eq_ignore_ascii_case("http") && base.port == 80)
    {
        format!("{}://{}", base.scheme, base.host)
    } else {
        format!("{}://{}:{}", base.scheme, base.host, base.port)
    };
    if location.starts_with('/') {
        return Ok(format!("{origin}{location}"));
    }
    let base_path = base.path_and_query.split('?').next().unwrap_or("/");
    let prefix = match base_path.rfind('/') {
        Some(0) | None => "/",
        Some(pos) => &base_path[..pos + 1],
    };
    Ok(format!("{origin}{prefix}{location}"))
}

fn connect_tls_stream(host: &str, port: u16) -> Result<HttpStream, String> {
    let tcp = if let Some((proxy_host, proxy_port)) = resolve_proxy_for_https() {
        let mut proxy_stream = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
        establish_proxy_connect_tunnel(&mut proxy_stream, host, port)?;
        proxy_stream
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
    };
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| format!("invalid dns name: {host}"))?;
    let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
    Ok(HttpStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
}

fn resolve_proxy_for_https() -> Option<(String, u16)> {
    let keys = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];
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

    let without_scheme = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };
    let authority = without_scheme.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit_once('@').map(|(_, rhs)| rhs).unwrap_or(authority);

    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let host = &host_port[1..end];
        if host.is_empty() {
            return None;
        }
        let remain = &host_port[end + 1..];
        let port = if let Some(raw_port) = remain.strip_prefix(':') {
            raw_port.parse::<u16>().ok()?
        } else {
            8080
        };
        return Some((host.to_string(), port));
    }

    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port = p.parse::<u16>().ok()?;
            return Some((h.to_string(), port));
        }
    }
    Some((host_port.to_string(), 8080))
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

fn read_http_response(stream: &mut HttpStream) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
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
    let (status, headers) = parse_response_headers(&buf[..header_end])?;
    let pending = buf[header_end + 4..].to_vec();
    let body = read_response_body(stream, &headers, pending)?;
    Ok((status, headers, body))
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
    mut pending: Vec<u8>,
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
            let mut remaining = total - take;
            while remaining > 0 {
                let mut buf = vec![0u8; remaining.min(16 * 1024)];
                let n = read_stream_chunk(stream, &mut buf, true)?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                remaining -= n;
            }
            return Ok(out);
        }
    }

    let mut out = Vec::new();
    if !pending.is_empty() {
        out.append(&mut pending);
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

fn is_chunked(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cookies_matches_expected_order() {
        let cookies = build_cookies("member", "hash", "star-cookie", "igneous-cookie");
        assert_eq!(cookies.len(), 11);
        assert_eq!(cookies[0].name, "ipb_member_id");
        assert_eq!(cookies[0].domain, "e-hentai.org");
        assert_eq!(cookies[1].name, "ipb_pass_hash");
        assert_eq!(cookies[2].name, "star");
        assert_eq!(cookies[3].name, "igneous");
        assert_eq!(cookies[4].domain, "exhentai.org");
        assert_eq!(cookies[10].domain, "e-hentai.org");
        assert_eq!(cookies[10].name, "nw");
    }

    #[test]
    fn do_login_without_required_cookies_returns_blank_configuration() {
        let payload = do_login("", "", "", "").unwrap();
        let data = payload.as_object().unwrap();
        assert_eq!(data.get("message").and_then(Value::as_str), Some("No cookies provided, returning blank UserAgent."));
        assert_eq!(
            data.get("cookies").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn parse_url_handles_default_https_path() {
        let parsed = parse_url("https://exhentai.org").unwrap();
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.host, "exhentai.org");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path_and_query, "/");
    }

    #[test]
    fn resolve_redirect_url_handles_relative_location() {
        let base = parse_url("https://exhentai.org/a/b?x=1").unwrap();
        let redirected = resolve_redirect_url(&base, "c").unwrap();
        assert_eq!(redirected, "https://exhentai.org/a/c");
    }

    #[test]
    fn validation_marker_is_detected() {
        let html = format!("<html>{INVALID_LOGIN_MARKER}</html>");
        assert!(html.contains(INVALID_LOGIN_MARKER));
    }
}
