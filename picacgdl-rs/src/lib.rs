use hmac::{Hmac, Mac};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
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
const AUTH_DATA_KEY: &str = "__lanlu.phase.picacglogin.data";
const MAX_HTTP_RETRIES: usize = 3;
const PICACG_API_KEY: &str = "C69BAF41DA5ABD1FFEDC6D2FEA56B";
const PICACG_SIGNATURE_KEY: &str = r#"~d}$Q7$eIni=V)9\RK/P.RM4;9[7|@/CA}b~OW!3?EV`:<>M7pddUBL5n|0/*Cn"#;
const DEFAULT_BASE_URL: &str = "https://picaapi.picacomic.com";

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

#[derive(Debug, Deserialize, Default)]
struct PicacgAuthData {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    base_url: String,
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
        let req = json!({"method": method, "params": params});
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 { return Err(Self::read_error()); }
        Self::read_response()
    }

    fn read_response() -> Result<Value, String> {
        let len = unsafe { host_response_len() };
        if len < 0 { return Err("host_response_len returned negative length".to_string()); }
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stream.read(buf) }
}

#[cfg(target_arch = "wasm32")]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.stream.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
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

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_get_with_retry(
    url: &str,
    extra_headers: &[(String, String)],
    max_retries: usize,
) -> Result<HttpResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_request(url, "GET", extra_headers, b"") {
            Ok(response) => {
                if response.status == 429 {
                    let wait_ms = retry_after_millis(&response.headers)
                        .unwrap_or_else(|| 1_000u64.saturating_mul(attempt as u64 + 1));
                    if attempt >= max_retries {
                        return Err(format!("HTTP 429 for {url}. Retry later."));
                    }
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
                if attempt >= max_retries || !is_retryable_network_error(&err) {
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

fn http_request(
    url: &str,
    method: &str,
    extra_headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let response = http_request_once(&current_url, method, extra_headers, body)?;
        if is_redirect_status(response.status) {
            let location = find_header_value(&response.headers, "location")
                .ok_or_else(|| format!("redirect {} without Location", response.status))?;
            let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
            let next = base.join(location).map_err(|e| e.to_string())?;
            current_url = next.to_string();
            continue;
        }
        return Ok(response);
    }
    Err("too many redirects".to_string())
}

fn http_request_once(
    url: &str,
    method: &str,
    extra_headers: &[(String, String)],
    body: &[u8],
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

    let has_custom_host = extra_headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
    let has_custom_user_agent = extra_headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("user-agent"));
    let has_custom_accept = extra_headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("accept"));
    let has_custom_connection = extra_headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("connection"));

    let mut req = String::new();
    req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    if !has_custom_host {
        if has_default_port(scheme, port) {
            req.push_str(&format!("Host: {host}\r\n"));
        } else {
            req.push_str(&format!("Host: {host}:{port}\r\n"));
        }
    }
    if !has_custom_user_agent {
        req.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    }
    if !has_custom_accept {
        req.push_str("Accept: */*\r\n");
    }
    req.push_str("Accept-Encoding: identity\r\n");
    if !has_custom_connection {
        req.push_str("Connection: close\r\n");
    }
    for (name, value) in extra_headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    let stream = connect_target_stream(scheme, host, port)?;
    let raw = if scheme == "https" {
        let request_bytes = [req.as_bytes(), body].concat();
        read_https_response(stream, host, &request_bytes)?
    } else {
        let mut plain_stream = stream;
        write_all_to_stream(&mut plain_stream, req.as_bytes())?;
        if !body.is_empty() {
            write_all_to_stream(&mut plain_stream, body)?;
        }
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
    if trimmed.is_empty() { return None; }
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
                .split("\r\n").next().unwrap_or_default().to_string();
            let status = status_line.split_whitespace().nth(1)
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| format!("invalid proxy CONNECT status line: {status_line}"))?;
            if !(200..300).contains(&status) {
                return Err(format!("proxy CONNECT failed: HTTP {status}"));
            }
            return Ok(());
        }
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { return Err("proxy closed before CONNECT response".to_string()); }
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
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn retry_after_millis(headers: &[(String, String)]) -> Option<u64> {
    find_header_value(headers, "retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 500 | 502 | 503 | 504)
}

fn is_retryable_network_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("resource temporarily unavailable")
        || lower.contains("would block")
        || lower.contains("timed out")
        || lower.contains("interrupted")
        || lower.contains("tls close_notify")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
}

fn has_default_port(scheme: &str, port: u16) -> bool {
    (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port).to_socket_addrs().map_err(|e| e.to_string())?
        .next().ok_or_else(|| format!("failed to resolve {host}:{port}"))
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for byte in data {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn generate_nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}{:08x}{:08x}{:08x}", now as u32, count as u32, now.swap_bytes() as u32, count.swap_bytes() as u32)
}

fn picacg_signature(path: &str, nonce: &str, time: &str, method: &str) -> String {
    let data = format!("{path}{time}{nonce}{method}{PICACG_API_KEY}").to_lowercase();
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(PICACG_SIGNATURE_KEY.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex_encode(&result.into_bytes())
}

fn picacg_headers(method: &str, path: &str, token: Option<&str>, nonce: &str, time: &str) -> Vec<(String, String)> {
    let signature = picacg_signature(path, nonce, time, method);
    let mut headers = vec![
        ("api-key".to_string(), PICACG_API_KEY.to_string()),
        ("accept".to_string(), "application/vnd.picacomic.com.v1+json".to_string()),
        ("app-channel".to_string(), "3".to_string()),
        ("time".to_string(), time.to_string()),
        ("nonce".to_string(), nonce.to_string()),
        ("app-version".to_string(), "2.2.1.3.3.4".to_string()),
        ("app-uuid".to_string(), "defaultUuid".to_string()),
        ("image-quality".to_string(), "original".to_string()),
        ("app-platform".to_string(), "android".to_string()),
        ("app-build-version".to_string(), "45".to_string()),
        ("Content-Type".to_string(), "application/json; charset=UTF-8".to_string()),
        ("user-agent".to_string(), "okhttp/3.8.1".to_string()),
        ("version".to_string(), "v1.5.4".to_string()),
        ("Host".to_string(), "picaapi.picacomic.com".to_string()),
        ("signature".to_string(), signature),
    ];
    if let Some(t) = token {
        headers.push(("authorization".to_string(), t.to_string()));
    }
    headers
}

fn picacg_time() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn load_picacg_auth() -> Result<PicacgAuthData, String> {
    let Some(value) = HostBridge::task_kv_get(AUTH_DATA_KEY)? else {
        return Err("Missing Picacg auth data in task KV. Ensure picacglogin ran as a pre hook.".to_string());
    };
    serde_json::from_value(value).map_err(|e| format!("Invalid Picacg auth data in task KV: {e}"))
}

fn base_url_from_auth(auth: &PicacgAuthData) -> String {
    let trimmed = auth.base_url.trim();
    if trimmed.is_empty() { DEFAULT_BASE_URL.to_string() } else { trimmed.to_string() }
}

fn picacg_get(path: &str, auth: &PicacgAuthData) -> Result<(u16, String), String> {
    let base = base_url_from_auth(auth);
    let url = format!("{base}/{path}");
    let time = picacg_time();
    let nonce = generate_nonce();
    let token = if auth.token.is_empty() { None } else { Some(auth.token.as_str()) };
    let headers = picacg_headers("GET", path, token, &nonce, &time);
    let response = http_get_with_retry(&url, &headers, MAX_HTTP_RETRIES)?;
    let text = String::from_utf8_lossy(&response.body).to_string();
    Ok((response.status, text))
}

fn extract_comic_id(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.starts_with("picacg://") {
        let id = &trimmed[9..];
        if !id.is_empty() { return Some(id.to_string()); }
    }
    if trimmed.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') && !trimmed.is_empty() {
        return Some(trimmed.to_string());
    }
    None
}

fn fetch_comic_info(comic_id: &str, auth: &PicacgAuthData) -> Result<Value, String> {
    let path = format!("comics/{comic_id}");
    let (status, text) = picacg_get(&path, auth)?;
    if status == 401 {
        return Err("Picacg API authentication was rejected (HTTP 401). Please rerun picacglogin.".to_string());
    }
    if status == 404 {
        return Err(format!("Comic not found: {comic_id}"));
    }
    if status != 200 {
        return Err(format!("Failed to fetch comic info: HTTP {status}"));
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse comic info: {e}"))?;
    Ok(parsed.get("data").and_then(|d| d.get("comic")).cloned().unwrap_or(Value::Null))
}

fn fetch_all_eps(comic_id: &str, auth: &PicacgAuthData) -> Result<Vec<Value>, String> {
    let mut all_eps = Vec::new();
    let mut page = 1u32;
    loop {
        let path = format!("comics/{comic_id}/eps?page={page}");
        let (status, text) = picacg_get(&path, auth)?;
        if status != 200 {
            return Err(format!("Failed to fetch episodes page {page}: HTTP {status}"));
        }
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse episodes response: {e}"))?;
        let docs = parsed.get("data")
            .and_then(|d| d.get("eps"))
            .and_then(|e| e.get("docs"))
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new()).clone();
        let total_pages = parsed.get("data")
            .and_then(|d| d.get("eps"))
            .and_then(|e| e.get("pages"))
            .and_then(|p| p.as_u64()).unwrap_or(1) as u32;
        all_eps.extend(docs);
        if page >= total_pages { break; }
        page += 1;
    }
    all_eps.sort_by(|a, b| {
        let ao = a.get("order").and_then(|v| v.as_i64()).unwrap_or(0);
        let bo = b.get("order").and_then(|v| v.as_i64()).unwrap_or(0);
        ao.cmp(&bo)
    });
    Ok(all_eps)
}

fn fetch_ep_pages(comic_id: &str, ep_order: i64, auth: &PicacgAuthData) -> Result<Vec<String>, String> {
    let mut images = Vec::new();
    let mut page = 1u32;
    loop {
        let path = format!("comics/{comic_id}/order/{ep_order}/pages?page={page}");
        let (status, text) = picacg_get(&path, auth)?;
        if status != 200 {
            return Err(format!("Failed to fetch pages for ep {ep_order} page {page}: HTTP {status}"));
        }
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse pages response: {e}"))?;
        let docs = parsed.get("data")
            .and_then(|d| d.get("pages"))
            .and_then(|p| p.get("docs"))
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new()).clone();
        let total_pages = parsed.get("data")
            .and_then(|d| d.get("pages"))
            .and_then(|p| p.get("pages"))
            .and_then(|p| p.as_u64()).unwrap_or(1) as u32;
        for doc in docs {
            if let Some(url) = build_image_url(&doc) {
                images.push(url);
            }
        }
        if page >= total_pages { break; }
        page += 1;
    }
    Ok(images)
}

fn build_image_url(page_doc: &Value) -> Option<String> {
    let media = page_doc.get("media")?;
    let file_server = media.get("fileServer").and_then(Value::as_str)?;
    let path = media.get("path").and_then(Value::as_str)?;
    let server = file_server.trim_end_matches('/');
    let p = path.trim_start_matches('/');
    Some(format!("{server}/static/{p}"))
}

fn download_image(url: &str, output: &PathBuf) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let headers = vec![
        ("Referer".to_string(), "https://picaapi.picacomic.com/".to_string()),
        ("User-Agent".to_string(), "okhttp/3.8.1".to_string()),
        ("Accept".to_string(), "image/*,*/*".to_string()),
    ];
    let response = http_get_with_retry(url, &headers, MAX_HTTP_RETRIES)?;
    if response.status >= 400 {
        return Err(format!("HTTP {}", response.status));
    }
    if response.body.is_empty() {
        return Err("empty response body".to_string());
    }
    let mut file = File::create(output).map_err(|e| e.to_string())?;
    file.write_all(&response.body).map_err(|e| e.to_string())?;
    Ok(())
}

fn sanitize_filename(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch == '<' || ch == '>' || ch == ':' || ch == '"' || ch == '/' || ch == '\\' || ch == '|' || ch == '?' || ch == '*' || ch == '[' || ch == ']' || ch == '「' || ch == '」' {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() { return "Comic".to_string(); }
    trimmed.chars().take(80).collect()
}

fn image_filename_from_url(url: &str, index: usize) -> String {
    let path = url.trim().trim_end_matches('/');
    let name = path.rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        return format!("{index}.jpg");
    }
    // Ensure extension exists
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.jpg")
    }
}

fn resolve_plugin_dir(raw: &str, ns: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return format!("./data/cache/plugins/{ns}");
    }
    trimmed.to_string()
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
    let _ = &input.plugin_type;

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

fn run_download(input: &PluginInput) -> Value {
    let comic_id = match extract_comic_id(&input.url) {
        Some(v) => v,
        None => return output_err("Invalid Picacg URL. Use picacg://<comic_id>"),
    };

    let auth = match load_picacg_auth() {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    HostBridge::progress(1, "Fetching comic info...");
    let info = match fetch_comic_info(&comic_id, &auth) {
        Ok(v) => v,
        Err(e) => return output_err(&format!("Failed to fetch comic info: {e}")),
    };
    let title = info.get("title").and_then(Value::as_str).unwrap_or("Untitled").trim();
    let safe_title = sanitize_filename(title);
    let folder_name = format!("{} {}", comic_id, safe_title);
    let plugin_base = resolve_plugin_dir(&input.plugin_dir, "picacg");
    let plugin_dir = format!("{plugin_base}/{folder_name}");
    if let Err(e) = fs::create_dir_all(&plugin_dir) {
        return output_err(&format!("Failed to prepare plugin dir: {e}"));
    }

    HostBridge::progress(5, "Fetching episodes...");
    let eps = match fetch_all_eps(&comic_id, &auth) {
        Ok(v) => v,
        Err(e) => {
            HostBridge::log(1, &format!("picacgdl failed to fetch episodes: {e}"));
            Vec::new()
        }
    };

    if eps.is_empty() {
        return output_err(&format!("No episodes found for comic: {comic_id}"));
    }

    let total_pages_estimate = info.get("pagesCount").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let mut downloaded_count = 0usize;
    let mut failed_count = 0usize;
    let mut processed_images = 0usize;

    let total_eps = eps.len();
    for (ep_idx, ep) in eps.iter().enumerate() {
        let ep_order = ep.get("order").and_then(|v| v.as_i64()).unwrap_or((ep_idx + 1) as i64);
        let ep_title = ep.get("title").and_then(Value::as_str).unwrap_or("");
        HostBridge::log(1, &format!("picacgdl downloading ep={ep_order} title={ep_title}"));

        let images = match fetch_ep_pages(&comic_id, ep_order, &auth) {
            Ok(v) => v,
            Err(e) => {
                HostBridge::log(1, &format!("picacgdl failed to fetch pages for ep {ep_order}: {e}"));
                continue;
            }
        };

        let ep_folder = if total_eps == 1 {
            plugin_dir.clone()
        } else {
            let ep_safe = sanitize_filename(ep_title);
            let ep_dir = format!("{plugin_dir}/{ep_order} {ep_safe}");
            if let Err(e) = fs::create_dir_all(&ep_dir) {
                HostBridge::log(1, &format!("picacgdl failed to create ep dir: {e}"));
                continue;
            }
            ep_dir
        };

        for (img_idx, image_url) in images.iter().enumerate() {
            let global_idx = processed_images + img_idx + 1;
            let file_name = image_filename_from_url(image_url, global_idx);
            let mut local_path = PathBuf::from(&ep_folder);
            local_path.push(file_name);

            match download_image(image_url, &local_path) {
                Ok(()) => downloaded_count += 1,
                Err(err) => {
                    failed_count += 1;
                    HostBridge::log(1, &format!("picacgdl image download failed ep={ep_order} idx={img_idx} url={image_url} error={err}"));
                }
            }

            let total = total_pages_estimate.max(1);
            let percent = ((global_idx * 100) / total.max(global_idx)).clamp(1, 99) as i32;
            HostBridge::progress(percent, &format!("Downloading page {global_idx}/{}...", total));
        }
        processed_images += images.len();
    }

    let partial = if total_pages_estimate > 0 {
        downloaded_count != total_pages_estimate
    } else {
        failed_count > 0
    };

    HostBridge::progress(100, &format!("Download complete: {} succeeded, {} failed, expected {}", downloaded_count, failed_count, total_pages_estimate));

    if downloaded_count == 0 {
        return output_err(&format!("No images were downloaded for comic: {comic_id}"));
    }

    json!({
        "success": true,
        "data": [{
            "plugin_relative_path": folder_name,
            "relative_path": folder_name,
            "filename": folder_name,
            "source": format!("picacg://{comic_id}"),
            "downloaded_count": downloaded_count,
            "failed_count": failed_count,
            "expected_count": total_pages_estimate,
            "partial": partial,
            "archive_type": "folder"
        }]
    })
}

/// resolve_page_asset action：path 形态（按宽窄兼容）：
/// - 新形态: "{comic_id}/{ep_order}/{page_num}"   ← 三段，对齐 metadata 插件 page child 的 path
/// - 旧形态: "{comic_id}/{page_num}"               ← 两段，ep_order 缺省取第一话
///
/// 不再写死「取第一话」——ep_order 直接从 path 取,与 picacg-qt 的
/// `GetComicsBookOrderReq(bookId, epsId=order, page)` 三参数定位一致。
fn resolve_page_asset(input: &PluginInput) -> Vec<u8> {
    let path = input.path.trim();
    if path.is_empty() {
        return build_binary_response(&output_err("path is required"), &[]);
    }
    let parts: Vec<&str> = path.split('/').collect();

    // 兼容旧的两段 path: "{comic_id}/{page_num}" → ep_order 默认为 1
    let (comic_id, ep_order, page_num): (&str, i64, usize) = if parts.len() >= 3 {
        let cid = parts[0];
        let order: i64 = match parts[1].parse() {
            Ok(o) if o >= 1 => o,
            _ => return build_binary_response(&output_err(&format!("invalid ep_order in path: {path}")), &[]),
        };
        let pn: usize = match parts[2].parse() {
            Ok(n) if n >= 1 => n,
            _ => return build_binary_response(&output_err(&format!("invalid page: {path}")), &[]),
        };
        (cid, order, pn)
    } else if parts.len() == 2 {
        let cid = parts[0];
        let pn: usize = match parts[1].parse() {
            Ok(n) if n >= 1 => n,
            _ => return build_binary_response(&output_err(&format!("invalid page: {path}")), &[]),
        };
        (cid, 1i64, pn)
    } else {
        return build_binary_response(&output_err(&format!("invalid path: {path}")), &[]);
    };

    let auth = match load_picacg_auth() {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&e), &[]),
    };

    // ep_order 已由 path 给出,无需再请求 eps 列表去取第一话。
    let pages_path = format!("comics/{comic_id}/order/{ep_order}/pages?page={}", (page_num - 1) / 50 + 1);
    let (p_status, p_text) = match picacg_get(&pages_path, &auth) {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&format!("pages: {e}")), &[]),
    };
    if p_status != 200 {
        return build_binary_response(&output_err(&format!("pages HTTP {p_status}")), &[]);
    }
    let p_parsed: Value = match serde_json::from_str(&p_text) {
        Ok(v) => v,
        Err(e) => return build_binary_response(&output_err(&format!("pages JSON: {e}")), &[]),
    };
    let docs = p_parsed.get("data").and_then(|d| d.get("pages"))
        .and_then(|p| p.get("docs")).and_then(Value::as_array)
        .cloned().unwrap_or_default();

    let page_idx_in_doc = ((page_num - 1) % 50) as usize;
    let page_doc = docs.get(page_idx_in_doc);
    let image_url = match page_doc.and_then(|d| build_image_url(d)) {
        Some(url) => url,
        None => return build_binary_response(&output_err("failed to build image URL"), &[]),
    };

    let img_headers = vec![
        ("Referer".to_string(), "https://picaapi.picacomic.com/".to_string()),
        ("User-Agent".to_string(), USER_AGENT.to_string()),
    ];
    let img_resp = match http_get_with_retry(&image_url, &img_headers, 3) {
        Ok(r) => r,
        Err(e) => return build_binary_response(&output_err(&format!("image download: {e}")), &[]),
    };
    if img_resp.status != 200 {
        return build_binary_response(&output_err(&format!("image HTTP {}", img_resp.status)), &[]);
    }

    let ext = image_url.rsplit('.').next().unwrap_or("jpg").to_string();
    let content_type = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        _ => "application/octet-stream",
    };
    build_binary_response(&json!({"success": true, "content_type": content_type}), &img_resp.body)
}

/// download_archive action：从 targetId 解析 comic_id，复用整本下载流程
fn download_archive_action(input: &PluginInput) -> Value {
    let target_id = input.target_id.trim();
    let comic_id = match target_id.strip_prefix("source:picacgsource:") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return output_err(&format!("invalid sourceId: {target_id}")),
    };
    let fake_url = format!("picacg://{comic_id}");
    let fake_input = PluginInput {
        plugin_type: input.plugin_type.clone(),
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

fn output_err(message: &str) -> Value {
    json!({"success": false, "error": message})
}

fn plugin_info_json() -> Value {
    json!({
        "name": "Picacg Downloader (Rust)",
        "type": "download",
        "namespace": "picacg",
        "pre": ["picacglogin"],
        "source_id_regex": "^source:picacgsource:.*$",
        "author": "Lanlu",
        "version": "0.1.0",
        "description": "Rust/WASM Picacg downloader using the Picacg API.",
        "parameters": [],
        "url_regex": "picacg://[a-zA-Z0-9_-]+",
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
    HostBridge::log(2, &message);
    STATE.with(|state| state.borrow_mut().error = message.into_bytes());
    0
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 { &[] } else { slice::from_raw_parts(ptr as *const u8, len as usize) }
}
