use hmac::{Hmac, Mac};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
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
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
    #[serde(default)]
    action: String,
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "targetId", default)]
    target_id: String,
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

    fn select_index(
        title: &str,
        options: Vec<Value>,
        message: &str,
        default_index: i32,
        timeout_seconds: i32,
    ) -> Result<usize, String> {
        let value = Self::call("ui.select", json!({
            "title": title,
            "message": message,
            "default_index": default_index,
            "timeout_seconds": timeout_seconds,
            "options": options,
        }))?;
        let index = value.get("index").and_then(Value::as_i64)
            .ok_or_else(|| "ui.select returned missing index".to_string())?;
        usize::try_from(index).map_err(|_| "ui.select returned invalid index".to_string())
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

fn http_post_with_retry(
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    max_retries: usize,
) -> Result<HttpResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_request(url, "POST", headers, body) {
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

fn http_get_with_retry(
    url: &str,
    headers: &[(String, String)],
    max_retries: usize,
) -> Result<HttpResponse, String> {
    http_post_with_retry(url, headers, b"", max_retries)
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

    let mut req = String::new();
    req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    if has_default_port(scheme, port) {
        req.push_str(&format!("Host: {host}\r\n"));
    } else {
        req.push_str(&format!("Host: {host}:{port}\r\n"));
    }
    req.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    req.push_str("Accept: application/json,*/*\r\n");
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    for (name, value) in extra_headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("\r\n");

    let stream = connect_target_stream(scheme, host, port)?;
    let raw = if scheme == "https" {
        let request_bytes = [req.as_bytes(), body].concat();
        read_https_response(stream, host, &request_bytes)?
    } else {
        let mut plain_stream = stream;
        write_all_to_stream(&mut plain_stream, req.as_bytes())?;
        write_all_to_stream(&mut plain_stream, body)?;
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
        .as_millis();
    let pid = std::process::id();
    format!("{:08x}{:08x}{:08x}{:08x}", now as u32, pid, now.swap_bytes() as u32, pid.swap_bytes())
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
        ("version".to_string(), "v1.4.1".to_string()),
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

fn picacg_post(path: &str, auth: &PicacgAuthData, body: &Value) -> Result<(u16, String), String> {
    let base = base_url_from_auth(auth);
    let url = format!("{base}/{path}");
    let time = picacg_time();
    let nonce = generate_nonce();
    let token = if auth.token.is_empty() { None } else { Some(auth.token.as_str()) };
    let headers = picacg_headers("POST", path, token, &nonce, &time);
    let body_bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let response = http_post_with_retry(&url, &headers, &body_bytes, MAX_HTTP_RETRIES)?;
    let text = String::from_utf8_lossy(&response.body).to_string();
    Ok((response.status, text))
}

fn parse_comic_id_from_input(input: &PluginInput) -> Option<String> {
    let oneshot = input.oneshot_param.trim();
    if !oneshot.is_empty() {
        return Some(oneshot.to_string());
    }
    let title = input.metadata.get("title").and_then(Value::as_str).unwrap_or("").trim();
    if title.is_empty() { return None; }
    None
}

fn search_comic_by_title(title: &str, auth: &PicacgAuthData) -> Result<Option<String>, String> {
    HostBridge::log(1, &format!("picacgmeta searching by title: {title}"));
    let path = "comics/advanced-search?page=1";
    let body = json!({"keyword": title, "sort": "dd"});
    let (status, text) = picacg_post(path, auth, &body)?;
    if status != 200 {
        HostBridge::log(1, &format!("picacgmeta search returned HTTP {status}"));
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse search response: {e}"))?;
    let docs = parsed.get("data")
        .and_then(|d| d.get("comics"))
        .and_then(|c| c.get("docs"))
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new()).clone();

    if docs.is_empty() {
        return Ok(None);
    }
    if docs.len() == 1 {
        return Ok(docs[0].get("_id").and_then(Value::as_str).map(|s| s.to_string()));
    }

    let options: Vec<Value> = docs.iter().enumerate().map(|(i, c)| {
        let t = c.get("title").and_then(Value::as_str).unwrap_or("Untitled");
        let a = c.get("author").and_then(Value::as_str).unwrap_or("");
        let desc = if a.is_empty() { t.to_string() } else { format!("{t} (by {a})") };
        json!({
            "label": desc,
            "description": format!("候选 {}", i + 1)
        })
    }).collect();

    let selected = HostBridge::select_index(
        "Picacg 候选匹配",
        options,
        &format!("为 \"{title}\" 选择最合适的 Picacg 漫画"),
        0,
        120,
    )?;

    Ok(docs.get(selected)
        .or_else(|| docs.first())
        .and_then(|c| c.get("_id").and_then(Value::as_str).map(|s| s.to_string())))
}

fn fetch_comic_metadata(comic_id: &str, auth: &PicacgAuthData) -> Result<Value, String> {
    let path = format!("comics/{comic_id}");
    let (status, text) = picacg_get(&path, auth)?;
    if status == 401 {
        return Err("Picacg API authentication was rejected (HTTP 401). Please rerun picacglogin.".to_string());
    }
    if status == 404 {
        return Err(format!("Comic not found: {comic_id}"));
    }
    if status != 200 {
        return Err(format!("Failed to fetch comic metadata: HTTP {status}"));
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse comic metadata: {e}"))?;
    Ok(parsed.get("data").and_then(|d| d.get("comic")).cloned().unwrap_or(Value::Null))
}

fn build_metadata_from_comic(comic: &Value, comic_id: &str) -> Map<String, Value> {
    let mut metadata = Map::new();

    let title = comic.get("title").and_then(Value::as_str).unwrap_or("Untitled").trim();
    if !title.is_empty() {
        metadata.insert("title".to_string(), Value::String(title.to_string()));
    }

    let mut tags = Vec::new();
    if let Some(author) = comic.get("author").and_then(Value::as_str) {
        if !author.trim().is_empty() {
            tags.push(Value::String(format!("artist:{}", author.trim())));
        }
    }
    if let Some(team) = comic.get("chineseTeam").and_then(Value::as_str) {
        if !team.trim().is_empty() {
            tags.push(Value::String(format!("group:{}", team.trim())));
        }
    }
    if let Some(categories) = comic.get("categories").and_then(Value::as_array) {
        for cat in categories {
            if let Some(s) = cat.as_str() {
                if !s.trim().is_empty() {
                    tags.push(Value::String(format!("category:{}", s.trim())));
                }
            }
        }
    }
    if let Some(comic_tags) = comic.get("tags").and_then(Value::as_array) {
        for tag in comic_tags {
            if let Some(s) = tag.as_str() {
                if !s.trim().is_empty() {
                    tags.push(Value::String(format!("tag:{}", s.trim())));
                }
            }
        }
    }
    tags.push(Value::String(format!("source:picacg://{comic_id}")));
    metadata.insert("tags".to_string(), Value::Array(tags));

    let description = comic.get("description").and_then(Value::as_str).unwrap_or("").trim();
    if !description.is_empty() {
        metadata.insert("description".to_string(), Value::String(description.to_string()));
    }

    if let Some(updated) = comic.get("updated_at").and_then(Value::as_str) {
        if !updated.trim().is_empty() {
            metadata.insert("updated_at".to_string(), Value::String(updated.trim().to_string()));
        }
    }

    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    metadata
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

    let payload = if input.action.trim() == "resolve_cover" {
        resolve_cover_action(&input)
    } else if input.action.trim() == "resolve_metadata"
        && normalize_target_type(&input.target_type, &input.params) == "source"
    {
        resolve_source_metadata(&input)
    } else {
        build_result_payload(input)
    };
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
        "name": "Picacg",
        "type": "metadata",
        "namespace": "picacgmeta",
        "pre": ["picacglogin"],
        "source_id_regex": "^source:picacgsource:.*$",
        "author": "Lanlu",
        "version": "1.0",
        "description": "Fetch metadata from Picacg (哔咔漫画) for your archive.",
        "parameters": [
            {
                "name": "additionaltags",
                "type": "bool",
                "desc": "Fetch updated_at timestamp",
                "default_value": "0"
            }
        ],
        "oneshot_arg": "Picacg Comic ID (Will attach tags matching this exact comic to your archive)",
        "cooldown": 2,
        "permissions": [
            "metadata.read_input",
            "net=picaapi.picacomic.com",
            "ui.select",
            "tcp.connect",
            "log.write",
            "progress.report",
            "task_kv.read",
            "asset.install_from_file"
        ]
    })
}

fn resolve_cover_action(input: &PluginInput) -> Value {
    let asset_id = input.extra_params.get("asset_id").and_then(Value::as_i64).unwrap_or(0);
    if asset_id <= 0 { return json!({"success": false, "error": "missing asset_id"}); }
    json!({"success": false, "error": "resolve_cover not yet implemented"})
}

fn normalize_target_type(raw: &str, params: &Value) -> String {
    let from_input = raw.trim().to_ascii_lowercase();
    if !from_input.is_empty() { return from_input; }
    params.get("__target_type").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase()
}

/// 解析 source 元数据：从 sourceId（source:picacgsource:{comic_id}）解析
fn resolve_source_metadata(input: &PluginInput) -> Value {
    HostBridge::progress(5, "解析 sourceId...");
    let target_id = input.target_id.trim();
    let comic_id = match target_id.strip_prefix("source:picacgsource:") {
        Some(id) if !id.is_empty() => id.trim().to_string(),
        _ => return json!({"success": false, "error": format!("invalid sourceId: {target_id}")}),
    };

    let auth = match load_picacg_auth() {
        Ok(v) => v,
        Err(e) => return json!({"success": false, "error": e}),
    };

    HostBridge::progress(30, &format!("获取漫画 {} 元数据...", comic_id));
    let comic = match fetch_comic_metadata(&comic_id, &auth) {
        Ok(v) => v,
        Err(e) => return json!({"success": false, "error": e}),
    };

    let title = comic.get("title").and_then(Value::as_str).unwrap_or("").to_string();
    let author = comic.get("author").and_then(Value::as_str).unwrap_or("").to_string();
    let description = comic.get("description").and_then(Value::as_str).unwrap_or("").to_string();
    let cover_path = comic.get("cover").and_then(|c| c.get("path")).and_then(Value::as_str).unwrap_or("").to_string();
    let mut tags = Vec::new();
    if let Some(cats) = comic.get("categories").and_then(Value::as_array) {
        for c in cats {
            if let Some(s) = c.as_str() {
                tags.push(Value::String(format!("category:{s}")));
            }
        }
    }
    if !author.is_empty() { tags.push(Value::String(format!("author:{author}"))); }

    // 获取章节列表
    HostBridge::progress(50, "获取章节列表...");
    let eps_path = format!("comics/{comic_id}/eps?page=1");
    let (status, eps_text) = match picacg_get(&eps_path, &auth) {
        Ok(v) => v,
        Err(e) => return json!({"success": false, "error": format!("eps fetch: {e}")}),
    };
    if status != 200 {
        return json!({"success": false, "error": format!("eps HTTP {status}")});
    }

    let parsed: Value = match serde_json::from_str(&eps_text) {
        Ok(v) => v,
        Err(e) => return json!({"success": false, "error": format!("eps JSON: {e}")}),
    };
    let eps = parsed.get("data").and_then(|d| d.get("eps")).and_then(|e| e.get("docs"))
        .and_then(Value::as_array).cloned().unwrap_or_default();

    let cover_url = if !cover_path.is_empty() {
        format!("https://picaapi.picacomic.com{}", cover_path)
    } else { String::new() };

    if !eps.is_empty() {
        // 有多话 → archive children
        let children: Vec<Value> = eps.iter().enumerate().map(|(idx, e)| {
            let ep_title = e.get("title").and_then(Value::as_str).unwrap_or("").to_string();
            let ep_order = e.get("order").and_then(Value::as_i64).unwrap_or((idx + 1) as i64);
            json!({
                "entity_type": "archive",
                "entity_id": format!("source:picacgsource:{}:ep{}", comic_id, ep_order),
                "title": if ep_title.is_empty() { format!("第{}話", idx + 1) } else { ep_title },
                "sort_order": ep_order,
            })
        }).collect();

        let mut data = json!({
            "title": title,
            "description": description,
            "tags": Value::Array(tags),
            "children": children,
        });
        if !cover_url.is_empty() { data["cover"] = json!(cover_url); }
        HostBridge::progress(100, "元数据获取完成");
        json!({"success": true, "data": data})
    } else {
        // 无多话 → page children（comic 本身就是单话）
        let pages_path = format!("comics/{comic_id}/order/1/pages?page=1");
        let (p_status, p_text) = match picacg_get(&pages_path, &auth) {
            Ok(v) => v,
            Err(e) => return json!({"success": false, "error": format!("pages fetch: {e}")}),
        };
        if p_status != 200 {
            return json!({"success": false, "error": format!("pages HTTP {p_status}")});
        }
        let p_parsed: Value = match serde_json::from_str(&p_text) {
            Ok(v) => v,
            Err(e) => return json!({"success": false, "error": format!("pages JSON: {e}")}),
        };
        let total_pages = p_parsed.get("data")
            .and_then(|d| d.get("pages")).and_then(|p| p.get("pages"))
            .and_then(Value::as_i64).unwrap_or(0);

        let children: Vec<Value> = (1..=total_pages).map(|pn| {
            json!({
                "entity_type": "page",
                "entity_id": format!("source:picacgsource:{}#page:{}", comic_id, pn),
                "title": "",
                "sort_order": pn,
                "path": format!("{}/{}", comic_id, pn),
                "media_type": "image",
            })
        }).collect();

        let mut data = json!({
            "title": title,
            "description": description,
            "tags": Value::Array(tags),
            "children": children,
        });
        if !cover_url.is_empty() { data["cover"] = json!(cover_url); }
        HostBridge::progress(100, "元数据获取完成");
        json!({"success": true, "data": data})
    }
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    let _ = &input.plugin_type;
    HostBridge::progress(5, "初始化 Picacg 元数据抓取...");
    let auth = load_picacg_auth()?;

    let comic_id = match parse_comic_id_from_input(&input) {
        Some(id) => id,
        None => {
            let title = input.metadata.get("title").and_then(Value::as_str).unwrap_or("").trim();
            if title.is_empty() {
                return Err("No Picacg comic ID provided and no title found in metadata.".to_string());
            }
            match search_comic_by_title(title, &auth)? {
                Some(id) => id,
                None => return Err(format!("No matching Picacg comic found for title: {title}")),
            }
        }
    };

    HostBridge::log(1, &format!("picacgmeta resolved comic_id={comic_id}"));
    HostBridge::progress(30, &format!("获取漫画 {comic_id} 元数据..."));

    let comic = fetch_comic_metadata(&comic_id, &auth)?;
    let mut metadata = build_metadata_from_comic(&comic, &comic_id);

    if read_bool_param(&input.params, "additionaltags", false) {
        if let Some(likes) = comic.get("likesCount").and_then(|v| v.as_u64()) {
            metadata.insert("likes_count".to_string(), Value::Number(serde_json::Number::from(likes)));
        }
    }

    HostBridge::progress(100, "元数据获取完成");
    Ok(Value::Object(metadata))
}

fn read_bool_param(params: &Value, name: &str, default: bool) -> bool {
    let Some(value) = params.get(name) else { return default; };
    match value {
        Value::Bool(v) => *v,
        Value::Number(v) => v.as_i64().unwrap_or(0) != 0,
        Value::String(v) => {
            let s = v.trim().to_ascii_lowercase();
            !(s.is_empty() || s == "0" || s == "false" || s == "no" || s == "off")
        }
        _ => default,
    }
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
