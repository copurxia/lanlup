use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("xmeta-rs requires wasm32-wasip1 (target_os = \"wasi\")");

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
    #[serde(rename = "loginCookies", default)]
    login_cookies: Vec<LoginCookie>,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
        "name": "Twitter/X",
        "type": "metadata",
        "namespace": "xmeta",
        "login_from": "xlogin",
        "author": "lrr4cj",
        "version": "1.0",
        "description": "Fetches tweet text as description and adds basic source/author tags.",
        "parameters": [
            {"name": "merge_existing", "type": "bool", "desc": "Merge new tags with existing archive tags", "default_value": "1"},
            {"name": "prefix_id", "type": "bool", "desc": "Prefix title with tweetId", "default_value": "0"},
            {"name": "strip_newlines", "type": "bool", "desc": "Replace newlines with spaces in description", "default_value": "0"}
        ],
        "oneshot_arg": "X/Twitter status URL or tweetId",
        "cooldown": 1,
        "permissions": [
            "metadata.read_input",
            "net=x.com",
            "net=cdn.syndication.twimg.com",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Twitter.ts"
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    let _ = &input.plugin_type;
    let _ = &input.login_cookies;
    HostBridge::progress(5, "Initializing X metadata...");

    let mut metadata = ensure_metadata_object(input.metadata);
    let merge_existing = read_bool_param(&input.params, "merge_existing", true);
    let prefix_id = read_bool_param(&input.params, "prefix_id", false);
    let strip_newlines = read_bool_param(&input.params, "strip_newlines", false);

    let existing_tags = metadata_tags_to_csv(&metadata);
    let title = metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let tweet_id = extract_tweet_id(&input.oneshot_param)
        .or_else(|| extract_tweet_id_from_source_tag(&existing_tags))
        .or_else(|| extract_tweet_id_from_title(&title));
    let Some(tweet_id) = tweet_id else {
        return Err("No tweetId found. Provide oneshotParam as X/Twitter status URL/ID, or add a source:https://x.com/<user>/status/<id> tag.".to_string());
    };

    HostBridge::progress(30, "Fetching tweet metadata...");
    let tweet = fetch_tweet(&tweet_id)?;

    let text = tweet
        .get("text")
        .and_then(Value::as_str)
        .or_else(|| tweet.get("full_text").and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
        .to_string();

    let screen_name = tweet
        .get("user")
        .and_then(|v| v.get("screen_name"))
        .and_then(Value::as_str)
        .or_else(|| tweet.get("screen_name").and_then(Value::as_str))
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let display_name = tweet
        .get("user")
        .and_then(|v| v.get("name"))
        .and_then(Value::as_str)
        .or_else(|| tweet.get("name").and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
        .to_string();

    let source_url = format!("https://x.com/{}/status/{}", screen_name, tweet_id);

    let next_title = if prefix_id {
        format!("{} {}", tweet_id, title_or_fallback(&title, &text, &tweet_id)).trim().to_string()
    } else if title.trim().is_empty() {
        title_or_fallback(&title, &text, &tweet_id)
    } else {
        title
    };

    let mut desc = text;
    if strip_newlines {
        desc = desc
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
    }

    let mut fetched_tags = vec![source_url.clone()];
    if !screen_name.is_empty() && screen_name != "unknown" {
        fetched_tags.push(format!("artist:{screen_name}"));
    }
    if !display_name.is_empty() {
        fetched_tags.push(format!("x_name:{display_name}"));
    }
    let fetched_csv = fetched_tags.join(", ");
    let merged_tags = if merge_existing {
        merge_tags(&existing_tags, &fetched_csv)
    } else {
        dedupe_csv(&fetched_csv)
    };

    if !next_title.trim().is_empty() {
        metadata.insert("title".to_string(), Value::String(next_title));
    }
    if !desc.trim().is_empty() {
        metadata.insert("description".to_string(), Value::String(desc));
    }
    metadata.insert("tags".to_string(), metadata_tags_from_csv(&merged_tags));
    metadata.insert("source_url".to_string(), Value::String(source_url));
    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "Metadata fetched");
    Ok(Value::Object(metadata))
}

fn fetch_tweet(tweet_id: &str) -> Result<Map<String, Value>, String> {
    let token = tweet_id
        .bytes()
        .fold(17u64, |acc, b| acc.wrapping_mul(131).wrapping_add(b as u64));
    let url = format!(
        "https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&token={token}"
    );
    let headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "application/json, text/plain, */*".to_string()),
        ("Referer".to_string(), "https://x.com/".to_string()),
    ];
    let text = http_get_text_with_retry(&url, &headers)?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("Invalid tweet response JSON: {e}"))?;
    let Some(obj) = v.as_object() else {
        return Err("Invalid tweet response payload.".to_string());
    };
    if obj.is_empty() || obj.get("error").is_some() {
        return Err("Failed to fetch tweet metadata.".to_string());
    }
    Ok(obj.clone())
}

fn extract_tweet_id(input: &str) -> Option<String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return Some(clean.to_string());
    }
    let re = Regex::new(r"(?:x\.com|twitter\.com)/(?:[^/]+/status/|i/web/status/)(\d+)").ok()?;
    re.captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_tweet_id_from_source_tag(existing_tags: &str) -> Option<String> {
    let re = Regex::new(r"source:https?://(?:x\.com|twitter\.com)/(?:[^/]+/status/|i/web/status/)(\d+)").ok()?;
    re.captures(existing_tags)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_tweet_id_from_title(title: &str) -> Option<String> {
    let re = Regex::new(r"\b(\d{10,20})\b").ok()?;
    re.captures(title)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn title_or_fallback(current: &str, text: &str, tweet_id: &str) -> String {
    if !current.trim().is_empty() {
        return current.trim().to_string();
    }
    if !text.trim().is_empty() {
        let mut s = text.trim().replace('\n', " ");
        if s.len() > 120 {
            s.truncate(120);
        }
        return s;
    }
    format!("tweet {tweet_id}")
}

fn read_bool_param(params: &Value, name: &str, default: bool) -> bool {
    let Some(value) = params.get(name) else {
        return default;
    };
    match value {
        Value::Bool(v) => *v,
        Value::Number(v) => v.as_i64().unwrap_or(0) != 0,
        Value::String(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        _ => default,
    }
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    if let Value::Object(map) = value {
        return map;
    }
    Map::new()
}

fn metadata_tags_to_csv(metadata: &Map<String, Value>) -> String {
    let Some(tags) = metadata.get("tags") else {
        return String::new();
    };
    match tags {
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(s) => {
                        let v = s.trim();
                        if !v.is_empty() {
                            out.push(v.to_string());
                        }
                    }
                    Value::Object(o) => {
                        if let Some(name) = o.get("name").and_then(Value::as_str) {
                            let v = name.trim();
                            if !v.is_empty() {
                                out.push(v.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            dedupe_csv(&out.join(","))
        }
        Value::String(s) => dedupe_csv(s),
        _ => String::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    let tags = split_csv_tags(csv)
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    Value::Array(tags)
}

fn merge_tags(existing: &str, fetched: &str) -> String {
    let mut out = split_csv_tags(existing);
    out.extend(split_csv_tags(fetched));
    dedupe_csv(&out.join(","))
}

fn split_csv_tags(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn dedupe_csv(csv: &str) -> String {
    let mut out = Vec::<String>::new();
    for tag in split_csv_tags(csv) {
        if !out.iter().any(|v| v.eq_ignore_ascii_case(&tag)) {
            out.push(tag);
        }
    }
    out.join(", ")
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
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
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

fn http_get_text_with_retry(url: &str, headers: &[(String, String)]) -> Result<String, String> {
    let mut last_error = String::new();
    for _ in 0..3 {
        match http_get_text(url, headers) {
            Ok(resp) => {
                if (200..300).contains(&resp.status) {
                    return Ok(resp.body_text);
                }
                last_error = format!("HTTP {}", resp.status);
            }
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
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
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
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
        (a, format!("/{b}"))
    } else {
        (rest, "/".to_string())
    };
    if authority.is_empty() {
        return Err(format!("missing host in URL: {url}"));
    }
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) {
            (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("invalid port in URL: {url}"))?,
            )
        } else {
            (authority.to_string(), 443)
        }
    } else {
        (authority.to_string(), 443)
    };

    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host,
        port,
        path_and_query: path_query,
    })
}

fn resolve_redirect_url(base: &ParsedUrl, location: &str) -> Result<String, String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_string());
    }
    if location.starts_with("//") {
        return Ok(format!("{}:{}", base.scheme, location));
    }
    let origin = if base.port == 443 {
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
        let mut proxy = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
        establish_proxy_connect_tunnel(&mut proxy, host, port)?;
        proxy
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
    for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(raw) = std::env::var(key) {
            if let Some(v) = parse_proxy_endpoint(&raw) {
                return Some(v);
            }
        }
    }
    None
}

fn parse_proxy_endpoint(raw: &str) -> Option<(String, u16)> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((_, right)) = s.split_once("://") {
        s = right;
    }
    if let Some((left, _)) = s.split_once('/') {
        s = left;
    }
    if let Some((_, right)) = s.rsplit_once('@') {
        s = right;
    }
    if s.is_empty() {
        return None;
    }

    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = &s[1..end];
        let tail = &s[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>().ok().unwrap_or(8080)
        } else {
            8080
        };
        if host.is_empty() {
            return None;
        }
        return Some((host.to_string(), port));
    }

    if let Some((h, p)) = s.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return Some((h.to_string(), p.parse::<u16>().ok().unwrap_or(8080)));
        }
    }
    Some((s.to_string(), 8080))
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
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
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
    let _http = parts.next();
    let status = parts
        .next()
        .ok_or_else(|| format!("invalid status line: {status_line}"))?
        .parse::<u16>()
        .map_err(|_| format!("invalid status code: {status_line}"))?;

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
    if is_chunked_transfer_encoding(headers) {
        loop {
            if ends_with_chunked_terminal(&pending) {
                break;
            }
            let mut chunk = [0u8; 16 * 1024];
            let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            pending.extend_from_slice(&chunk[..n]);
        }
        return decode_chunked(&pending);
    }

    if let Some(v) = header_value(headers, "Content-Length") {
        let expected = v.trim().parse::<usize>().unwrap_or(0);
        while pending.len() < expected {
            let mut chunk = [0u8; 16 * 1024];
            let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            pending.extend_from_slice(&chunk[..n]);
        }
        pending.truncate(expected.min(pending.len()));
        return Ok(pending);
    }

    let mut out = pending;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn is_chunked_transfer_encoding(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn ends_with_chunked_terminal(buf: &[u8]) -> bool {
    buf.windows(5).any(|w| w == b"0\r\n\r\n")
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < input.len() {
        let line_end = find_crlf(input, i).ok_or_else(|| "invalid chunked body".to_string())?;
        let size_line = String::from_utf8_lossy(&input[i..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {size_hex}"))?;
        i = line_end + 2;
        if size == 0 {
            break;
        }
        if i + size > input.len() {
            return Err("chunk exceeds buffer".to_string());
        }
        out.extend_from_slice(&input[i..i + size]);
        i += size;
        if i + 2 <= input.len() && &input[i..i + 2] == b"\r\n" {
            i += 2;
        }
    }
    Ok(out)
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    if start >= buf.len() {
        return None;
    }
    buf[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("failed to resolve {host}:{port}"))
}
