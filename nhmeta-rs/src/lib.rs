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
use time::macros::format_description;
use time::OffsetDateTime;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("nhmeta-rs requires wasm32-wasip1 (target_os = \"wasi\")");

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
        "name": "nHentai",
        "type": "metadata",
        "namespace": "nhmeta",
        "login_from": "nhlogin",
        "author": "Difegue and others (ported)",
        "version": "1.1",
        "description": "Searches nHentai for tags matching your archive.",
        "parameters": [
            {
                "name": "additionaltags",
                "type": "bool",
                "desc": "Fetch upload_date and set metadata.updated_at (UTC timestamp string)",
                "default_value": "0"
            }
        ],
        "oneshot_arg": "nHentai Gallery URL or ID (Will attach tags matching this exact gallery to your archive)",
        "cooldown": 2,
        "permissions": [
            "metadata.read_input",
            "net=nhentai.net",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/NHentai.ts"
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
    HostBridge::progress(5, "初始化 nHentai 元数据抓取...");

    let add_uploaded = read_bool_param(&input.params, "additionaltags", false)
        || read_bool_param(&input.params, "add_uploaded", false);

    let mut metadata = ensure_metadata_object(input.metadata);
    let existing_tags = metadata_tags_to_csv(&metadata);
    let title = metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let cookie_header = build_cookie_header_for_nh(&input.login_cookies);

    let gallery_id = extract_gallery_id(&input.oneshot_param)
        .or_else(|| extract_gallery_id_from_source_tag(&existing_tags))
        .or_else(|| extract_gallery_id_from_title(&title))
        .or_else(|| {
            if title.is_empty() {
                None
            } else {
                search_gallery_id_by_title(&title, &cookie_header).ok().flatten()
            }
        });

    let Some(gallery_id) = gallery_id else {
        return Err("No matching nHentai Gallery Found!".to_string());
    };
    HostBridge::log(1, &format!("nhmeta-rs resolved gallery_id={gallery_id}"));

    HostBridge::progress(30, &format!("获取画廊 {} 元数据...", gallery_id));
    let (next_title, tags_csv, updated_at) = fetch_gallery_metadata(&gallery_id, add_uploaded, &cookie_header)?;

    if !next_title.trim().is_empty() {
        metadata.insert("title".to_string(), Value::String(next_title));
    }
    metadata.insert("tags".to_string(), metadata_tags_from_csv(&tags_csv));
    if let Some(v) = updated_at {
        if !v.trim().is_empty() {
            metadata.insert("updated_at".to_string(), Value::String(v));
        }
    }
    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "元数据获取完成");
    Ok(Value::Object(metadata))
}

fn extract_gallery_id(input: &str) -> Option<String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return Some(clean.to_string());
    }
    let re = Regex::new(r"nhentai\.net/g/(\d+)").ok()?;
    re.captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_gallery_id_from_source_tag(existing_tags: &str) -> Option<String> {
    let re = Regex::new(r"source:\s*(?:https?://)?nhentai\.net/g/(\d+)").ok()?;
    re.captures(existing_tags)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_gallery_id_from_title(title: &str) -> Option<String> {
    let re = Regex::new(r"\{(\d+)\}").ok()?;
    re.captures(title)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn sanitize_search_title(title: &str) -> String {
    title.replace(['-', '\''], " ").trim().to_string()
}

fn search_gallery_id_by_title(title: &str, cookie_header: &str) -> Result<Option<String>, String> {
    let q = sanitize_search_title(title);
    if q.is_empty() {
        return Ok(None);
    }

    let url = format!("https://nhentai.net/search/?q={}", urlencoding::encode(&q));
    let mut headers = default_headers();
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header.to_string()));
    }
    HostBridge::log(1, &format!("nhmeta-rs GET search {}", url));
    let response = http_get_text_with_retry(&url, &headers, 4)?;
    HostBridge::log(1, &format!("nhmeta-rs search response status={}", response.status));
    if !(200..300).contains(&response.status) {
        return Ok(None);
    }

    if looks_like_cloudflare_block(&response.body_text) {
        return Err("Cloudflare protection detected. Please configure nhlogin cookies (cf_clearance).".to_string());
    }

    let re = Regex::new(r#"class=\"cover\"[^>]*href=\"([^\"]+)\""#)
        .map_err(|e| e.to_string())?;
    if let Some(caps) = re.captures(&response.body_text) {
        if let Some(href) = caps.get(1) {
            let re_id = Regex::new(r"/g/(\d+)/").map_err(|e| e.to_string())?;
            if let Some(id_caps) = re_id.captures(href.as_str()) {
                if let Some(id) = id_caps.get(1) {
                    return Ok(Some(id.as_str().to_string()));
                }
            }
        }
    }

    Ok(None)
}

fn fetch_gallery_metadata(
    gallery_id: &str,
    add_uploaded: bool,
    cookie_header: &str,
) -> Result<(String, String, Option<String>), String> {
    let url = format!("https://nhentai.net/g/{gallery_id}/");
    let mut headers = default_headers();
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header.to_string()));
    }
    HostBridge::log(1, &format!("nhmeta-rs GET gallery {}", url));
    let response = http_get_text_with_retry(&url, &headers, 4)?;
    HostBridge::log(1, &format!("nhmeta-rs gallery response status={}", response.status));

    if response.status == 404 {
        return Err(format!("Gallery not found: {gallery_id}"));
    }
    if response.status == 403 {
        return Err(
            "Blocked by Cloudflare. Please configure nhlogin cookies (cf_clearance) and retry."
                .to_string(),
        );
    }
    if !(200..300).contains(&response.status) {
        return Err(format!("Failed to fetch gallery: HTTP {}", response.status));
    }

    if looks_like_cloudflare_block(&response.body_text) {
        return Err(
            "Cloudflare protection detected. Please configure nhlogin cookies (cf_clearance) and retry."
                .to_string(),
        );
    }

    let gallery = extract_gallery_json_from_html(&response.body_text)?;
    let title = pick_title_from_gallery_json(&gallery, gallery_id);
    let (tags, updated_at) = build_tags_from_gallery_json(&gallery, gallery_id, add_uploaded);
    Ok((title, tags, updated_at))
}

fn http_get_text_with_retry(
    url: &str,
    headers: &[(String, String)],
    max_retries: usize,
) -> Result<HttpTextResponse, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match http_get_text(url, headers) {
            Ok(v) => {
                if attempt > 0 {
                    HostBridge::log(1, &format!("nhmeta-rs retry succeeded attempt={attempt} url={url}"));
                }
                return Ok(v);
            }
            Err(e) => {
                HostBridge::log(
                    1,
                    &format!("nhmeta-rs request failed attempt={attempt}/{max_retries} url={url} error={e}"),
                );
                if attempt >= max_retries || !is_retryable_network_error(&e) {
                    return Err(e);
                }
                last_err = e;
                let wait_ms = 120u64 * (attempt as u64 + 1);
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
            }
        }
    }
    Err(last_err)
}

fn is_retryable_network_error(err: &str) -> bool {
    let s = err.to_ascii_lowercase();
    s.contains("os error 6")
        || s.contains("resource temporarily unavailable")
        || s.contains("would block")
        || s.contains("timed out")
        || s.contains("interrupted")
}

fn extract_gallery_json_from_html(html: &str) -> Result<Value, String> {
    let re = Regex::new(
        r#"window\._gallery\s*=\s*JSON\.parse\(\s*(\"(?:\\.|[^\"\\])*\")\s*\)\s*;"#,
    )
    .map_err(|e| e.to_string())?;
    let caps = re
        .captures(html)
        .ok_or_else(|| "Failed to parse gallery metadata (missing embedded JSON)".to_string())?;
    let quoted = caps
        .get(1)
        .ok_or_else(|| "Failed to parse gallery metadata (json string missing)".to_string())?
        .as_str();

    let json_string: String = serde_json::from_str(quoted)
        .map_err(|e| format!("Failed to decode embedded gallery JSON string: {e}"))?;
    serde_json::from_str::<Value>(&json_string)
        .map_err(|e| format!("Failed to parse embedded gallery JSON: {e}"))
}

fn build_tags_from_gallery_json(
    gallery: &Value,
    gallery_id: &str,
    add_uploaded: bool,
) -> (String, Option<String>) {
    let mut tags = Vec::<String>::new();
    if let Some(arr) = gallery.get("tags").and_then(Value::as_array) {
        for t in arr {
            let ns = t
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if name.is_empty() {
                continue;
            }
            if ns.is_empty() || ns == "tag" {
                tags.push(name);
            } else {
                tags.push(format!("{ns}:{name}"));
            }
        }
    }

    if !tags.is_empty() {
        tags.push(format!("source:nhentai.net/g/{gallery_id}"));
    }

    let updated_at = if add_uploaded {
        gallery.get("upload_date").and_then(format_uploaded_at_value)
    } else {
        None
    };

    (tags.join(", "), updated_at)
}

fn format_uploaded_at_value(value: &Value) -> Option<String> {
    if let Some(n) = value.as_i64() {
        return epoch_seconds_to_utc_timestamp(n);
    }
    let raw = value.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.chars().all(|ch| ch.is_ascii_digit()) {
        let secs = raw.parse::<i64>().ok()?;
        return epoch_seconds_to_utc_timestamp(secs);
    }
    Some(raw.to_string())
}

fn epoch_seconds_to_utc_timestamp(secs: i64) -> Option<String> {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(fmt).ok())
}

fn pick_title_from_gallery_json(gallery: &Value, gallery_id: &str) -> String {
    for key in ["pretty", "english", "japanese"] {
        if let Some(v) = gallery
            .get("title")
            .and_then(Value::as_object)
            .and_then(|obj| obj.get(key))
            .and_then(Value::as_str)
        {
            let t = v.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    format!("Gallery {gallery_id}")
}

fn looks_like_cloudflare_block(html: &str) -> bool {
    let lc = html.to_ascii_lowercase();
    lc.contains("just a moment")
        || lc.contains("checking your browser")
        || lc.contains("cf-browser-verification")
}

fn build_cookie_header_for_nh(cookies: &[LoginCookie]) -> String {
    cookies
        .iter()
        .filter(|c| {
            let d = c.domain.trim().to_ascii_lowercase();
            d.is_empty() || d == "nhentai.net" || d.ends_with(".nhentai.net")
        })
        .filter(|c| !c.name.trim().is_empty() && !c.value.trim().is_empty())
        .map(|c| format!("{}={}", c.name.trim(), c.value.trim()))
        .collect::<Vec<_>>()
        .join("; ")
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
            !(s.is_empty() || s == "0" || s == "false" || s == "no" || s == "off")
        }
        _ => default,
    }
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn metadata_tags_to_csv(metadata: &Map<String, Value>) -> String {
    let Some(raw) = metadata.get("tags") else {
        return String::new();
    };
    match raw {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Object(o) => o.get("name").and_then(Value::as_str).map(|s| s.trim().to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    let tags = csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| Value::String(s.to_string()))
        .collect::<Vec<_>>();
    Value::Array(tags)
}

fn default_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        (
            "Accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ),
        ("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()),
        ("Referer".to_string(), "https://nhentai.net/".to_string()),
    ]
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
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid dns name: {host}"))?;
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
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, v)| v)
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next()?.trim();
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, rhs)| rhs)
        .unwrap_or(authority);
    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return Some((h.to_string(), p.parse::<u16>().ok()?));
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
    let _http = parts
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
    if is_chunked_transfer_encoding(headers) {
        let mut raw = pending;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = read_stream_chunk(stream, &mut buf, true)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        return decode_chunked_body(&raw);
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

    let mut out = pending;
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

fn is_chunked_transfer_encoding(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let size_line_end = raw[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .ok_or_else(|| "invalid chunked body: missing chunk size line ending".to_string())?;
        let size_line = std::str::from_utf8(&raw[i..size_line_end])
            .map_err(|_| "invalid chunked body: chunk size line is not utf-8".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunked body: bad chunk size `{size_hex}`"))?;
        i = size_line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if i + size + 2 > raw.len() {
            return Err("invalid chunked body: truncated chunk payload".to_string());
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size;
        if &raw[i..i + 2] != b"\r\n" {
            return Err("invalid chunked body: missing chunk terminator".to_string());
        }
        i += 2;
    }
    Err("invalid chunked body: missing final zero chunk".to_string())
}

fn read_stream_chunk(stream: &mut HttpStream, buf: &mut [u8], allow_tls_eof: bool) -> Result<usize, String> {
    let mut retries = 0u8;
    loop {
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) => {
                if allow_tls_eof && is_tls_close_notify_eof(&e) {
                    return Ok(0);
                }
                if is_temporary_io_error(&e) && retries < 6 {
                    retries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                return Err(e.to_string());
            }
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

fn is_temporary_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = format!("{host}:{port}").to_socket_addrs().map_err(|e| e.to_string())?;
    addrs
        .next()
        .ok_or_else(|| format!("unable to resolve host: {host}:{port}"))
}
