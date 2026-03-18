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
use std::sync::Arc;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "lanlu_host")]
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
    url: String,
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
    #[serde(default)]
    params: Value,
    #[serde(rename = "loginCookies", default)]
    login_cookies: Vec<LoginCookie>,
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

#[derive(Clone)]
struct MediaItem {
    kind: String,
    url: String,
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

    let result = run_download(input);
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
        "name": "Twitter/X Downloader",
        "type": "download",
        "namespace": "xdl",
        "login_from": "xlogin",
        "author": "lrr4cj",
        "version": "1.0",
        "description": "Downloads media (photos/videos) from a single X (Twitter) post URL.",
        "parameters": [
            {
                "name": "image_quality",
                "type": "string",
                "desc": "Photo quality for pbs.twimg.com: orig | large | medium | small | 4096x4096 | 1200x1200 | 900x900",
                "default_value": "orig"
            }
        ],
        "url_regex": "https?://(x\\.com|twitter\\.com)/(?:[^/]+/status/\\d+|i/web/status/\\d+)(?:\\?.*)?$",
        "permissions": [
            "net=x.com",
            "net=twitter.com",
            "net=cdn.syndication.twimg.com",
            "net=pbs.twimg.com",
            "net=video.twimg.com",
            "tcp.connect",
            "fs.write",
            "log.write",
            "progress.report"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Download/Twitter.ts"
    })
}

fn run_download(input: PluginInput) -> Value {
    let Some(tweet_id) = extract_tweet_id(&input.url) else {
        return output_err("Invalid X/Twitter status URL.");
    };

    let quality = input
        .params
        .get("image_quality")
        .and_then(Value::as_str)
        .unwrap_or("orig")
        .trim()
        .to_string();

    HostBridge::progress(1, "Fetching tweet info...");
    let tweet = match fetch_tweet(&tweet_id, &input.login_cookies) {
        Ok(v) => v,
        Err(e) => return output_err(&e),
    };

    let screen_name = tweet
        .get("user")
        .and_then(|v| v.get("screen_name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let media = collect_media(&tweet, &quality);
    if media.is_empty() {
        return output_err("No media found in this tweet (or it is not accessible).");
    }

    let safe_author = sanitize_filename(&screen_name);
    let base_dir = resolve_plugin_dir(&input.plugin_dir, "xdl-rs");
    let abs_dir = format!("{base_dir}/{safe_author}/{tweet_id}");
    if let Err(e) = fs::create_dir_all(&abs_dir) {
        return output_err(&format!("Failed to prepare output dir: {e}"));
    }

    let mut ok_count = 0usize;
    let mut fail_count = 0usize;
    for (idx, item) in media.iter().enumerate() {
        let ext = guess_ext(&item.url);
        let filename = format!("{tweet_id}_{}_{}.{}", item.kind, format!("{:02}", idx + 1), ext);
        let mut out_path = PathBuf::from(&abs_dir);
        out_path.push(filename);

        let pct = (((idx + 1) * 100) / media.len()).clamp(1, 100) as i32;
        HostBridge::progress(pct, &format!("Downloading {} {}/{}...", item.kind, idx + 1, media.len()));

        match download_file(&item.url, Some(&input.url), &input.login_cookies, &out_path) {
            Ok(_) => ok_count += 1,
            Err(err) => {
                fail_count += 1;
                HostBridge::log(1, &format!("xdl-rs download failed: {} ({err})", item.url));
            }
        }
    }

    HostBridge::progress(100, &format!("Done. Downloaded: {ok_count}, failed: {fail_count}"));
    if ok_count == 0 {
        return output_err("All downloads failed.");
    }

    json!({
        "success": true,
        "data": [{
            "relative_path": format!("plugins/xdl-rs/{safe_author}/{tweet_id}"),
            "filename": format!("{}_{}", safe_author, tweet_id),
            "source": input.url,
            "downloaded_count": ok_count,
            "failed_count": fail_count,
            "archive_type": "folder"
        }]
    })
}

fn fetch_tweet(tweet_id: &str, login_cookies: &[LoginCookie]) -> Result<Value, String> {
    let token = tweet_id
        .bytes()
        .fold(17u64, |acc, b| acc.wrapping_mul(131).wrapping_add(b as u64));
    let url = format!(
        "https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&token={token}"
    );

    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "application/json, text/plain, */*".to_string()),
        ("Referer".to_string(), "https://x.com/".to_string()),
    ];
    let cookie_header = build_cookie_header(&url, login_cookies);
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header));
    }

    let resp = http_get(&url, Some("https://x.com/"), &headers)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("Failed to fetch tweet metadata (HTTP {}).", resp.status));
    }
    serde_json::from_slice(&resp.body).map_err(|e| format!("Invalid tweet JSON: {e}"))
}

fn collect_media(tweet: &Value, quality: &str) -> Vec<MediaItem> {
    let mut out = Vec::new();

    if let Some(photos) = tweet.get("photos").and_then(Value::as_array) {
        for p in photos {
            if let Some(url) = p.get("url").and_then(Value::as_str) {
                out.push(MediaItem {
                    kind: "photo".to_string(),
                    url: photo_url_with_quality(url, quality),
                });
            }
        }
    }

    if let Some(entities) = tweet.get("mediaDetails").and_then(Value::as_array) {
        for m in entities {
            let kind = m.get("type").and_then(Value::as_str).unwrap_or("file");
            if kind == "photo" {
                if let Some(u) = m
                    .get("media_url_https")
                    .and_then(Value::as_str)
                    .or_else(|| m.get("media_url").and_then(Value::as_str))
                {
                    out.push(MediaItem {
                        kind: "photo".to_string(),
                        url: photo_url_with_quality(u, quality),
                    });
                }
                continue;
            }
            if let Some(v) = pick_best_video_variant(m.get("video_info").or_else(|| m.get("videoInfo"))) {
                out.push(MediaItem {
                    kind: if kind == "animated_gif" { "gif" } else { "video" }.to_string(),
                    url: v,
                });
            }
        }
    }

    if let Some(video) = tweet.get("video") {
        if let Some(v) = pick_best_video_variant(Some(video)) {
            out.push(MediaItem {
                kind: "video".to_string(),
                url: v,
            });
        }
    }

    dedupe_media(out)
}

fn pick_best_video_variant(video_info: Option<&Value>) -> Option<String> {
    let vars = video_info
        .and_then(|v| v.get("variants"))
        .and_then(Value::as_array)?;
    let mut best: Option<(i64, String)> = None;
    for v in vars {
        let content = v
            .get("content_type")
            .or_else(|| v.get("contentType"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !content.contains("mp4") {
            continue;
        }
        let url = v.get("url").and_then(Value::as_str).unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let bitrate = v.get("bitrate").and_then(Value::as_i64).unwrap_or(0);
        match &best {
            Some((b, _)) if *b >= bitrate => {}
            _ => best = Some((bitrate, url.to_string())),
        }
    }
    best.map(|(_, u)| u)
}

fn dedupe_media(items: Vec<MediaItem>) -> Vec<MediaItem> {
    let mut out = Vec::<MediaItem>::new();
    for item in items {
        if !out.iter().any(|x| x.url == item.url) {
            out.push(item);
        }
    }
    out
}

fn photo_url_with_quality(raw: &str, quality: &str) -> String {
    if let Ok(mut u) = Url::parse(raw) {
        if u.host_str() == Some("pbs.twimg.com") && u.path().contains("/media/") {
            let filename = u
                .path_segments()
                .and_then(|mut s| s.next_back())
                .unwrap_or_default()
                .to_string();
            let (id, ext) = if let Some((a, b)) = filename.rsplit_once('.') {
                (a.to_string(), b.to_string())
            } else {
                (filename, "jpg".to_string())
            };
            return format!(
                "https://pbs.twimg.com/media/{}?format={}&name={}",
                id,
                ext,
                if quality.is_empty() { "orig" } else { quality }
            );
        }
    }
    raw.to_string()
}

fn extract_tweet_id(input: &str) -> Option<String> {
    let clean = input.trim();
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return Some(clean.to_string());
    }
    let re = Regex::new(r"(?:x\.com|twitter\.com)/(?:[^/]+/status/|i/web/status/)(\d+)").ok()?;
    re.captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn sanitize_filename(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '[' | ']') {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
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

fn guess_ext(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        if let Some(format) = parsed
            .query_pairs()
            .find(|(k, _)| k == "format")
            .map(|(_, v)| v.to_string())
        {
            return format;
        }
        if let Some(seg) = parsed.path_segments().and_then(|mut s| s.next_back()) {
            if let Some((_, ext)) = seg.rsplit_once('.') {
                let ext = ext.to_ascii_lowercase();
                if !ext.is_empty() && ext.len() <= 6 {
                    return ext;
                }
            }
        }
    }
    "jpg".to_string()
}

fn output_err(msg: &str) -> Value {
    json!({ "success": false, "error": msg })
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

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
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

fn download_file(
    url: &str,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    output: &PathBuf,
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    if let Some(v) = referer {
        headers.push(("Referer".to_string(), v.to_string()));
    }
    let cookie_header = build_cookie_header(url, cookies);
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header));
    }
    let resp = http_get(url, referer, &headers)?;
    if resp.status >= 400 {
        return Err(format!("HTTP {}", resp.status));
    }
    let mut file = File::create(output).map_err(|e| e.to_string())?;
    file.write_all(&resp.body).map_err(|e| e.to_string())?;
    Ok(())
}

fn http_get(url: &str, referer: Option<&str>, headers: &[(String, String)]) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut current_referer = referer.map(|v| v.to_string());
    for _ in 0..=MAX_REDIRECTS {
        let response = http_get_once(&current_url, current_referer.as_deref(), headers)?;
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
    headers: &[(String, String)],
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

    let mut req = String::new();
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    if has_default_port(scheme, port) {
        req.push_str(&format!("Host: {host}\r\n"));
    } else {
        req.push_str(&format!("Host: {host}:{port}\r\n"));
    }
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    if let Some(v) = referer {
        req.push_str(&format!("Referer: {v}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
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
    if let Some((proxy_host, proxy_port)) = resolve_proxy_for_scheme(scheme) {
        let mut proxy_stream = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
        establish_proxy_connect_tunnel(&mut proxy_stream, host, port)?;
        Ok(proxy_stream)
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)
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
    write_all_to_stream(stream, req.as_bytes())?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
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
    let status_line = String::from_utf8_lossy(&buf[..header_end])
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
    Ok(())
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

fn read_https_response(stream: HostTcpStream, host: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid tls server name: {host}"))?;
    let conn = ClientConnection::new(tls_client_config().clone(), server_name)
        .map_err(|e| e.to_string())?;
    let mut tls_stream = StreamOwned::new(conn, stream);
    write_all_to_stream(&mut tls_stream, request)?;
    read_all_from_stream(&mut tls_stream)
}

fn tls_client_config() -> &'static Arc<ClientConfig> {
    static TLS_CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
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
            return Err("chunk exceeds buffer length".to_string());
        }
        out.extend_from_slice(&input[idx..idx + size]);
        idx += size;
        if idx + 2 <= input.len() && &input[idx..idx + 2] == b"\r\n" {
            idx += 2;
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

fn is_chunked(headers: &[(String, String)]) -> bool {
    find_header_value(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    find_header_value(headers, "content-length")?.parse::<usize>().ok()
}

fn find_header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn has_default_port(scheme: &str, port: u16) -> bool {
    (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("failed to resolve {host}:{port}"))
}
