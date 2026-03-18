use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0";
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

    fn info(message: &str) {
        Self::log(0, message);
    }

    fn warn(message: &str) {
        Self::log(1, message);
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
        "name": "ArtStation Downloader",
        "type": "download",
        "namespace": "artstation",
        "author": "lrr4cj",
        "version": "1.0",
        "description": "Downloads all artwork images from an ArtStation user profile to a folder",
        "parameters": [
            {"name": "quality", "type": "string", "desc": "Image quality: 4k or large", "default_value": "4k"},
            {"name": "bypass_url", "type": "string", "desc": "CloudflareBypass URL (e.g. http://localhost:8089)", "default_value": ""}
        ],
        "url_regex": "https?://(www\\.artstation\\.com/[^/]+|[^/]+\\.artstation\\.com)/?.*",
        "permissions": ["net"],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Download/ArtStation.ts"
    })
}

fn run_download(input: PluginInput) -> Value {
    let Some(username) = extract_username(&input.url) else {
        return output_err("Invalid ArtStation URL. Use https://www.artstation.com/username or https://username.artstation.com");
    };

    let quality = input
        .params
        .get("quality")
        .and_then(Value::as_str)
        .unwrap_or("4k")
        .trim()
        .to_string();
    let bypass = input
        .params
        .get("bypass_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_string();
    HostBridge::info(&format!(
        "[artstation-rs] start username='{}' bypass_url='{}'",
        username,
        if bypass.is_empty() { "<empty>" } else { "<set>" }
    ));

    let mut hash_ids = Vec::<String>::new();
    let mut page = 1usize;

    loop {
        let rss_url = format!("https://{}.artstation.com/rss?page={}", username, page);
        HostBridge::info(&format!("[artstation-rs] fetch rss page={} url={}", page, rss_url));
        let rss = fetch_text_with_optional_bypass(&rss_url, &bypass, None);
        let text = match rss {
            Ok(v) => v,
            Err(e) => {
                if page == 1 {
                    if e.contains("HTTP 403") {
                        return output_err(
                            "Blocked by ArtStation. Please try again later or use CloudflareBypass.",
                        );
                    }
                    if e.contains("HTTP 404") {
                        return output_err(&format!("User not found: {}", username));
                    }
                    return output_err(&format!("Failed to fetch RSS: {e}"));
                }
                break;
            }
        };

        let links = parse_rss_links(&text);
        HostBridge::info(&format!(
            "[artstation-rs] rss page={} links={}",
            page,
            links.len()
        ));
        if links.is_empty() {
            break;
        }
        for link in links {
            if let Some(id) = extract_artwork_hash(&link) {
                hash_ids.push(id);
            }
        }
        page += 1;
        if page > 200 {
            break;
        }
    }

    if hash_ids.is_empty() {
        return output_err(&format!("No artworks found for user: {}", username));
    }

    let out_base = resolve_plugin_dir(&input.plugin_dir, "artstation-rs");
    let out_dir = format!("{out_base}/{username}");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        return output_err(&format!("Failed to prepare output dir: {e}"));
    }

    let mut downloaded = 0usize;
    let mut failed = 0usize;

    for (i, hash_id) in hash_ids.iter().enumerate() {
        let progress = ((i * 100) / hash_ids.len()) as i32;
        HostBridge::progress(progress, &format!("Downloading project {}/{}...", i + 1, hash_ids.len()));

        let project_url = format!("https://www.artstation.com/projects/{}.json", hash_id);
        let ptxt = fetch_text_with_optional_bypass(&project_url, &bypass, Some("application/json"));
        let ptxt = match ptxt {
            Ok(v) => v,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let project: Value = match serde_json::from_str(&ptxt) {
            Ok(v) => v,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let assets = project
            .get("assets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for asset in assets {
            let has_image = asset.get("has_image").and_then(Value::as_bool).unwrap_or(false);
            if !has_image {
                continue;
            }
            let mut image_url = asset
                .get("image_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if image_url.is_empty() {
                continue;
            }

            if quality.eq_ignore_ascii_case("4k") {
                image_url = image_url.replace("/large/", "/4k/");
            }
            let file_name = file_name_from_url(&image_url);
            let file_path = PathBuf::from(format!("{out_dir}/{file_name}"));
            if file_path.exists() {
                downloaded += 1;
                continue;
            }

            match download_file(&image_url, None, "", &file_path) {
                Ok(_) => downloaded += 1,
                Err(_) => failed += 1,
            }
        }
    }

    HostBridge::progress(100, &format!("Download complete: {} succeeded, {} failed", downloaded, failed));
    if downloaded == 0 {
        return output_err(&format!("No images were downloaded for user: {}", username));
    }

    json!({
        "success": true,
        "data": [{
            "relative_path": format!("plugins/artstation-rs/{}", username),
            "filename": username,
            "source": format!("https://www.artstation.com/{}", username),
            "downloaded_count": downloaded,
            "failed_count": failed
        }]
    })
}

fn extract_username(url: &str) -> Option<String> {
    let clean = url.trim().trim_matches('"').trim_matches('\'');

    let m1 = Regex::new(r#"https?://(?:www\.)?artstation\.com/([^/?#"'\s]+)"#).ok()?;
    if let Some(u) = m1
        .captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
    {
        if u != "artwork" && u != "projects" {
            return Some(u);
        }
    }

    let m2 = Regex::new(r"https?://([^\.]+)\.artstation\.com").ok()?;
    if let Some(u) = m2
        .captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
    {
        if u != "www" {
            return Some(u);
        }
    }

    None
}

fn parse_rss_links(rss: &str) -> Vec<String> {
    let item_re = Regex::new(r"(?s)<item[^>]*>.*?</item>").ok();
    let link_re = Regex::new(r"<link[^>]*>([^<]+)</link>").ok();

    let mut links = Vec::new();
    if let (Some(i_re), Some(l_re)) = (item_re, link_re) {
        for item in i_re.find_iter(rss) {
            if let Some(cap) = l_re.captures(item.as_str()) {
                if let Some(m) = cap.get(1) {
                    links.push(m.as_str().trim().to_string());
                }
            }
        }
    }
    links
}

fn extract_artwork_hash(link: &str) -> Option<String> {
    let re = Regex::new(r"artstation\.com/artwork/([A-Za-z0-9]+)").ok()?;
    re.captures(link)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn file_name_from_url(url: &str) -> String {
    if let Ok(u) = Url::parse(url) {
        if let Some(seg) = u.path_segments().and_then(|mut s| s.next_back()) {
            if !seg.is_empty() {
                return seg.to_string();
            }
        }
    }
    format!("image_{}.jpg", now_millis())
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn fetch_text_with_bypass(url: &str, bypass: &str) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or_else(|| "invalid host".to_string())?;
    let endpoint = format!("{}{}{}", bypass, parsed.path(), parsed.query().map(|q| format!("?{q}")).unwrap_or_default());
    fetch_text_with_headers(&endpoint, Some(host), None, true)
}

fn fetch_text_with_optional_bypass(url: &str, bypass: &str, accept: Option<&str>) -> Result<String, String> {
    if bypass.trim().is_empty() {
        return fetch_text(url, accept);
    }
    match fetch_text_with_bypass(url, bypass) {
        Ok(v) => Ok(v),
        Err(e) => {
            HostBridge::warn(&format!(
                "[artstation-rs] bypass failed for {}, fallback direct: {}",
                url, e
            ));
            fetch_text(url, accept)
        }
    }
}

fn fetch_text(url: &str, accept: Option<&str>) -> Result<String, String> {
    fetch_text_with_headers(url, None, accept, false)
}

fn fetch_text_with_headers(
    url: &str,
    x_hostname: Option<&str>,
    accept: Option<&str>,
    force_direct: bool,
) -> Result<String, String> {
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        (
            "Accept".to_string(),
            accept
                .unwrap_or("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .to_string(),
        ),
        ("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()),
    ];
    if let Some(h) = x_hostname {
        headers.push(("x-hostname".to_string(), h.to_string()));
    }

    let resp = http_get(url, None, &headers, force_direct)?;
    if !(200..300).contains(&resp.status) {
        HostBridge::warn(&format!(
            "[artstation-rs] non-2xx url={} status={}",
            url, resp.status
        ));
        return Err(format!("HTTP {}", resp.status));
    }
    Ok(String::from_utf8_lossy(&resp.body).to_string())
}

fn resolve_plugin_dir(raw: &str, ns: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return format!("./data/cache/plugins/{ns}");
    }
    trimmed.to_string()
}

fn output_err(msg: &str) -> Value {
    json!({"success": false, "error": msg})
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

fn download_file(url: &str, referer: Option<&str>, cookie_header: &str, output: &PathBuf) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "image/*,*/*".to_string()),
    ];
    if let Some(r) = referer {
        headers.push(("Referer".to_string(), r.to_string()));
    }
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header.to_string()));
    }

    let resp = http_get(url, referer, &headers, false)?;
    if resp.status >= 400 {
        return Err(format!("HTTP {}", resp.status));
    }
    let mut file = File::create(output).map_err(|e| e.to_string())?;
    file.write_all(&resp.body).map_err(|e| e.to_string())?;
    Ok(())
}

fn http_get(
    url: &str,
    referer: Option<&str>,
    headers: &[(String, String)],
    force_direct: bool,
) -> Result<HttpResponse, String> {
    let mut current_url = url.to_string();
    let mut current_referer = referer.map(|v| v.to_string());
    for _ in 0..=MAX_REDIRECTS {
        let response = http_get_once(&current_url, current_referer.as_deref(), headers, force_direct)?;
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
    force_direct: bool,
) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid url {url}: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme: {scheme}"));
    }
    let host = parsed.host_str().ok_or_else(|| "url missing host".to_string())?;
    let port = parsed.port_or_known_default().ok_or_else(|| "url missing port".to_string())?;

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

    let proxy = if force_direct {
        None
    } else {
        resolve_proxy_for_scheme(scheme, host)
    };
    if let Some((ph, pp)) = &proxy {
        HostBridge::info(&format!(
            "[artstation-rs] http_get_once {} via proxy {}:{}",
            url, ph, pp
        ));
    } else {
        HostBridge::info(&format!("[artstation-rs] http_get_once {} direct", url));
    }
    let do_once = |proxy_override: Option<(String, u16)>| -> Result<HttpResponse, String> {
        let stream = connect_target_stream(host, port, proxy_override)?;
        let raw = if scheme == "https" {
            read_https_response(stream, host, req.as_bytes())?
        } else {
            let mut plain_stream = stream;
            write_all_to_stream(&mut plain_stream, req.as_bytes())?;
            read_all_from_stream(&mut plain_stream)?
        };
        parse_http_response(&raw)
    };

    let first = do_once(proxy.clone());
    if first.is_ok() {
        return first;
    }
    if proxy.is_some() {
        if first.is_err() {
            HostBridge::warn(&format!(
                "[artstation-rs] proxy request failed for {}, fallback to direct",
                url
            ));
            return do_once(None);
        }
    }
    first
}

fn connect_target_stream(
    host: &str,
    port: u16,
    proxy: Option<(String, u16)>,
) -> Result<HostTcpStream, String> {
    if let Some((proxy_host, proxy_port)) = proxy {
        let mut proxy_stream = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
        establish_proxy_connect_tunnel(&mut proxy_stream, host, port)?;
        Ok(proxy_stream)
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)
    }
}

fn resolve_proxy_for_scheme(scheme: &str, target_host: &str) -> Option<(String, u16)> {
    if should_bypass_proxy(target_host) {
        return None;
    }
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

fn should_bypass_proxy(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    if h == "localhost" || h == "::1" || h == "127.0.0.1" {
        return true;
    }
    if h.starts_with("127.") || h.starts_with("10.") || h.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = h.strip_prefix("172.") {
        if let Some(first) = rest.split('.').next() {
            if let Ok(v) = first.parse::<u8>() {
                if (16..=31).contains(&v) {
                    return true;
                }
            }
        }
    }

    for key in ["NO_PROXY", "no_proxy"] {
        if let Ok(v) = std::env::var(key) {
            for raw in v.split(',') {
                let token = raw.trim().to_ascii_lowercase();
                if token.is_empty() {
                    continue;
                }
                if token == "*" || token == h {
                    return true;
                }
                if let Some(suffix) = token.strip_prefix('.') {
                    if h == suffix || h.ends_with(&format!(".{suffix}")) {
                        return true;
                    }
                }
            }
        }
    }
    false
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
    HostBridge::info(&format!(
        "[artstation-rs] proxy CONNECT {}:{}",
        target_host, target_port
    ));
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
    HostBridge::info(&format!("[artstation-rs] proxy CONNECT status={}", status));
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
    let start = raw
        .windows(5)
        .position(|w| w == b"HTTP/")
        .unwrap_or(0);
    let sliced = &raw[start..];
    let header_end = if let Some(p) = sliced.windows(4).position(|w| w == b"\r\n\r\n") {
        (p, 4usize)
    } else if let Some(p) = sliced.windows(2).position(|w| w == b"\n\n") {
        (p, 2usize)
    } else {
        let preview_len = sliced.len().min(120);
        let preview = String::from_utf8_lossy(&sliced[..preview_len]).replace('\n', "\\n");
        HostBridge::warn(&format!(
            "[artstation-rs] parse_http_response missing headers, raw_len={}, preview={}",
            raw.len(),
            preview
        ));
        return Err("invalid HTTP response: missing headers".to_string());
    };
    let (head, rest) = sliced.split_at(header_end.0 + header_end.1);
    let header_text = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let mut lines = header_text.split('\n');
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
