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
compile_error!("pixivmeta-rs requires wasm32-wasip1 (target_os = \"wasi\")");

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
        "name": "Pixiv",
        "type": "metadata",
        "namespace": "pixivmeta",
        "login_from": "pixivlogin",
        "author": "lrr4cj",
        "version": "1.0",
        "description": "Fetches metadata (title/tags/summary) from Pixiv artwork via web ajax.",
        "parameters": [
            {"name": "lang", "type": "string", "desc": "Pixiv ajax lang parameter (e.g. en, ja, zh)", "default_value": "en"},
            {"name": "merge_existing", "type": "bool", "desc": "Merge new tags with existing archive tags", "default_value": "1"},
            {"name": "prefix_id", "type": "bool", "desc": "Prefix title with illustId", "default_value": "0"},
            {"name": "strip_html", "type": "bool", "desc": "Strip HTML tags from Pixiv caption", "default_value": "1"},
            {"name": "include_translations", "type": "bool", "desc": "Also add translated tag names when available", "default_value": "0"}
        ],
        "oneshot_arg": "Pixiv artwork URL or illustId (e.g. https://www.pixiv.net/artworks/12345678)",
        "cooldown": 1,
        "permissions": [
            "metadata.read_input",
            "net=www.pixiv.net",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Pixiv.ts"
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
    HostBridge::progress(5, "初始化 Pixiv 元数据抓取...");

    let mut metadata = ensure_metadata_object(input.metadata);
    let lang = read_string_param(&input.params, "lang", "en");
    let merge_existing = read_bool_param(&input.params, "merge_existing", true);
    let prefix_id = read_bool_param(&input.params, "prefix_id", false);
    let strip_html_caption = read_bool_param(&input.params, "strip_html", true);
    let include_translations = read_bool_param(&input.params, "include_translations", false);

    let existing_tags = metadata_tags_to_csv(&metadata);
    let title = metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let illust_id = extract_illust_id(&input.oneshot_param)
        .or_else(|| extract_illust_id_from_source_tag(&existing_tags))
        .or_else(|| extract_illust_id_from_title(&title));

    let Some(illust_id) = illust_id else {
        return Err("No Pixiv illustId found. Provide oneshotParam as Pixiv URL/ID, or add a source:https://www.pixiv.net/artworks/<id> tag.".to_string());
    };
    HostBridge::log(1, &format!("pixivmeta-rs resolved illust_id={illust_id}, lang={lang}"));

    let cookie_header = build_cookie_header_for_pixiv(&input.login_cookies);
    let body = fetch_illust(&illust_id, &lang, &cookie_header)?;

    let raw_title = body
        .get("illustTitle")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let final_title = if prefix_id {
        format!("{} {}", illust_id, raw_title).trim().to_string()
    } else if raw_title.is_empty() {
        illust_id.clone()
    } else {
        raw_title
    };

    let comment = body
        .get("illustComment")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let summary = if strip_html_caption {
        strip_html(comment)
    } else {
        comment.to_string()
    };

    let tags = build_tags(&body, &illust_id, &lang, include_translations);
    let merged_tags = if merge_existing {
        merge_tags(&existing_tags, &tags)
    } else {
        tags
    };

    if !final_title.is_empty() {
        metadata.insert("title".to_string(), Value::String(final_title));
    }
    metadata.insert("description".to_string(), Value::String(summary));
    metadata.insert("tags".to_string(), metadata_tags_from_csv(&merged_tags));

    if let Some(updated_at) = normalize_to_epoch_seconds(
        body.get("updateDate")
            .or_else(|| body.get("uploadDate"))
            .or_else(|| body.get("createDate")),
    ) {
        metadata.insert("updated_at".to_string(), Value::String(updated_at));
    }

    metadata.insert("children".to_string(), Value::Array(Vec::new()));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "元数据获取完成");
    Ok(Value::Object(metadata))
}

fn extract_illust_id(input: &str) -> Option<String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return Some(clean.to_string());
    }

    let re1 = Regex::new(r"pixiv\.net/(?:[a-z]{2}/)?artworks/(\d+)").ok()?;
    if let Some(v) = re1
        .captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
    {
        return Some(v);
    }

    let re2 = Regex::new(r"pixiv\.net/member_illust\.php\?[^#]*illust_id=(\d+)").ok()?;
    re2.captures(clean)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_illust_id_from_source_tag(existing_tags: &str) -> Option<String> {
    let re1 = Regex::new(r"source:\s*(?:https?://(?:www\.)?pixiv\.net/(?:[a-z]{2}/)?artworks/(\d+))").ok()?;
    if let Some(v) = re1
        .captures(existing_tags)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
    {
        return Some(v);
    }
    let re2 = Regex::new(r"source:\s*pixiv:(\d+)").ok()?;
    re2.captures(existing_tags)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_illust_id_from_title(title: &str) -> Option<String> {
    let re = Regex::new(r"pixiv[^0-9]{0,10}(\d{6,})").ok()?;
    re.captures(title)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn fetch_illust(illust_id: &str, lang: &str, cookie_header: &str) -> Result<Map<String, Value>, String> {
    let url = format!(
        "https://www.pixiv.net/ajax/illust/{illust_id}?lang={}",
        urlencoding::encode(lang)
    );
    let mut headers = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        (
            "Accept".to_string(),
            "application/json, text/plain, */*".to_string(),
        ),
        (
            "Referer".to_string(),
            format!("https://www.pixiv.net/artworks/{illust_id}"),
        ),
    ];
    if !cookie_header.is_empty() {
        headers.push(("Cookie".to_string(), cookie_header.to_string()));
    }

    HostBridge::log(1, &format!("pixivmeta-rs GET {}", url));
    let response = http_get_text_with_retry(&url, &headers, 4)?;
    HostBridge::log(
        1,
        &format!(
            "pixivmeta-rs response status={} content_length={:?} transfer_encoding={:?}",
            response.status,
            response.content_length,
            response.transfer_encoding
        ),
    );
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "HTTP {}: {}",
            response.status,
            response.body_text.chars().take(200).collect::<String>()
        ));
    }

    let env: Value = serde_json::from_str(&response.body_text).map_err(|e| {
        let preview = response.body_text.chars().take(160).collect::<String>();
        format!("Invalid pixiv ajax response: {e}; body_preview={preview}")
    })?;
    if env.get("error").and_then(Value::as_bool).unwrap_or(false) {
        return Err(
            env.get("message")
                .and_then(Value::as_str)
                .unwrap_or("Pixiv ajax returned error.")
                .to_string(),
        );
    }

    env.get("body")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "Pixiv ajax returned empty body.".to_string())
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
                    HostBridge::log(1, &format!("pixivmeta-rs retry succeeded attempt={attempt} url={url}"));
                }
                return Ok(v);
            }
            Err(e) => {
                HostBridge::log(
                    1,
                    &format!("pixivmeta-rs request failed attempt={attempt}/{max_retries} url={url} error={e}"),
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

fn build_tags(body: &Map<String, Value>, illust_id: &str, lang: &str, include_translations: bool) -> String {
    let mut out = Vec::<String>::new();

    out.push(format!("source:https://www.pixiv.net/artworks/{illust_id}"));
    out.push(format!("pixiv:{illust_id}"));

    if let Some(uid) = body.get("userId").and_then(Value::as_str) {
        let v = uid.trim();
        if !v.is_empty() {
            out.push(format!("pixiv_user:{v}"));
        }
    }
    if let Some(name) = body.get("userName").and_then(Value::as_str) {
        let v = name.trim();
        if !v.is_empty() {
            out.push(format!("artist:{v}"));
        }
    }
    if let Some(account) = body.get("userAccount").and_then(Value::as_str) {
        let v = account.trim();
        if !v.is_empty() {
            out.push(format!("pixiv_user_account:{v}"));
        }
    }

    match body.get("xRestrict").and_then(Value::as_i64).unwrap_or(0) {
        1 => out.push("rating:R-18".to_string()),
        2 => out.push("rating:R-18G".to_string()),
        _ => {}
    }

    if body.get("aiType").and_then(Value::as_i64).unwrap_or(0) == 2 {
        out.push("ai:generated".to_string());
    }

    if let Some(tags_obj) = body.get("tags").and_then(Value::as_object) {
        if let Some(tags_arr) = tags_obj.get("tags").and_then(Value::as_array) {
            for tag_obj in tags_arr {
                let name = tag_obj
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                out.push(format!("pixiv_tag:{name}"));

                if include_translations {
                    if let Some(trans_obj) = tag_obj.get("translation").and_then(Value::as_object)
                    {
                        let translated = trans_obj
                            .get(lang)
                            .or_else(|| trans_obj.get("en"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        if !translated.is_empty() && translated != name {
                            out.push(format!("pixiv_tag:{translated}"));
                        }
                    }
                }
            }
        }
    }

    dedup_preserve_order(out).join(", ")
}

fn strip_html(html: &str) -> String {
    let with_newlines = Regex::new(r"(?i)<br\s*/?>")
        .map(|re| re.replace_all(html, "\n").to_string())
        .unwrap_or_else(|_| html.to_string());
    let no_tags = Regex::new(r"<[^>]+>")
        .map(|re| re.replace_all(&with_newlines, "").to_string())
        .unwrap_or(with_newlines);

    no_tags
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .trim()
        .to_string()
}

fn normalize_to_epoch_seconds(value: Option<&Value>) -> Option<String> {
    let Some(v) = value else {
        return None;
    };

    if let Some(n) = v.as_i64() {
        if n > 1_000_000_000_000 {
            return Some((n / 1000).to_string());
        }
        return Some(n.to_string());
    }

    let Some(s) = v.as_str() else {
        return None;
    };
    let t = s.trim();
    if t.is_empty() {
        return None;
    }

    if t.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = t.parse::<i64>() {
            if n > 1_000_000_000_000 {
                return Some((n / 1000).to_string());
            }
            return Some(n.to_string());
        }
    }

    if let Ok(ts) = parse_iso8601_to_epoch_seconds(t) {
        return Some(ts.to_string());
    }
    None
}

fn parse_iso8601_to_epoch_seconds(s: &str) -> Result<i64, String> {
    let re = Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-]\d{2}):(\d{2}))?$",
    )
    .map_err(|e| e.to_string())?;
    let caps = re
        .captures(s)
        .ok_or_else(|| "invalid datetime format".to_string())?;

    let year: i32 = caps.get(1).ok_or("year")?.as_str().parse().map_err(|_| "year")?;
    let mon: i32 = caps.get(2).ok_or("month")?.as_str().parse().map_err(|_| "month")?;
    let day: i32 = caps.get(3).ok_or("day")?.as_str().parse().map_err(|_| "day")?;
    let hour: i32 = caps.get(4).ok_or("hour")?.as_str().parse().map_err(|_| "hour")?;
    let min: i32 = caps.get(5).ok_or("minute")?.as_str().parse().map_err(|_| "minute")?;
    let sec: i32 = caps.get(6).ok_or("second")?.as_str().parse().map_err(|_| "second")?;

    let mut offset_seconds = 0i64;
    if let Some(sign_h) = caps.get(7) {
        let sign = if sign_h.as_str().starts_with('-') { -1 } else { 1 };
        let hh: i64 = sign_h.as_str()[1..].parse().map_err(|_| "tz hour")?;
        let mm: i64 = caps.get(8).ok_or("tz minute")?.as_str().parse().map_err(|_| "tz minute")?;
        offset_seconds = sign * (hh * 3600 + mm * 60);
    }

    let days = days_from_civil(year, mon, day)?;
    let mut ts = days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64;
    ts -= offset_seconds;
    Ok(ts)
}

fn days_from_civil(y: i32, m: i32, d: i32) -> Result<i64, String> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err("invalid date".to_string());
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era as i64) * 146097 + (doe as i64) - 719468)
}

fn merge_tags(existing: &str, additions: &str) -> String {
    let mut out = Vec::<String>::new();
    for part in existing.split(',').chain(additions.split(',')) {
        let t = part.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    dedup_preserve_order(out).join(", ")
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out = Vec::<String>::new();
    for item in items {
        let key = item.trim().to_string();
        if key.is_empty() || seen.contains(&key) {
            continue;
        }
        seen.insert(key.clone());
        out.push(key);
    }
    out
}

fn build_cookie_header_for_pixiv(cookies: &[LoginCookie]) -> String {
    cookies
        .iter()
        .filter(|c| c.domain.trim().is_empty() || c.domain.to_ascii_lowercase().contains("pixiv.net"))
        .filter(|c| !c.name.trim().is_empty() && !c.value.trim().is_empty())
        .map(|c| format!("{}={}", c.name.trim(), c.value.trim()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn read_string_param(params: &Value, name: &str, default: &str) -> String {
    params
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .trim()
        .to_string()
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
    content_length: Option<usize>,
    transfer_encoding: Option<String>,
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
                    content_length: header_value(&response_headers, "Content-Length")
                        .and_then(|v| v.parse::<usize>().ok()),
                    transfer_encoding: header_value(&response_headers, "Transfer-Encoding")
                        .map(|v| v.to_string()),
                });
            };
            current = resolve_redirect_url(&parsed, location)?;
            continue;
        }
        return Ok(HttpTextResponse {
            status,
            body_text: String::from_utf8_lossy(&body).to_string(),
            content_length: header_value(&response_headers, "Content-Length").and_then(|v| v.parse::<usize>().ok()),
            transfer_encoding: header_value(&response_headers, "Transfer-Encoding").map(|v| v.to_string()),
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
