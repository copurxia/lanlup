use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("bofmeta-rs requires wasm32-wasip1 (target_os = \"wasi\")");

const USER_AGENT: &str = "lanlu-bof-metadata/1.0";
const DEFAULT_TIMEOUT_MS: i32 = 10_000;
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
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Clone)]
struct SeriesInfo {
    id: String,
    title: String,
    summary: String,
    status: String,
    tags: Vec<String>,
    cover_frame_url: String,
}

#[derive(Clone)]
struct SearchItem {
    id: String,
    title: String,
}

#[derive(Clone)]
struct VolumeMeta {
    volume_no: i32,
    title: String,
    tags: String,
    cover: String,
    source_url: String,
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
        "name": "Bookof",
        "type": "metadata",
        "namespace": "bofmeta",
        "author": "lanlu",
        "version": "1.0",
        "description": "Scrapes bookof.moe for series metadata and volume cover info.",
        "parameters": [
            {"name": "search_limit", "type": "int", "desc": "Search candidate limit (1-20).", "default_value": "8"}
        ],
        "oneshot_arg": "Bookof series URL, series id, or search keyword",
        "cooldown": 1,
        "permissions": [
            "metadata.read_input",
            "net=bookof.moe",
            "net=img.bookof.moe",
            "net=kmimg.moex.ink",
            "net=moex.ink",
            "net=mxomo.com",
            "net=img.mxomo.com",
            "net=i.mxomo.com",
            "net=pic.mxomo.com",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Bof.ts"
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
    HostBridge::progress(5, "Initializing Bookof metadata...");
    HostBridge::info(&format!(
        "[bofmeta-rs] oneshotParam='{}'",
        input.oneshot_param.trim()
    ));

    let search_limit = clamp_int(read_i64_param(&input.params, "search_limit", 8), 1, 20);
    let mut metadata = ensure_metadata_object(input.metadata);

    let existing_tags = metadata_tags_to_csv(&metadata);
    let archive_title = metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let search_keywords = collect_search_keywords(&input.oneshot_param, &archive_title);
    HostBridge::info(&format!(
        "[bofmeta-rs] search keywords: {}",
        if search_keywords.is_empty() {
            "<none>".to_string()
        } else {
            search_keywords.join(" | ")
        }
    ));
    let series_id = extract_series_id(&input.oneshot_param)
        .or_else(|| extract_series_id_from_tags(&existing_tags))
        .or_else(|| search_series_id_by_keywords(&search_keywords, search_limit));

    let Some(series_id) = series_id else {
        return Err("No Bookof series id found. Provide oneshotParam (series URL/ID/keyword), source tag, or searchable title.".to_string());
    };
    HostBridge::info(&format!("[bofmeta-rs] resolved series id: {series_id}"));

    HostBridge::progress(30, "Fetching series page...");
    let series_url = format!("https://bookof.moe/b/{series_id}.htm");
    HostBridge::info(&format!("[bofmeta-rs] fetch series page: {series_url}"));
    let series_html = fetch_text(&series_url)?;
    let series = parse_series_html(&series_id, &series_html)
        .ok_or_else(|| format!("Failed to parse series page {series_url}"))?;
    HostBridge::info(&format!(
        "[bofmeta-rs] parsed series title='{}', status='{}'",
        series.title, series.status
    ));

    HostBridge::progress(55, "Fetching volume covers...");
    let mut volumes = if !series.cover_frame_url.is_empty() {
        HostBridge::info(&format!(
            "[bofmeta-rs] fetch cover frame: {}",
            series.cover_frame_url
        ));
        fetch_volumes(&series.cover_frame_url)?
    } else {
        Vec::new()
    };
    HostBridge::info(&format!(
        "[bofmeta-rs] parsed {} volume cover entries",
        volumes.len()
    ));
    for (idx, v) in volumes.iter_mut().enumerate() {
        if v.volume_no <= 0 {
            v.volume_no = (idx + 1) as i32;
        }
        if v.title.trim().is_empty() {
            v.title = format!("Volume {}", idx + 1);
        }
        v.tags = dedupe_csv(&format!("source:{series_url}"));
        v.source_url = series_url.clone();
        let cover_url = v.cover.clone();
        let cached = cache_cover_for_result(
            std::slice::from_ref(&cover_url),
            &format!("vol_{}", idx + 1),
            &input.plugin_dir,
            "bofmeta",
        );
        if !cached.is_empty() {
            v.cover = cached;
        }
    }

    HostBridge::progress(80, "Building output metadata...");
    let tags = build_series_tags(&series, &series_url);
    let summary = clean_summary(&series.summary);

    let cover_urls = volumes.iter().map(|v| v.cover.clone()).collect::<Vec<_>>();
    let mut series_cover =
        cache_cover_for_result(&cover_urls, &format!("series_{series_id}"), &input.plugin_dir, "bofmeta");
    if series_cover.is_empty() && !cover_urls.is_empty() {
        series_cover = cover_urls[0].clone();
    }
    if series_cover.is_empty() {
        HostBridge::warn("[bofmeta-rs] series cover not resolved");
    } else {
        HostBridge::info(&format!("[bofmeta-rs] series cover: {series_cover}"));
    }

    if !series.title.trim().is_empty() {
        metadata.insert("title".to_string(), Value::String(series.title.clone()));
    }
    if !summary.trim().is_empty() {
        metadata.insert("description".to_string(), Value::String(summary));
    }
    if !tags.trim().is_empty() {
        metadata.insert("tags".to_string(), metadata_tags_from_csv(&tags));
    }
    if !series_cover.trim().is_empty() {
        metadata.insert(
            "assets".to_string(),
            metadata_set_asset_value(metadata.get("assets").cloned(), "cover", &series_cover),
        );
    }

    let mut children = Vec::new();
    for item in &volumes {
        children.push(json!({
            "title": item.title,
            "type": 0,
            "description": "",
            "tags": metadata_tags_from_csv(&item.tags),
            "assets": metadata_set_asset_value(None, "cover", &item.cover),
            "volume_no": item.volume_no,
            "locator": {"entity_type": "archive", "volume_no": item.volume_no},
            "release_at": "",
            "isbn": "",
            "source_url": item.source_url,
        }));
    }
    metadata.insert("children".to_string(), Value::Array(children));
    metadata.remove("archive");
    metadata.remove("archive_id");

    if metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        if let Some(first_title) = metadata
            .get("children")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("title"))
            .and_then(Value::as_str)
        {
            if !first_title.trim().is_empty() {
                metadata.insert("title".to_string(), Value::String(first_title.to_string()));
            }
        }
    }

    if metadata
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        if let Some(first_desc) = metadata
            .get("children")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("description"))
            .and_then(Value::as_str)
        {
            if !first_desc.trim().is_empty() {
                metadata.insert("description".to_string(), Value::String(first_desc.to_string()));
            }
        }
    }

    let need_tags = metadata
        .get("tags")
        .map(|v| !v.is_array() || v.as_array().is_some_and(|arr| arr.is_empty()))
        .unwrap_or(true);
    if need_tags {
        metadata.insert(
            "tags".to_string(),
            metadata_tags_from_csv(&format!("source:{series_url}")),
        );
    }

    let need_assets = metadata
        .get("assets")
        .map(|v| !v.is_array() || v.as_array().is_some_and(|arr| arr.is_empty()))
        .unwrap_or(true);
    if need_assets {
        let fallback = metadata
            .get("children")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("assets"))
            .cloned();
        if let Some(cover) = metadata_get_asset_value(fallback, "cover") {
            metadata.insert(
                "assets".to_string(),
                metadata_set_asset_value(metadata.get("assets").cloned(), "cover", &cover),
            );
        }
    }

    metadata.insert("source_url".to_string(), Value::String(series_url));
    HostBridge::info(&format!(
        "[bofmeta-rs] done, children={}",
        metadata
            .get("children")
            .and_then(Value::as_array)
            .map(|v| v.len())
            .unwrap_or(0)
    ));
    HostBridge::progress(100, "Metadata fetched");
    Ok(Value::Object(metadata))
}

fn fetch_text(url: &str) -> Result<String, String> {
    HostBridge::info(&format!("[bofmeta-rs] HTTP GET {url}"));
    let headers = vec![
        ("user-agent".to_string(), USER_AGENT.to_string()),
        (
            "accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ),
        ("accept-language".to_string(), "zh-CN,zh;q=0.9,en;q=0.6".to_string()),
    ];
    let response = http_request_with_retry("GET", url, &headers, None)?;
    HostBridge::info(&format!(
        "[bofmeta-rs] HTTP status {} for {}",
        response.status, url
    ));
    if !(200..300).contains(&response.status) {
        return Err(format!("HTTP {}", response.status));
    }
    Ok(String::from_utf8_lossy(&response.body).to_string())
}

fn extract_series_id(value: &str) -> Option<String> {
    let raw = value.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return Some(raw.to_string());
    }
    let re = Regex::new(r"bookof\.moe/b/([^./]+)\.htm").ok()?;
    re.captures(raw)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn extract_series_id_from_tags(existing_tags: &str) -> Option<String> {
    let re = Regex::new(r"source:\s*(?:https?://)?bookof\.moe/b/([^\s,]+)\.htm").ok()?;
    re.captures(existing_tags)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn collect_search_keywords(oneshot_param: &str, archive_title: &str) -> Vec<String> {
    let mut out = Vec::new();
    let oneshot = oneshot_param.trim();
    if !oneshot.is_empty() && extract_series_id(oneshot).is_none() {
        out.extend(extract_search_keywords(oneshot, Some(3)));
    }
    out.extend(extract_search_keywords(archive_title, Some(4)));
    dedupe_strings(out).into_iter().take(6).collect()
}

fn extract_search_keywords(raw_title: &str, limit_count: Option<usize>) -> Vec<String> {
    let input = raw_title.trim();
    if input.is_empty() {
        return Vec::new();
    }

    let title_no_ext = Regex::new(r"\.(?:zip|cbz|cbr|rar|7z|pdf|epub)$")
        .ok()
        .map(|re| re.replace(input, "").to_string())
        .unwrap_or_else(|| input.to_string())
        .trim()
        .to_string();

    let bracket_re = Regex::new(r"\[([^\[\]]+)\]").ok();
    let mut bracket_parts = Vec::<String>::new();
    if let Some(re) = bracket_re {
        for cap in re.captures_iter(&title_no_ext) {
            let s = cap.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            if !s.is_empty() {
                bracket_parts.push(s);
            }
        }
    }

    let mut title_part = String::new();
    let mut author_parts: Vec<String> = Vec::new();

    let author_candidate = bracket_parts
        .iter()
        .find(|p| p.chars().any(|c| c == 'x' || c == 'X' || c == '×'))
        .cloned();

    if let Some(candidate) = author_candidate {
        author_parts = candidate
            .split(['×', 'x', 'X'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for part in &bracket_parts {
            if *part != candidate {
                title_part = part.clone();
                break;
            }
        }
    } else {
        if let Some(v) = bracket_parts.first() {
            title_part = v.clone();
        }
        if bracket_parts.len() > 1 {
            author_parts.push(bracket_parts[1].clone());
        }
    }

    let title_parts: Vec<String> = if title_part.is_empty() {
        Vec::new()
    } else {
        title_part
            .split('_')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    };

    let mut grouped = Vec::<String>::new();
    for t in title_parts.into_iter().chain(author_parts.into_iter()) {
        let s = sanitize_search_keyword(&t);
        if !s.is_empty() {
            grouped.push(s);
        }
    }

    let mut minimal = title_no_ext.clone();
    for pat in [
        r"[\(\[【（]?境外版[\)\]】）]?\s*",
        r"[\(\[【（]?单行本[\)\]】）]?\s*$",
        r"[\(\[【（]?\d+卷[\)\]】）]?\s*$",
        r"\[.*?\]",
        r"【.*?】",
        r"[（()）]",
        r"[_-]?\s*$",
    ] {
        if let Ok(re) = Regex::new(pat) {
            minimal = re.replace_all(&minimal, " ").to_string();
        }
    }
    minimal = sanitize_search_keyword(minimal.trim());

    let mut fallback = title_no_ext.clone();
    for pat in [r"\[.*?\]", r"【.*?】", r"[（(][^）)]*[）)]"] {
        if let Ok(re) = Regex::new(pat) {
            fallback = re.replace_all(&fallback, " ").to_string();
        }
    }
    fallback = sanitize_search_keyword(fallback.trim());

    let mut final_titles = dedupe_strings(
        std::iter::once(minimal)
            .chain(grouped)
            .chain(std::iter::once(fallback))
            .filter(|s| !s.is_empty())
            .collect(),
    );
    if let Some(limit) = limit_count {
        final_titles.truncate(limit);
    }
    final_titles
}

fn search_series_id_by_keywords(keywords: &[String], limit: i32) -> Option<String> {
    let normalized_keywords = dedupe_strings(
        keywords
            .iter()
            .map(|k| normalize_title_for_search(k))
            .filter(|k| !k.is_empty())
            .collect(),
    );
    if normalized_keywords.is_empty() {
        return None;
    }

    let mut candidates = Vec::<(String, f64)>::new();
    for keyword in normalized_keywords {
        let items = search_series_items(&keyword, limit);
        for it in items {
            let score = title_similarity(&keyword, &normalize_title_for_search(&it.title));
            if let Some(v) = candidates.iter_mut().find(|v| v.0 == it.id) {
                if score > v.1 {
                    v.1 = score;
                }
            } else {
                candidates.push((it.id, score));
            }
        }
    }

    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    candidates.first().map(|v| v.0.clone())
}

fn search_series_items(keyword: &str, limit: i32) -> Vec<SearchItem> {
    let normalized = normalize_title_for_search(keyword);
    if normalized.is_empty() {
        return Vec::new();
    }

    let url = format!(
        "https://bookof.moe/data_list.php?s={}&p=1",
        urlencoding::encode(&normalized)
    );
    HostBridge::info(&format!("[bofmeta-rs] search url: {url}"));
    let html = match fetch_text(&url) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = parse_search_results(&html);
    HostBridge::info(&format!(
        "[bofmeta-rs] search '{}' got {} candidates",
        keyword,
        items.len()
    ));
    items
        .into_iter()
        .take(limit.max(1) as usize)
        .collect()
}

fn parse_search_results(html: &str) -> Vec<SearchItem> {
    let re = Regex::new(r"datainfo-B=[^,]*,([^,]+),([^,]*),([^,]*),([0-9-]*)").ok();
    let Some(re) = re else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for cap in re.captures_iter(html) {
        let id = cap.get(1).map(|m| m.as_str().trim()).unwrap_or_default();
        let title = cap
            .get(2)
            .map(|m| decode_html_entities(m.as_str().trim()))
            .unwrap_or_default();
        if !id.is_empty() && !title.is_empty() {
            out.push(SearchItem {
                id: id.to_string(),
                title,
            });
        }
    }
    out
}

fn parse_series_html(id: &str, html: &str) -> Option<SeriesInfo> {
    let title = decode_html_entities(&strip_html(&extract_first(
        html,
        r#"class="name_main"[^>]*>([\s\S]*?)<"#,
    )))
    .trim()
    .to_string();

    let info_text = decode_html_entities(&strip_html(&extract_first(
        html,
        r#"class="name_subt"[^>]*>([\s\S]*?)<"#,
    )));

    let summary = decode_html_entities(&strip_html(&extract_first(
        html,
        r#"id="div_desctext"[^>]*>([\s\S]*?)<"#,
    )))
    .replace("\r\n", "\n")
    .trim()
    .to_string();

    let status = Regex::new(r"[狀状]態[:：]\s*([^\s分類<]+)")
        .ok()
        .and_then(|re| re.captures(&info_text))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .unwrap_or_default();

    let tags = Regex::new(r"分[類类][:：]\s*([^\n<]+)")
        .ok()
        .and_then(|re| re.captures(&info_text))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .unwrap_or_default()
        .split_whitespace()
        .map(|v| v.to_string())
        .collect::<Vec<_>>();

    let cover_frame_raw = extract_first(
        html,
        r#"window\.iframe_action\.location\.href\s*=\s*['"]([^'"]+)['"]"#,
    );
    let cover_frame_url = if cover_frame_raw.is_empty() {
        String::new()
    } else if cover_frame_raw.starts_with("http://") || cover_frame_raw.starts_with("https://") {
        cover_frame_raw
    } else {
        format!("https://bookof.moe{}{}", if cover_frame_raw.starts_with('/') { "" } else { "/" }, cover_frame_raw)
    };

    if title.is_empty() {
        return None;
    }

    Some(SeriesInfo {
        id: id.to_string(),
        title,
        summary,
        status,
        tags,
        cover_frame_url,
    })
}

fn fetch_volumes(cover_frame_url: &str) -> Result<Vec<VolumeMeta>, String> {
    let html = fetch_text(cover_frame_url)?;
    let re = Regex::new(r"datainfo-V=\d+,[^,]+,[^,]+,[^,]+,([^,]+),[^,]+")
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for (i, cap) in re.captures_iter(&html).enumerate() {
        let cover_raw = cap.get(1).map(|m| m.as_str().trim()).unwrap_or_default();
        if cover_raw.is_empty() {
            continue;
        }
        let cover_url = if cover_raw.starts_with("http://") || cover_raw.starts_with("https://") {
            cover_raw.to_string()
        } else {
            format!("https://bookof.moe{}{}", if cover_raw.starts_with('/') { "" } else { "/" }, cover_raw)
        };

        out.push(VolumeMeta {
            volume_no: (i + 1) as i32,
            title: format!("Volume {}", i + 1),
            tags: String::new(),
            cover: cover_url.clone(),
            source_url: cover_frame_url.to_string(),
        });
    }
    HostBridge::info(&format!(
        "[bofmeta-rs] cover frame parsed {} entries",
        out.len()
    ));
    Ok(out)
}

fn build_series_tags(series: &SeriesInfo, series_url: &str) -> String {
    let mut tags = vec![format!("source:{series_url}")];
    if !series.status.trim().is_empty() {
        tags.push(series.status.trim().to_string());
    }
    for tag in &series.tags {
        if !tag.trim().is_empty() {
            tags.push(tag.trim().to_string());
        }
    }
    dedupe_csv(&tags.join(", "))
}

fn extract_first(input: &str, pat: &str) -> String {
    Regex::new(pat)
        .ok()
        .and_then(|re| re.captures(input))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .unwrap_or_default()
}

fn strip_html(input: &str) -> String {
    let no_tag = Regex::new(r"<[^>]*>")
        .ok()
        .map(|re| re.replace_all(input, " ").to_string())
        .unwrap_or_else(|| input.to_string());
    Regex::new(r"\s+")
        .ok()
        .map(|re| re.replace_all(&no_tag, " ").to_string())
        .unwrap_or(no_tag)
        .trim()
        .to_string()
}

fn decode_html_entities(input: &str) -> String {
    input
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
}

fn normalize_title_for_search(raw: &str) -> String {
    let mut s = raw.to_string();
    for pat in [r"\[[^\]]*\]", r"\([^)]*\)", r"（[^）]*）", r"[._\-:/\\|]+"] {
        if let Ok(re) = Regex::new(pat) {
            s = re.replace_all(&s, " ").to_string();
        }
    }
    if let Ok(re) = Regex::new(r"\s+") {
        s = re.replace_all(&s, " ").to_string();
    }
    s.trim().to_string()
}

fn sanitize_search_keyword(raw: &str) -> String {
    let mut s = raw.to_string();
    if let Ok(re) = Regex::new(r"[:：•·․,，。'’?？!！~⁓～]") {
        s = re.replace_all(&s, " ").to_string();
    }
    s = s.replace('／', "/");
    if let Ok(re) = Regex::new(r"\s+") {
        s = re.replace_all(&s, " ").to_string();
    }
    s.trim().to_string()
}

fn clean_summary(summary: &str) -> String {
    summary
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|v| v.trim())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn title_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    if a == b {
        return 1.0;
    }
    let al = a.to_ascii_lowercase();
    let bl = b.to_ascii_lowercase();
    if al == bl {
        return 0.98;
    }
    if al.contains(&bl) || bl.contains(&al) {
        return 0.9;
    }

    let ta: Vec<&str> = al.split_whitespace().collect();
    let tb: Vec<&str> = bl.split_whitespace().collect();
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }

    let mut hit = 0usize;
    for t in &ta {
        if tb.contains(t) {
            hit += 1;
        }
    }
    hit as f64 / ta.len().max(tb.len()) as f64
}

fn cache_cover_for_result(urls: &[String], key: &str, plugin_dir: &str, namespace: &str) -> String {
    if urls.is_empty() || plugin_dir.trim().is_empty() || namespace.trim().is_empty() {
        return String::new();
    }

    let cache_dir = format!("{}/cache/covers", plugin_dir.trim_end_matches('/'));
    if fs::create_dir_all(&cache_dir).is_err() {
        return String::new();
    }

    let safe_key = sanitize_key(key);

    for image_url in urls {
        let headers = vec![
            ("user-agent".to_string(), USER_AGENT.to_string()),
            ("accept".to_string(), "image/*,*/*;q=0.8".to_string()),
        ];
        let resp = match http_request_with_retry("GET", image_url, &headers, None) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !(200..300).contains(&resp.status) || resp.body.is_empty() {
            continue;
        }

        let content_type = header_value(&resp.headers, "content-type").unwrap_or("");
        let ext = detect_image_extension(image_url, content_type);
        let file_name = format!("{safe_key}.{ext}");
        let output = format!("{cache_dir}/{file_name}");
        if fs::write(&output, &resp.body).is_ok() {
            return format!("plugins/{namespace}/cache/covers/{file_name}");
        }
    }

    String::new()
}

fn detect_image_extension(url: &str, content_type: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("image/avif") {
        return "avif";
    }
    if ct.contains("image/webp") {
        return "webp";
    }
    if ct.contains("image/png") {
        return "png";
    }
    if ct.contains("image/gif") {
        return "gif";
    }
    if ct.contains("image/jpeg") || ct.contains("image/jpg") {
        return "jpg";
    }

    let clean = url.split('?').next().unwrap_or("").split('#').next().unwrap_or("");
    let re = Regex::new(r"\.([a-zA-Z0-9]{2,5})$").ok();
    let ext = re
        .and_then(|r| r.captures(clean))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
        .unwrap_or_else(|| "jpg".to_string());

    match ext.as_str() {
        "jpeg" | "jpg" => "jpg",
        "png" => "png",
        "webp" => "webp",
        "gif" => "gif",
        "avif" => "avif",
        _ => "jpg",
    }
}

fn sanitize_key(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    let re = Regex::new(r"[^a-z0-9._-]+")
        .ok()
        .map(|r| r.replace_all(&lower, "_").to_string())
        .unwrap_or(lower);
    re.trim_matches('_').to_string()
}

fn clamp_int(v: i64, min: i32, max: i32) -> i32 {
    let mut n = if v < min as i64 { min } else { v as i32 };
    if n > max {
        n = max;
    }
    n
}

fn read_i64_param(params: &Value, key: &str, default: i64) -> i64 {
    let Some(v) = params.get(key) else {
        return default;
    };
    match v {
        Value::Number(n) => n.as_i64().unwrap_or(default),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(default),
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        _ => default,
    }
}

fn dedupe_strings(input: Vec<String>) -> Vec<String> {
    let mut out = Vec::<String>::new();
    for item in input {
        let clean = item.trim();
        if clean.is_empty() {
            continue;
        }
        if !out.iter().any(|v| v.eq_ignore_ascii_case(clean)) {
            out.push(clean.to_string());
        }
    }
    out
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    if let Value::Object(map) = value {
        map
    } else {
        Map::new()
    }
}

fn metadata_tags_to_csv(metadata: &Map<String, Value>) -> String {
    let Some(tags) = metadata.get("tags") else {
        return String::new();
    };
    match tags {
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let Some(s) = item.as_str() {
                    if !s.trim().is_empty() {
                        out.push(s.trim().to_string());
                    }
                } else if let Some(name) = item
                    .as_object()
                    .and_then(|o| o.get("name"))
                    .and_then(Value::as_str)
                {
                    if !name.trim().is_empty() {
                        out.push(name.trim().to_string());
                    }
                }
            }
            dedupe_csv(&out.join(", "))
        }
        Value::String(s) => dedupe_csv(s),
        _ => String::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    Value::Array(
        split_csv_tags(csv)
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>(),
    )
}

fn split_csv_tags(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn dedupe_csv(csv: &str) -> String {
    dedupe_strings(split_csv_tags(csv)).join(", ")
}

fn metadata_set_asset_value(existing: Option<Value>, key: &str, value: &str) -> Value {
    let mut arr = existing.and_then(|v| v.as_array().cloned()).unwrap_or_default();
    arr.retain(|item| {
        item.as_object()
            .and_then(|o| o.get("key"))
            .and_then(Value::as_str)
            .map(|k| !k.eq_ignore_ascii_case(key))
            .unwrap_or(true)
    });
    if !value.trim().is_empty() {
        arr.push(json!({"key": key, "value": value}));
    }
    Value::Array(arr)
}

fn metadata_get_asset_value(existing: Option<Value>, key: &str) -> Option<String> {
    let arr = existing?.as_array()?.clone();
    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let k = obj.get("key").and_then(Value::as_str).unwrap_or_default();
        if !k.eq_ignore_ascii_case(key) {
            continue;
        }
        let v = obj.get("value").and_then(Value::as_str).unwrap_or_default();
        if !v.trim().is_empty() {
            return Some(v.to_string());
        }
    }
    None
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

struct HttpRawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
}

fn http_request_with_retry(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<HttpRawResponse, String> {
    let mut last_error = String::new();
    for idx in 0..3 {
        HostBridge::info(&format!(
            "[bofmeta-rs] attempt {} start {} {}",
            idx + 1,
            method,
            url
        ));
        match http_request(method, url, headers, body) {
            Ok(resp) => {
                if (200..300).contains(&resp.status) {
                    HostBridge::info(&format!(
                        "[bofmeta-rs] attempt {} success {} {} => {}",
                        idx + 1,
                        method,
                        url,
                        resp.status
                    ));
                    return Ok(resp);
                }
                last_error = format!("HTTP {}", resp.status);
                HostBridge::warn(&format!(
                    "[bofmeta-rs] attempt {} got {} for {} {}",
                    idx + 1,
                    resp.status,
                    method,
                    url
                ));
            }
            Err(e) => {
                HostBridge::warn(&format!(
                    "[bofmeta-rs] attempt {} failed for {} {}: {}",
                    idx + 1,
                    method,
                    url,
                    e
                ));
                last_error = e;
            }
        }
    }
    Err(last_error)
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<HttpRawResponse, String> {
    if method.eq_ignore_ascii_case("GET") {
        let mut current = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            let resp = http_request_once(method, &current, headers, body)?;
            if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                let parsed = parse_url(&current)?;
                let Some(location) = header_value(&resp.headers, "Location") else {
                    return Ok(resp);
                };
                current = resolve_redirect_url(&parsed, location)?;
                continue;
            }
            return Ok(resp);
        }
        Err(format!("too many redirects while requesting {url}"))
    } else {
        http_request_once(method, url, headers, body)
    }
}

fn http_request_once(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<HttpRawResponse, String> {
    let parsed = parse_url(url)?;
    if !parsed.scheme.eq_ignore_ascii_case("https") {
        return Err(format!("unsupported URL scheme: {}", parsed.scheme));
    }
    HostBridge::info(&format!(
        "[bofmeta-rs] connect {}:{}",
        parsed.host, parsed.port
    ));

    let mut stream = connect_tls_stream(&parsed.host, parsed.port)?;
    HostBridge::info(&format!(
        "[bofmeta-rs] connected tls {}:{}",
        parsed.host, parsed.port
    ));
    let mut req = String::new();
    req.push_str(&format!(
        "{} {} HTTP/1.1\r\n",
        method.to_ascii_uppercase(),
        parsed.path_and_query
    ));
    if parsed.port == 443 {
        req.push_str(&format!("Host: {}\r\n", parsed.host));
    } else {
        req.push_str(&format!("Host: {}:{}\r\n", parsed.host, parsed.port));
    }
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");

    let mut has_content_type = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }

    if let Some(data) = body {
        if !has_content_type {
            req.push_str("Content-Type: application/json\r\n");
        }
        req.push_str(&format!("Content-Length: {}\r\n", data.len()));
    }

    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .and_then(|_| {
            if let Some(data) = body {
                stream.write_all(data)
            } else {
                Ok(())
            }
        })
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;
    HostBridge::info(&format!("[bofmeta-rs] request sent {} {}", method, url));

    HostBridge::info(&format!("[bofmeta-rs] waiting response {} {}", method, url));
    let (status, response_headers, body) = read_http_response(&mut stream)?;
    HostBridge::info(&format!(
        "[bofmeta-rs] response received {} {} status={} bytes={}",
        method,
        url,
        status,
        body.len()
    ));
    Ok(HttpRawResponse {
        status,
        headers: response_headers,
        body,
    })
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
