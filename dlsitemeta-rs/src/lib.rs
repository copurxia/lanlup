use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::slice;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wasmedge_host")]
extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32) -> i32;
    fn host_progress(percent: i32, ptr: i32, len: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 { 0 }
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 { 0 }

thread_local! {
    static STATE: RefCell<PluginState> = RefCell::new(PluginState::default());
    static SET_PROXY: RefCell<Option<String>> = const { RefCell::new(None) };
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
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

struct HostBridge;
impl HostBridge {
    fn log(level: i32, message: &str) {
        unsafe { host_log(level, message.as_ptr() as i32, message.len() as i32); }
    }

    fn progress(percent: i32, message: &str) {
        unsafe { host_progress(percent, message.as_ptr() as i32, message.len() as i32); }
    }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_alloc(size: i32) -> i32 {
    if size <= 0 { return 0; }
    let layout = Layout::from_size_align(size as usize, 4).unwrap_or(Layout::new::<u8>());
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_free(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 { return; }
    let layout = Layout::from_size_align(size as usize, 4).unwrap_or(Layout::new::<u8>());
    unsafe { dealloc(ptr as *mut u8, layout); }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info() -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.info.is_empty() {
            state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
        }
        state.info.as_ptr() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info_len() -> i32 {
    STATE.with(|state| state.borrow().info.len() as i32)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_run(input_ptr: i32, input_len: i32) -> i32 {
    clear_runtime_buffers();
    let input_bytes = unsafe { read_guest_bytes(input_ptr, input_len) };
    let input: PluginInput = match serde_json::from_slice(input_bytes) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("Failed to parse input: {}", e)),
    };
    let payload = build_result_payload(input);
    STATE.with(|state| {
        let mut s = state.borrow_mut();
        s.result = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    });
    STATE.with(|state| state.borrow().result.as_ptr() as i32)
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
    if ptr == 0 || len <= 0 { &[] }
    else { unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) } }
}

fn plugin_info_json() -> Value {
    json!({
        "name": "DLsite",
        "type": "metadata",
        "namespace": "dlsitemeta",
        "author": "copur",
        "version": "0.1.0",
        "description": "Fetches metadata (title, circle, voice actor, tracks) from DLsite work pages.",
        "parameters": [
            {"name": "merge_existing", "type": "bool", "desc": "Merge extracted tags with existing metadata.tags", "default_value": "1"},
            {"name": "include_circle_tag", "type": "bool", "desc": "Add circle:<name> tag", "default_value": "1"},
            {"name": "include_va_tag", "type": "bool", "desc": "Add voice_actor:<name> tag", "default_value": "1"},
            {"name": "proxy", "type": "string", "desc": "HTTPS proxy address (e.g. http://192.168.0.112:7890). If empty, uses HTTPS_PROXY env var.", "default_value": ""}
        ],
        "oneshot_arg": "DLsite work URL or product ID (e.g. RJ01498492 or https://www.dlsite.com/maniax/work/=/product_id/RJ01498492.html)",
        "cooldown": 2,
        "permissions": [
            "metadata.read_input",
            "net=www.dlsite.com",
            "tcp.connect",
            "log.write",
            "progress.report",
            "fs.write"
        ],
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Dlsite.ts"
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    HostBridge::progress(5, "Initializing...");

    let mut metadata = ensure_metadata_object(input.metadata);
    let existing_tags = metadata_tags_to_csv(&metadata);

    let merge_existing = read_bool_param(&input.params, "merge_existing", true);
    let include_circle = read_bool_param(&input.params, "include_circle_tag", true);
    let include_va = read_bool_param(&input.params, "include_va_tag", true);
    let configured_proxy = read_string_param(&input.params, "proxy", "");

    if !configured_proxy.is_empty() {
        SET_PROXY.with(|p| *p.borrow_mut() = Some(configured_proxy));
    }

    let title = metadata.get("title")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();

    HostBridge::progress(15, "Identifying product...");

    let rj_id = extract_rj_id(&input.oneshot_param)
        .or_else(|| extract_rj_from_tags(&existing_tags))
        .or_else(|| extract_rj_id(&title))
        .ok_or_else(|| "Could not identify DLsite product ID. Provide an RJ number (e.g. RJ01498492) or URL.".to_string())?;

    HostBridge::progress(30, &format!("Fetching product RJ{}...", &rj_id));

    let url = format!("https://www.dlsite.com/maniax/work/=/product_id/RJ{}.html", rj_id);
    let page_html = fetch_dlsite_page(&url)?;

    HostBridge::progress(60, "Parsing metadata...");

    let parsed = parse_dlsite_html(&page_html)?;

    let new_tags_csv = build_tags_csv(&parsed, &rj_id, include_circle, include_va);

    let mut final_tags_csv = if merge_existing {
        merge_csv_tags(&existing_tags, &new_tags_csv)
    } else {
        new_tags_csv.clone()
    };

    final_tags_csv = dedupe_csv(&final_tags_csv);

    metadata.insert("title".to_string(), Value::String(parsed.title.clone()));
    metadata.insert("description".to_string(), Value::String(parsed.description));

    let source_url = format!("https://www.dlsite.com/maniax/work/=/product_id/RJ{}.html", rj_id);
    metadata.insert("source_url".to_string(), Value::String(source_url));

    if !parsed.release_date.is_empty() {
        metadata.insert("updated_at".to_string(), Value::String(parsed.release_date.clone()));
    }

    let tags_value = if final_tags_csv.is_empty() {
        Value::Array(vec![])
    } else {
        metadata_tags_from_csv(&final_tags_csv)
    };
    metadata.insert("tags".to_string(), tags_value);

    let cover_path = if let Some(cover_url) = &parsed.cover_url {
        HostBridge::progress(75, "Downloading cover...");
        match download_cover(cover_url) {
            Ok(path) => {
                let assets = metadata_set_asset_value(
                    metadata.get("assets").cloned(),
                    "cover",
                    &path,
                );
                metadata.insert("assets".to_string(), assets);
                Some(path)
            }
            Err(e) => {
                HostBridge::log(1, &format!("Cover download failed: {}", e));
                None
            }
        }
    } else {
        None
    };

    if !parsed.tracks.is_empty() {
        let pages: Vec<Value> = parsed.tracks.iter().enumerate().map(|(i, track)| {
            let mut page = json!({
                "page_number": i + 1,
                "entry_path": format!("{}.wav", i + 1),
                "title": track.title,
                "description": track.duration
            });
            if let Some(ref cp) = cover_path {
                page["thumb"] = json!(cp);
            }
            page
        }).collect();
        metadata.insert("pages".to_string(), Value::Array(pages));
    }

    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "Metadata fetched");
    Ok(Value::Object(metadata))
}

fn extract_rj_id(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() { return None; }

    let re = Regex::new(r"RJ(\d+)").ok()?;
    if let Some(cap) = re.captures(input) {
        return Some(cap.get(1)?.as_str().to_string());
    }

    if let Ok(n) = input.parse::<u64>() {
        return Some(n.to_string());
    }

    None
}

fn extract_rj_from_tags(csv_tags: &str) -> Option<String> {
    let re = Regex::new(r"(?:^|,)dlsite:RJ(\d+)(?:,|$)").ok()?;
    if let Some(cap) = re.captures(csv_tags) {
        return Some(cap.get(1)?.as_str().to_string());
    }
    let re2 = Regex::new(r"(?:^|,)source:dlsite:RJ(\d+)(?:,|$)").ok()?;
    if let Some(cap) = re2.captures(csv_tags) {
        return Some(cap.get(1)?.as_str().to_string());
    }
    None
}

#[derive(Debug, Default)]
struct DlsiteMetadata {
    title: String,
    circle: String,
    voice_actor: String,
    scenario: String,
    illust: String,
    music: String,
    release_date: String,
    genres: Vec<String>,
    tracks: Vec<TrackInfo>,
    description: String,
    file_size: String,
    total_time: String,
    cover_url: Option<String>,
}

#[derive(Debug)]
struct TrackInfo {
    number: i32,
    title: String,
    duration: String,
}

fn parse_dlsite_html(html: &str) -> Result<DlsiteMetadata, String> {
    let mut meta = DlsiteMetadata::default();

    meta.title = extract_title(html);
    meta.circle = extract_circle(html);
    meta.voice_actor = extract_staff(html, "声優");
    meta.scenario = extract_staff(html, "シナリオ");
    meta.illust = extract_staff(html, "イラスト");
    meta.music = extract_staff(html, "音楽");
    meta.release_date = extract_release_date(html);
    meta.genres = extract_genres(html);
    meta.tracks = extract_tracks(html);
    meta.file_size = extract_field_value(html, "ファイル容量");
    meta.total_time = extract_total_time(html);
    meta.cover_url = extract_cover_url(html);
    meta.description = build_description(&meta, html);

    Ok(meta)
}

fn extract_title(html: &str) -> String {
    let re = Regex::new(r#"(?i)<h1[^>]*(?:id="work_name"|class="[^"]*product_title[^"]*")[^>]*>([\s\S]*?)</h1>"#).ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            let inner = cap.get(1).unwrap().as_str();
            let cleaned = Regex::new(r"<[^>]+>").ok()
                .map(|tag_re| tag_re.replace_all(inner, "").to_string())
                .unwrap_or_else(|| inner.to_string());
            return cleaned.trim().to_string();
        }
    }

    let re2 = Regex::new(r"<title>([^<]+)</title>").ok();
    if let Some(re2) = re2 {
        if let Some(cap) = re2.captures(html) {
            let t = cap.get(1).unwrap().as_str();
            if let Some(pos) = t.find('|') {
                return t[..pos].trim().to_string();
            }
            return t.trim().to_string();
        }
    }

    String::new()
}

fn extract_circle(html: &str) -> String {
    let re = Regex::new(r"サークル名[\s\S]{0,300}?<a[^>]*>([^<]+)</a>").ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            return cap.get(1).unwrap().as_str().trim().to_string();
        }
    }
    String::new()
}

fn extract_staff(html: &str, role: &str) -> String {
    let escaped = regex::escape(role);
    let pattern = format!(r"<th[^>]*>{}[\s\S]{{0,5}}?</th>[\s\S]{{0,300}}?<a[^>]*>([^<]+)</a>", escaped);
    let re = Regex::new(&pattern).ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            return cap.get(1).unwrap().as_str().trim().to_string();
        }
    }
    String::new()
}

fn extract_release_date(html: &str) -> String {
    let re = Regex::new(r"販売日[\s\S]{0,100}?(\d{4})年(\d{1,2})月(\d{1,2})日").ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            let y = cap.get(1).unwrap().as_str();
            let m = format!("{:0>2}", cap.get(2).unwrap().as_str());
            let d = format!("{:0>2}", cap.get(3).unwrap().as_str());
            return format!("{}-{}-{}", y, m, d);
        }
    }
    String::new()
}

fn extract_genres(html: &str) -> Vec<String> {
    let re = Regex::new(r#"class="work_genre_item"[^>]*>([^<]+)</a>"#).ok();
    if let Some(re) = re {
        let genres: Vec<String> = re.captures_iter(html)
            .map(|cap| cap.get(1).unwrap().as_str().trim().to_string())
            .filter(|g| !g.is_empty())
            .collect();
        if !genres.is_empty() { return genres; }
    }

    let re2 = Regex::new(r#"<a[^>]*href="[^"]*genre[^"]*"[^>]*>([^<]+)</a>"#).ok();
    if let Some(re2) = re2 {
        let mut seen = std::collections::HashSet::new();
        let genres: Vec<String> = re2.captures_iter(html)
            .map(|cap| cap.get(1).unwrap().as_str().trim().to_string())
            .filter(|g| !g.is_empty() && !g.contains("genre") && g.len() <= 30)
            .filter(|g| seen.insert(g.clone()))
            .collect();
        if !genres.is_empty() { return genres; }
    }

    vec![]
}

fn extract_tracks(html: &str) -> Vec<TrackInfo> {
    let re = Regex::new(r"トラック(\d+)\s*[　\s]+([^(]+)\((\d+):(\d+)\)").ok();
    let mut tracks = vec![];
    if let Some(re) = re {
        for cap in re.captures_iter(html) {
            let num: i32 = cap.get(1).unwrap().as_str().parse().unwrap_or(0);
            let title = cap.get(2).unwrap().as_str().trim().to_string();
            let mins = cap.get(3).unwrap().as_str();
            let secs = cap.get(4).unwrap().as_str();
            let duration = format!("{}:{}", mins, secs);
            tracks.push(TrackInfo { number: num, title, duration });
        }
    }
    tracks.sort_by_key(|t| t.number);
    tracks
}

fn extract_field_value(html: &str, field: &str) -> String {
    let escaped = regex::escape(field);
    let pattern = format!(r"{}[\s\S]{{0,100}}?([\d.]+[GMk]B)", escaped);
    let re = Regex::new(&pattern).ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            return cap.get(1).unwrap().as_str().to_string();
        }
    }
    String::new()
}

fn extract_total_time(html: &str) -> String {
    let re = Regex::new(r"総再生時間[\s\S]{0,100}?(\d+分\d+秒)").ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            return cap.get(1).unwrap().as_str().to_string();
        }
    }
    String::new()
}

fn extract_cover_url(html: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)<img[^>]*class="[^"]*slider_image[^"]*"[^>]*src="([^"]+)"#).ok();
    if let Some(re) = re {
        if let Some(cap) = re.captures(html) {
            let url = cap.get(1).unwrap().as_str();
            if url.starts_with("http") {
                return Some(url.to_string());
            }
            if url.starts_with("//") {
                return Some(format!("https:{}", url));
            }
        }
    }

    let re2 = Regex::new(r#"(?i)<img[^>]*class="[^"]*product_slider[^"]*"[^>]*src="([^"]+)"#).ok();
    if let Some(re2) = re2 {
        if let Some(cap) = re2.captures(html) {
            let url = cap.get(1).unwrap().as_str();
            if url.starts_with("http") {
                return Some(url.to_string());
            }
            if url.starts_with("//") {
                return Some(format!("https:{}", url));
            }
        }
    }
    None
}

fn build_description(meta: &DlsiteMetadata, html: &str) -> String {
    let mut parts: Vec<String> = vec![];

    if !meta.circle.is_empty() {
        parts.push(format!("サークル: {}", meta.circle));
    }
    if !meta.voice_actor.is_empty() {
        parts.push(format!("声優: {}", meta.voice_actor));
    }
    if !meta.scenario.is_empty() {
        parts.push(format!("シナリオ: {}", meta.scenario));
    }
    if !meta.illust.is_empty() {
        parts.push(format!("イラスト: {}", meta.illust));
    }
    if !meta.music.is_empty() {
        parts.push(format!("音楽: {}", meta.music));
    }
    if !meta.release_date.is_empty() {
        parts.push(format!("販売日: {}", meta.release_date));
    }
    if !meta.file_size.is_empty() {
        parts.push(format!("ファイル容量: {}", meta.file_size));
    }
    if !meta.total_time.is_empty() {
        parts.push(format!("総再生時間: {}", meta.total_time));
    }

    let concept = extract_section_text(html, "コンセプト");
    let story = extract_section_text(html, "ストーリー");

    if let Some(concept) = concept {
        if !concept.is_empty() {
            parts.push(format!("\n【コンセプト】\n{}", concept));
        }
    }
    if let Some(story) = story {
        if !story.is_empty() {
            parts.push(format!("\n【ストーリー】\n{}", story));
        }
    }

    if !meta.tracks.is_empty() {
        let mut track_lines: Vec<String> = vec!["【トラックリスト】".to_string()];
        for track in &meta.tracks {
            track_lines.push(format!("トラック{} {} ({})", track.number, track.title, track.duration));
        }
        parts.push(track_lines.join("\n"));
    }

    parts.join("\n")
}

fn extract_section_text(html: &str, section: &str) -> Option<String> {
    let escaped = regex::escape(section);
    let pattern = format!(r"{}[\s\S]{{0,1500}}?<p[^>]*>([\s\S]*?)</p>", escaped);
    let re = Regex::new(&pattern).ok()?;
    if let Some(cap) = re.captures(html) {
        let content = cap.get(1).unwrap().as_str();
        let cleaned = Regex::new(r"<[^>]+>").ok()
            .map(|tag_re| tag_re.replace_all(content, ""))
            .unwrap_or_else(|| content.into());
        let cleaned = cleaned.replace("&amp;", "&");
        let trimmed = cleaned.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

fn build_tags_csv(meta: &DlsiteMetadata, rj_id: &str, include_circle: bool, include_va: bool) -> String {
    let mut tags: Vec<String> = vec![];

    tags.push(format!("source:dlsite:RJ{}", rj_id));
    tags.push(format!("dlsite:RJ{}", rj_id));

    if include_circle && !meta.circle.is_empty() {
        tags.push(format!("circle:{}", meta.circle));
    }

    if include_va && !meta.voice_actor.is_empty() {
        tags.push(format!("voice_actor:{}", meta.voice_actor));
    }

    if !meta.scenario.is_empty() {
        tags.push(format!("scenario:{}", meta.scenario));
    }

    if !meta.illust.is_empty() {
        tags.push(format!("artist:{}", meta.illust));
    }

    if !meta.music.is_empty() {
        tags.push(format!("music:{}", meta.music));
    }

    for genre in &meta.genres {
        tags.push(format!("genre:{}", genre));
    }

    tags.join(",")
}

fn read_bool_param(params: &Value, name: &str, default: bool) -> bool {
    params.get(name)
        .and_then(|v| {
            if let Some(b) = v.as_bool() { Some(b) }
            else if let Some(s) = v.as_str() { Some(s == "1" || s == "true" || s == "yes") }
            else if let Some(n) = v.as_i64() { Some(n != 0) }
            else { None }
        })
        .unwrap_or(default)
}

fn read_string_param(params: &Value, name: &str, default: &str) -> String {
    params.get(name)
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| default.to_string())
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn metadata_tags_to_csv(metadata: &Map<String, Value>) -> String {
    metadata.get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn metadata_tags_from_csv(csv: &str) -> Value {
    if csv.is_empty() { return Value::Array(vec![]); }
    let tags: Vec<Value> = csv.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| Value::String(s.trim().to_string()))
        .collect();
    Value::Array(tags)
}

fn split_csv_tags(csv: &str) -> Vec<String> {
    csv.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

fn dedupe_csv(csv: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    split_csv_tags(csv).into_iter()
        .filter(|tag| seen.insert(tag.clone()))
        .collect::<Vec<_>>()
        .join(",")
}

fn merge_csv_tags(a: &str, b: &str) -> String {
    if a.is_empty() { return b.to_string(); }
    if b.is_empty() { return a.to_string(); }
    format!("{},{}", a, b)
}

fn metadata_set_asset_value(existing: Option<Value>, key: &str, value: &str) -> Value {
    let mut assets: Vec<Value> = match existing {
        Some(Value::Array(arr)) => arr,
        _ => vec![],
    };

    let new_asset = json!({"key": key, "value": value});

    let pos = assets.iter().position(|a| {
        a.get("key").and_then(|k| k.as_str()) == Some(key)
    });

    match pos {
        Some(i) => assets[i] = new_asset,
        None => assets.push(new_asset),
    }

    Value::Array(assets)
}

fn fetch_dlsite_page(url: &str) -> Result<String, String> {
    let parsed = parse_url(url)?;
    let host = parsed.host.clone();
    let port = parsed.port;

    let max_retries = 3;
    let mut last_err = String::new();
    for attempt in 1..=max_retries {
        if attempt > 1 {
            HostBridge::log(1, &format!("Retry {}/{} for DLsite page...", attempt, max_retries));
        }
        HostBridge::progress(35, &format!("Connecting to {} (try {})...", host, attempt));

        match fetch_dlsite_page_once(&parsed, &host, port) {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = e;
                if attempt < max_retries {
                    HostBridge::log(1, &format!("Attempt failed: {}, retrying...", last_err));
                }
            }
        }
    }
    Err(format!("Failed after {} retries: {}", max_retries, last_err))
}

fn fetch_dlsite_page_once(parsed: &ParsedUrl, host: &str, port: u16) -> Result<String, String> {
    let mut stream = connect_tls_stream(&host, port)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja-JP,ja;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n",
        parsed.path_and_query, host
    );

    stream.write_all(request.as_bytes()).map_err(|e| format!("Failed to send request: {}", e))?;
    stream.flush().map_err(|e| format!("Failed to flush: {}", e))?;

    let response = read_http_response(&mut stream)?;

    if response.status_code == 200 || response.status_code == 302 || response.status_code == 301 {
        let body_str = String::from_utf8_lossy(&response.body).to_string();
        Ok(body_str)
    } else {
        Err(format!("HTTP {}: {}", response.status_code, String::from_utf8_lossy(&response.body).chars().take(200).collect::<String>()))
    }
}

fn download_cover(url: &str) -> Result<String, String> {
    let parsed = parse_url(url)?;
    let host = parsed.host.clone();
    let port = parsed.port;

    let mut stream = connect_tls_stream(&host, port)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8\r\nAccept-Language: ja-JP,ja;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n",
        parsed.path_and_query, host
    );

    stream.write_all(request.as_bytes()).map_err(|e| format!("Cover request failed: {}", e))?;
    stream.flush().map_err(|e| format!("Cover flush failed: {}", e))?;

    let response = read_http_response(&mut stream)?;

    if response.status_code != 200 {
        return Err(format!("Cover HTTP {}: {}", response.status_code, String::from_utf8_lossy(&response.body).chars().take(100).collect::<String>()));
    }

    let data = &response.body;
    if data.len() < 100 {
        return Err("Cover too small".to_string());
    }

    let ext = detect_image_extension(data);
    let filename = format!("cover.{}", ext);
    let save_path = std::path::Path::new("/plugin").join(&filename);

    if let Some(parent) = save_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&save_path, data).map_err(|e| format!("Failed to save cover: {}", e))?;

    Ok(filename)
}

fn detect_image_extension(data: &[u8]) -> &'static str {
    if data.len() > 2 && data[0] == 0xFF && data[1] == 0xD8 { "jpg" }
    else if data.len() > 8 {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if data[..8] == png { "png" }
        else if data.len() > 4 {
            let webp = *b"WEBP";
            if data[0] == 0x52 && data[4..8] == webp { "webp" }
            else { "jpg" }
        } else { "jpg" }
    } else { "jpg" }
}

#[allow(dead_code)]
struct HttpRawResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let rest = if let Some(s) = url.strip_prefix("https://") { s }
    else if let Some(s) = url.strip_prefix("http://") { s }
    else { return Err("URL must start with http:// or https://".to_string()); };

    let (host_part, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "/")
    };

    let (host, port) = if let Some(pos) = host_part.find(':') {
        let p: u16 = host_part[pos+1..].parse().map_err(|_| "Invalid port".to_string())?;
        (&host_part[..pos], p)
    } else {
        (host_part, 443)
    };

    Ok(ParsedUrl {
        scheme: "https".to_string(),
        host: host.to_string(),
        port,
        path_and_query: path.to_string(),
    })
}

const DEFAULT_TIMEOUT_MS: i32 = 30_000;

use std::io::{self, Read, Write};
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("This plugin requires the wasm32-wasip1 target (target_os = \"wasi\")");

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
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
    stream: std::net::TcpStream,
}

#[cfg(not(target_arch = "wasm32"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", host, port);
        let sock_addrs = addr.to_socket_addrs().map_err(|e| format!("DNS: {}", e))?;
        let addr = sock_addrs.as_slice().first().ok_or("No address resolved")?.to_owned();
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
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

fn connect_tls_stream(host: &str, port: u16) -> Result<HttpStream, String> {
    let tcp = if let Some((proxy_host, proxy_port)) = resolve_proxy_for_https() {
        let mut proxy = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
        establish_proxy_connect_tunnel(&mut proxy, host, port)?;
        proxy
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
    };

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name: ServerName = host.to_string().try_into()
        .map_err(|_| format!("invalid dns name: {host}"))?;
    let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
    Ok(HttpStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
}

fn resolve_proxy_for_https() -> Option<(String, u16)> {
    let configured = SET_PROXY.with(|p| p.borrow().clone());
    if let Some(proxy) = configured {
        if !proxy.is_empty() {
            if let Some(v) = parse_proxy_endpoint(&proxy) {
                return Some(v);
            }
        }
    }

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
    if s.is_empty() { return None; }
    if let Some((_, right)) = s.split_once("://") { s = right; }
    if let Some((left, _)) = s.split_once('/') { s = left; }
    if let Some((_, right)) = s.rsplit_once('@') { s = right; }
    if s.is_empty() { return None; }
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = &s[1..end];
        let tail = &s[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>().ok().unwrap_or(8080)
        } else { 8080 };
        if host.is_empty() { return None; }
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
    stream.write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 1024];
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

fn read_http_response(stream: &mut HttpStream) -> Result<HttpRawResponse, String> {
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        let n = read_stream(stream, &mut chunk)?;
        if n == 0 {
            return Err("connection closed before response headers".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("response headers too large".to_string());
        }
    };

    let (status_code, headers) = parse_response_headers(&buf[..header_end])?;
    let pending = buf[header_end..].to_vec();

    let cl = header_value(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok());

    let body = if is_chunked_transfer_encoding(&headers) {
        let mut raw = pending;
        loop {
            let n = read_stream(stream, &mut chunk)?;
            if n == 0 { break; }
            raw.extend_from_slice(&chunk[..n]);
        }
        decode_chunked_body(&raw)?
    } else if let Some(len) = cl {
        let mut body = pending;
        let remaining = len.saturating_sub(body.len());
        if remaining > 0 {
            let mut buf = vec![0u8; remaining];
            let mut pos = 0;
            while pos < remaining {
                let n = read_stream(stream, &mut buf[pos..])?;
                if n == 0 { return Err("connection closed before body complete".to_string()); }
                pos += n;
            }
            body.extend_from_slice(&buf);
        }
        body
    } else {
        let mut body = pending;
        loop {
            let n = read_stream(stream, &mut chunk)?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
        }
        body
    };

    Ok(HttpRawResponse { status_code, headers, body })
}

fn read_stream(stream: &mut HttpStream, buf: &mut [u8]) -> Result<usize, String> {
    match stream.read(buf) {
        Ok(n) => Ok(n),
        Err(e) => {
            if is_tls_close_notify_eof(&e) {
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

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn parse_response_headers(raw: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let header_str = String::from_utf8_lossy(raw);
    let mut lines = header_str.lines();

    let status_line = lines.next().ok_or("Empty response")?;
    let status_code = status_line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid status line: {}", status_line))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_string();
            let value = line[pos+1..].trim().to_string();
            headers.push((key, value));
        }
    }

    Ok((status_code, headers))
}

fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn is_chunked_transfer_encoding(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding")
        && v.to_lowercase().contains("chunked")
    })
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut pending = raw.to_vec();
    let mut out = Vec::new();
    loop {
        let line = extract_line_crlf(&mut pending)
            .ok_or_else(|| "truncated chunked body: missing size line".to_string())?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() {
            continue;
        }
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
    let pos = pending.windows(2).position(|v| v == b"\r\n")?;
    let line = String::from_utf8_lossy(&pending[..pos]).to_string();
    pending.drain(..pos + 2);
    Some(line)
}
