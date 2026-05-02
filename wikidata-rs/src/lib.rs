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
compile_error!("wikidata-rs requires wasm32-wasip1 (target_os = \"wasi\")");

const USER_AGENT: &str = "lanlu-wikidata-metadata/0.1 (https://github.com/copur/lanlu)";
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
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(rename = "pluginDir", default)]
    plugin_dir: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct SearchResponse {
    #[serde(default)]
    search: Vec<SearchHit>,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct SearchHit {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Default, Deserialize)]
struct EntitiesResponse {
    #[serde(default)]
    entities: Map<String, Value>,
}

#[derive(Debug, Default, Clone)]
struct EntitySummary {
    id: String,
    label: String,
    description: String,
    aliases: Vec<String>,
    image_file: String,
    official_site: String,
    musicbrainz_artist_id: String,
    musicbrainz_release_group_id: String,
    discogs_artist_id: String,
    viaf_id: String,
    isni_id: String,
    spotify_artist_id: String,
    apple_music_artist_id: String,
    youtube_channel_id: String,
    inception: String,
    birth_date: String,
    death_date: String,
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
        "name": "Wikidata",
        "type": "metadata",
        "namespace": "wikidata",
        "author": "codex",
        "version": "0.1.0",
        "description": "Fetches artist and creator entity metadata from Wikidata.",
        "parameters": [
            {"name": "language", "type": "string", "desc": "Preferred Wikidata language code.", "default_value": "zh"},
            {"name": "fallback_language", "type": "string", "desc": "Fallback Wikidata language code.", "default_value": "en"},
            {"name": "search_limit", "type": "int", "desc": "Search candidate limit (1-20).", "default_value": "8"},
            {"name": "merge_existing_tags", "type": "bool", "desc": "Merge existing metadata tags into the result.", "default_value": "1"},
            {"name": "cache_image", "type": "bool", "desc": "Download Commons image into plugin cache.", "default_value": "1"}
        ],
        "oneshot_arg": "Wikidata QID, Wikidata URL, or artist/creator search keyword",
        "cooldown": 1,
        "permissions": [
            "metadata.read_input",
            "net=www.wikidata.org",
            "net=commons.wikimedia.org",
            "net=upload.wikimedia.org",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "runtime": "wamr",
        "abi_version": 1
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(v) => json!({"success": true, "data": v}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    if !input.plugin_type.trim().eq_ignore_ascii_case("metadata") {
        return Err("wikidata-rs only supports Metadata plugins".to_string());
    }

    HostBridge::progress(5, "准备 Wikidata 查询...");
    let language = normalize_language(&read_string_param(&input.params, "language", "zh"));
    let fallback_language =
        normalize_language(&read_string_param(&input.params, "fallback_language", "en"));
    let search_limit = clamp_i64(read_i64_param(&input.params, "search_limit", 8), 1, 20);
    let merge_existing_tags = read_bool_param(&input.params, "merge_existing_tags", true);
    let cache_image = read_bool_param(&input.params, "cache_image", true);

    let mut metadata = ensure_metadata_object(input.metadata);
    let existing_title = metadata_string(&metadata, "title");
    let existing_tags = metadata_tags(&metadata);
    let qid = extract_qid(&input.oneshot_param)
        .or_else(|| extract_qid_from_tags(&existing_tags))
        .or_else(|| {
            search_entity_id(
                &collect_search_keywords(
                    &input.oneshot_param,
                    &existing_title,
                    &existing_tags,
                    &input.target_type,
                ),
                &language,
                &fallback_language,
                search_limit,
            )
        });

    let Some(qid) = qid else {
        return Err(
            "No Wikidata entity found. Provide a QID/URL or a searchable artist name.".to_string(),
        );
    };

    HostBridge::progress(35, "读取 Wikidata 实体...");
    let entity = fetch_entity_summary(&qid, &language, &fallback_language)?;

    HostBridge::progress(75, "合并 Wikidata 元数据...");
    if !entity.label.is_empty() {
        metadata.insert("title".to_string(), Value::String(entity.label.clone()));
    }

    let description = build_description(&entity);
    if !description.is_empty() {
        metadata.insert("description".to_string(), Value::String(description));
    }

    let mut tags = if merge_existing_tags {
        existing_tags
    } else {
        Vec::new()
    };
    tags.extend(build_entity_tags(&entity));
    metadata.insert("tags".to_string(), json!(dedupe_strings(tags)));

    let image_url = commons_file_url(&entity.image_file, 900);
    let cover = if cache_image {
        cache_cover_for_result(&image_url, &entity.id, &input.plugin_dir, "wikidata")
    } else {
        String::new()
    };
    if !cover.is_empty() {
        metadata.insert(
            "assets".to_string(),
            metadata_set_asset_value(metadata.get("assets").cloned(), "cover", &cover),
        );
    }

    metadata.insert(
        "source_url".to_string(),
        Value::String(entity.source_url.clone()),
    );
    metadata.remove("archive");
    metadata.remove("archive_id");
    HostBridge::progress(100, "Wikidata 元数据完成");
    Ok(Value::Object(metadata))
}

fn collect_search_keywords(
    oneshot: &str,
    title: &str,
    tags: &[String],
    target_type: &str,
) -> Vec<String> {
    let mut out = Vec::<String>::new();
    let oneshot = oneshot.trim();
    if !oneshot.is_empty() && extract_qid(oneshot).is_none() {
        out.push(oneshot.to_string());
    }
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        for prefix in ["artist:", "creator:", "author:", "composer:"] {
            if lower.starts_with(prefix) {
                let v = tag[prefix.len()..].trim();
                if !v.is_empty() {
                    out.push(v.to_string());
                }
            }
        }
    }
    if target_type.trim().eq_ignore_ascii_case("tankoubon") && !title.trim().is_empty() {
        out.push(title.trim().to_string());
    }
    if out.is_empty() && !title.trim().is_empty() {
        out.push(title.trim().to_string());
    }
    dedupe_strings(out)
}

fn search_entity_id(
    keywords: &[String],
    language: &str,
    fallback_language: &str,
    limit: i64,
) -> Option<String> {
    for keyword in keywords {
        for lang in dedupe_strings(vec![language.to_string(), fallback_language.to_string()]) {
            HostBridge::progress(15, &format!("搜索 Wikidata: {keyword}"));
            match search_entities(keyword, &lang, limit) {
                Ok(items) => {
                    if let Some(best) = choose_search_hit(keyword, &items) {
                        return Some(best.id);
                    }
                }
                Err(err) => HostBridge::log(1, &format!("wikidata search failed: {err}")),
            }
        }
    }
    None
}

fn search_entities(keyword: &str, language: &str, limit: i64) -> Result<Vec<SearchHit>, String> {
    let url = format!(
        "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&type=item&language={}&uselang={}&limit={}&search={}",
        urlencoding::encode(language),
        urlencoding::encode(language),
        limit,
        urlencoding::encode(keyword)
    );
    let response = get_json(&url)?;
    let parsed: SearchResponse = serde_json::from_value(response)
        .map_err(|e| format!("invalid Wikidata search response: {e}"))?;
    Ok(parsed.search)
}

fn choose_search_hit(keyword: &str, items: &[SearchHit]) -> Option<SearchHit> {
    let normalized_keyword = normalize_for_match(keyword);
    let mut best: Option<(i32, SearchHit)> = None;
    for item in items {
        if item.id.trim().is_empty() {
            continue;
        }
        let label = normalize_for_match(&item.label);
        let description = item.description.to_ascii_lowercase();
        let mut score = 0;
        if label == normalized_keyword {
            score += 100;
        } else if label.contains(&normalized_keyword) || normalized_keyword.contains(&label) {
            score += 40;
        }
        if description.contains("singer")
            || description.contains("musician")
            || description.contains("composer")
            || description.contains("artist")
            || description.contains("band")
            || description.contains("歌手")
            || description.contains("音乐")
            || description.contains("作曲")
            || description.contains("乐队")
        {
            score += 25;
        }
        if score == 0 {
            score = 1;
        }
        match &best {
            Some((best_score, _)) if *best_score >= score => {}
            _ => best = Some((score, item.clone())),
        }
    }
    best.map(|(_, item)| item)
}

fn fetch_entity_summary(
    qid: &str,
    language: &str,
    fallback_language: &str,
) -> Result<EntitySummary, String> {
    let languages = dedupe_strings(vec![
        language.to_string(),
        fallback_language.to_string(),
        "en".to_string(),
        "zh".to_string(),
        "ja".to_string(),
    ])
    .join("|");
    let url = format!(
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&ids={}&props=labels|descriptions|aliases|claims|sitelinks&languages={}&languagefallback=1",
        urlencoding::encode(qid),
        urlencoding::encode(&languages)
    );
    let response = get_json(&url)?;
    let parsed: EntitiesResponse = serde_json::from_value(response)
        .map_err(|e| format!("invalid Wikidata entity response: {e}"))?;
    let entity = parsed
        .entities
        .get(qid)
        .ok_or_else(|| format!("Wikidata entity not found: {qid}"))?;

    let label = localized_text(
        entity.get("labels"),
        &[language, fallback_language, "en", "zh", "ja"],
    );
    let description = localized_text(
        entity.get("descriptions"),
        &[language, fallback_language, "en", "zh", "ja"],
    );
    let aliases = localized_aliases(
        entity.get("aliases"),
        &[language, fallback_language, "en", "zh", "ja"],
    );

    Ok(EntitySummary {
        id: qid.to_string(),
        label,
        description,
        aliases,
        image_file: claim_string(entity, "P18"),
        official_site: claim_string(entity, "P856"),
        musicbrainz_artist_id: claim_string(entity, "P434"),
        musicbrainz_release_group_id: claim_string(entity, "P436"),
        discogs_artist_id: claim_string(entity, "P1953"),
        viaf_id: claim_string(entity, "P214"),
        isni_id: claim_string(entity, "P213"),
        spotify_artist_id: claim_string(entity, "P1902"),
        apple_music_artist_id: claim_string(entity, "P2850"),
        youtube_channel_id: claim_string(entity, "P2397"),
        inception: claim_time(entity, "P571"),
        birth_date: claim_time(entity, "P569"),
        death_date: claim_time(entity, "P570"),
        source_url: format!("https://www.wikidata.org/wiki/{qid}"),
    })
}

fn localized_text(value: Option<&Value>, languages: &[&str]) -> String {
    let Some(obj) = value.and_then(Value::as_object) else {
        return String::new();
    };
    for lang in languages {
        if let Some(text) = obj
            .get(*lang)
            .and_then(|v| v.get("value"))
            .and_then(Value::as_str)
        {
            let clean = text.trim();
            if !clean.is_empty() {
                return clean.to_string();
            }
        }
    }
    String::new()
}

fn localized_aliases(value: Option<&Value>, languages: &[&str]) -> Vec<String> {
    let Some(obj) = value.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for lang in languages {
        if let Some(items) = obj.get(*lang).and_then(Value::as_array) {
            for item in items {
                if let Some(text) = item.get("value").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        out.push(text.trim().to_string());
                    }
                }
            }
        }
    }
    dedupe_strings(out)
}

fn claim_string(entity: &Value, property: &str) -> String {
    first_claim_value(entity, property)
        .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
        .unwrap_or_default()
}

fn claim_time(entity: &Value, property: &str) -> String {
    let raw = first_claim_value(entity, property)
        .and_then(|v| v.get("time"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    normalize_wikidata_time(raw)
}

fn first_claim_value<'a>(entity: &'a Value, property: &str) -> Option<&'a Value> {
    let claims = entity.get("claims")?.as_object()?;
    let items = claims.get(property)?.as_array()?;
    for item in items {
        let snak = item.get("mainsnak")?;
        if snak.get("snaktype").and_then(Value::as_str) != Some("value") {
            continue;
        }
        if let Some(v) = snak.get("datavalue").and_then(|v| v.get("value")) {
            return Some(v);
        }
    }
    None
}

fn build_description(entity: &EntitySummary) -> String {
    let mut lines = Vec::<String>::new();
    if !entity.description.trim().is_empty() {
        lines.push(entity.description.trim().to_string());
    }
    if !entity.aliases.is_empty() {
        lines.push(format!("Aliases: {}", entity.aliases.join(", ")));
    }
    if !entity.birth_date.is_empty() || !entity.death_date.is_empty() {
        let mut life = entity.birth_date.clone();
        if !entity.death_date.is_empty() {
            life.push_str(" - ");
            life.push_str(&entity.death_date);
        }
        lines.push(format!("Life: {life}"));
    } else if !entity.inception.is_empty() {
        lines.push(format!("Inception: {}", entity.inception));
    }
    if !entity.official_site.is_empty() {
        lines.push(format!("Official site: {}", entity.official_site));
    }
    lines.push(format!("Wikidata: {}", entity.source_url));
    lines.join("\n")
}

fn build_entity_tags(entity: &EntitySummary) -> Vec<String> {
    let mut tags = Vec::<String>::new();
    tags.push(format!("source:{}", entity.source_url));
    tags.push(format!("wikidata:{}", entity.id));
    if !entity.musicbrainz_artist_id.is_empty() {
        tags.push(format!(
            "musicbrainz_artist:{}",
            entity.musicbrainz_artist_id
        ));
    }
    if !entity.musicbrainz_release_group_id.is_empty() {
        tags.push(format!(
            "musicbrainz_release_group:{}",
            entity.musicbrainz_release_group_id
        ));
    }
    if !entity.discogs_artist_id.is_empty() {
        tags.push(format!("discogs_artist:{}", entity.discogs_artist_id));
    }
    if !entity.viaf_id.is_empty() {
        tags.push(format!("viaf:{}", entity.viaf_id));
    }
    if !entity.isni_id.is_empty() {
        tags.push(format!("isni:{}", entity.isni_id));
    }
    if !entity.spotify_artist_id.is_empty() {
        tags.push(format!("spotify_artist:{}", entity.spotify_artist_id));
    }
    if !entity.apple_music_artist_id.is_empty() {
        tags.push(format!(
            "apple_music_artist:{}",
            entity.apple_music_artist_id
        ));
    }
    if !entity.youtube_channel_id.is_empty() {
        tags.push(format!("youtube_channel:{}", entity.youtube_channel_id));
    }
    dedupe_strings(tags)
}

fn get_json(url: &str) -> Result<Value, String> {
    let headers = vec![
        ("user-agent".to_string(), USER_AGENT.to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    let resp = http_request_with_retry("GET", url, &headers, None)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {}", resp.status));
    }
    serde_json::from_slice::<Value>(&resp.body).map_err(|e| e.to_string())
}

fn commons_file_url(file_name: &str, width: i64) -> String {
    let clean = file_name.trim();
    if clean.is_empty() {
        return String::new();
    }
    format!(
        "https://commons.wikimedia.org/wiki/Special:FilePath/{}?width={}",
        urlencoding::encode(clean),
        width.max(1)
    )
}

fn cache_cover_for_result(image_url: &str, key: &str, plugin_dir: &str, namespace: &str) -> String {
    if image_url.trim().is_empty() || plugin_dir.trim().is_empty() || namespace.trim().is_empty() {
        return String::new();
    }

    let cache_dir = format!("{}/cache/covers", plugin_dir.trim_end_matches('/'));
    if fs::create_dir_all(&cache_dir).is_err() {
        return String::new();
    }

    let headers = vec![
        ("user-agent".to_string(), USER_AGENT.to_string()),
        ("accept".to_string(), "image/*,*/*;q=0.8".to_string()),
    ];
    let resp = match http_request_with_retry("GET", image_url, &headers, None) {
        Ok(v) => v,
        Err(err) => {
            HostBridge::log(1, &format!("wikidata image download failed: {err}"));
            return String::new();
        }
    };
    if !(200..300).contains(&resp.status) || resp.body.is_empty() {
        return String::new();
    }

    let content_type = header_value(&resp.headers, "content-type").unwrap_or("");
    let ext = detect_image_extension(image_url, content_type);
    let file_name = format!("{}.{}", sanitize_key(key), ext);
    let output = format!("{cache_dir}/{file_name}");
    if fs::write(&output, &resp.body).is_ok() {
        return format!("plugins/{namespace}/cache/covers/{file_name}");
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
    let clean = url
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");
    let ext = clean
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
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

fn extract_qid(value: &str) -> Option<String> {
    let re = Regex::new(r"(?i)\bQ[1-9][0-9]*\b").ok()?;
    re.find(value).map(|m| m.as_str().to_ascii_uppercase())
}

fn extract_qid_from_tags(tags: &[String]) -> Option<String> {
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        if lower.starts_with("wikidata:") || lower.starts_with("wikidata_id:") {
            if let Some(v) = extract_qid(tag) {
                return Some(v);
            }
        }
    }
    None
}

fn normalize_wikidata_time(raw: &str) -> String {
    let s = raw.trim().trim_start_matches('+');
    if s.len() >= 10 {
        return s[..10].to_string();
    }
    s.to_string()
}

fn normalize_language(value: &str) -> String {
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() {
        "en".to_string()
    } else {
        v
    }
}

fn normalize_for_match(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || !c.is_ascii())
        .collect::<String>()
}

fn sanitize_key(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    let re = Regex::new(r"[^a-z0-9._-]+")
        .ok()
        .map(|r| r.replace_all(&lower, "_").to_string())
        .unwrap_or(lower);
    let clean = re.trim_matches('_').to_string();
    if clean.is_empty() {
        "wikidata".to_string()
    } else {
        clean
    }
}

fn read_string_param(params: &Value, key: &str, default: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .trim()
        .to_string()
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

fn read_bool_param(params: &Value, key: &str, default: bool) -> bool {
    let Some(v) = params.get(key) else {
        return default;
    };
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
        Value::String(s) => matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => default,
    }
}

fn clamp_i64(v: i64, min: i64, max: i64) -> i64 {
    v.max(min).min(max)
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    if let Value::Object(map) = value {
        map
    } else {
        Map::new()
    }
}

fn metadata_string(metadata: &Map<String, Value>, key: &str) -> String {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn metadata_tags(metadata: &Map<String, Value>) -> Vec<String> {
    let Some(tags) = metadata.get("tags") else {
        return Vec::new();
    };
    match tags {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                if let Some(s) = item.as_str() {
                    return Some(s.trim().to_string());
                }
                item.as_object()
                    .and_then(|o| o.get("name"))
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn metadata_set_asset_value(existing: Option<Value>, key: &str, value: &str) -> Value {
    let mut arr = existing
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
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
    for _ in 0..3 {
        match http_request(method, url, headers, body) {
            Ok(resp) => {
                if (200..300).contains(&resp.status) {
                    return Ok(resp);
                }
                last_error = format!("HTTP {}", resp.status);
            }
            Err(e) => last_error = e,
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

    let mut stream = connect_tls_stream(&parsed.host, parsed.port)?;
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

    let (status, response_headers, body) = read_http_response(&mut stream)?;
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

fn read_http_response(
    stream: &mut HttpStream,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
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
