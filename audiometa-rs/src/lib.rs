use lofty::prelude::*;
use lofty::probe::Probe;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

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
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_call(_: i32, _: i32, _: i32) -> i32 {
    1
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_len() -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_read(_: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_len() -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_read(_: i32, _: i32) -> i32 {
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
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
struct ArchiveFilesResponse {
    #[serde(default, alias = "archiveId", alias = "archive_id")]
    archive_id: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ExportedFileItem {
    #[serde(default)]
    source: String,
    #[serde(default)]
    relative_path: String,
}

#[derive(Debug, Deserialize)]
struct ExportEntriesResponse {
    #[serde(default)]
    files: Vec<ExportedFileItem>,
}

#[derive(Debug, Clone, Default)]
struct ParsedAudioTags {
    title: String,
    artist: String,
    album: String,
    comment: String,
    genre: String,
    lyrics: String,
    year: Option<u32>,
    duration_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct ExtractedCover {
    relative_path: String,
}

#[derive(Debug, Clone)]
struct ExtractedLyrics {
    relative_path: String,
}

#[derive(Clone, Copy)]
struct AudioMetaOptions {
    merge_existing: bool,
    include_artist_tag: bool,
    include_album_tag: bool,
    include_genre_tag: bool,
    include_year_tag: bool,
    levels_up: i64,
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
    let result = match serde_json::to_vec(&payload) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("failed to encode result: {e}")),
    };

    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = result;
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
        "name": "Audio Embedded Tags (Rust/WASM)",
        "type": "metadata",
        "namespace": "audiometa",
        "author": "codex",
        "version": "0.1.0",
        "description": "Extracts embedded tags from audio files (ID3/FLAC/Vorbis/MP4) using lofty.",
        "permissions": [
            "metadata.read_input",
            "archive.list_files",
            "archive.export_entries",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "entry_name", "type": "string", "desc": "Preferred audio entry path inside archive/folder", "default_value": ""},
            {"name": "levels_up", "type": "number", "desc": "Allow adjacent file fallback by climbing parent dirs", "default_value": "0"},
            {"name": "merge_existing", "type": "bool", "desc": "Merge extracted tags with existing metadata.tags", "default_value": "1"},
            {"name": "include_artist_tag", "type": "bool", "desc": "Add artist:<name> into metadata.tags", "default_value": "1"},
            {"name": "include_album_tag", "type": "bool", "desc": "Add album:<name> into metadata.tags", "default_value": "1"},
            {"name": "include_genre_tag", "type": "bool", "desc": "Add genre:<name> into metadata.tags", "default_value": "1"},
            {"name": "include_year_tag", "type": "bool", "desc": "Add year:<yyyy> into metadata.tags", "default_value": "1"}
        ],
        "oneshot_arg": "Optional audio entry path (e.g. track01.flac)",
        "cooldown": 0,
        "runtime": "wamr",
        "abi_version": 1
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(data) => json!({
            "success": true,
            "data": data,
        }),
        Err(error) => json!({
            "success": false,
            "error": error,
        }),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    if !input.plugin_type.trim().eq_ignore_ascii_case("metadata") {
        return Err("audiometa-rs only supports Metadata plugins".to_string());
    }

    let archive_id = input.target_id.trim();
    if archive_id.is_empty() {
        return Err("Missing targetId".to_string());
    }

    let options = AudioMetaOptions {
        merge_existing: read_bool_param(&input.params, "merge_existing", true),
        include_artist_tag: read_bool_param(&input.params, "include_artist_tag", true),
        include_album_tag: read_bool_param(&input.params, "include_album_tag", true),
        include_genre_tag: read_bool_param(&input.params, "include_genre_tag", true),
        include_year_tag: read_bool_param(&input.params, "include_year_tag", true),
        levels_up: read_i64_param(&input.params, "levels_up", 0).clamp(0, 8),
    };
    let execution_tag = resolve_execution_tag(&input.params);

    HostBridge::progress(5, "扫描归档音频文件...");
    let listing = HostBridge::list_files(archive_id)?;
    let _ = &listing.archive_id;

    let preferred = first_non_empty(&[
        input.oneshot_param.trim().to_string(),
        read_string_param(&input.params, "entry_name", ""),
    ]);

    let audio_entries = collect_audio_entries(&listing.files);
    let target_entry = select_audio_entry(&audio_entries, &preferred)
        .ok_or_else(|| "No audio file found in archive listing".to_string())?;

    HostBridge::progress(25, "导出目标音频文件到运行目录...");
    let exported = HostBridge::export_entries(archive_id, audio_entries.clone(), options.levels_up)?;
    if exported.files.is_empty() {
        return Err("archive.export_entries returned empty files".to_string());
    }
    let mut exported_by_source = HashMap::<String, ExportedFileItem>::new();
    for item in &exported.files {
        let key = normalize_entry_key(&item.source);
        if key.is_empty() {
            continue;
        }
        exported_by_source.entry(key).or_insert_with(|| item.clone());
    }

    HostBridge::progress(55, "读取音频内嵌标签...");
    let mut page_patches = Vec::<Value>::new();
    let mut target_parsed: Option<ParsedAudioTags> = None;
    let mut target_cover: Option<ExtractedCover> = None;
    let mut target_source_name = String::new();

    for (idx, entry) in audio_entries.iter().enumerate() {
        let source_key = normalize_entry_key(entry);
        let Some(exported_file) = exported_by_source.get(&source_key) else {
            HostBridge::log(2, &format!("skip page patch: missing exported file for entry={entry}"));
            continue;
        };
        let runtime_path = format!("/plugin/{}", exported_file.relative_path.trim_start_matches('/'));
        let parsed = match read_audio_tags(&runtime_path) {
            Ok(v) => v,
            Err(e) => {
                if normalize_entry_key(entry) == normalize_entry_key(&target_entry) {
                    return Err(e);
                }
                HostBridge::log(2, &format!("skip entry due to parse error entry={entry}: {e}"));
                continue;
            }
        };
        let cover_prefix = format!("__embedded_cover_{}", idx + 1);
        let extracted_cover = match extract_embedded_cover(
            &runtime_path,
            exported_file.relative_path.trim(),
            &cover_prefix,
            &execution_tag,
        ) {
            Ok(v) => v,
            Err(e) => {
                HostBridge::log(2, &format!("cover extract failed entry={entry}: {e}"));
                None
            }
        };
        let lyrics_prefix = format!("__embedded_lyrics_{}", idx + 1);
        let extracted_lyrics = match extract_embedded_lyrics(
            &runtime_path,
            exported_file.relative_path.trim(),
            &lyrics_prefix,
            parsed.lyrics.trim(),
            &execution_tag,
        ) {
            Ok(v) => v,
            Err(e) => {
                HostBridge::log(2, &format!("lyrics extract failed entry={entry}: {e}"));
                None
            }
        };

        let page_description = build_track_description(&parsed);
        let mut page_obj = Map::<String, Value>::new();
        page_obj.insert("entry_path".to_string(), Value::String(entry.clone()));
        if !parsed.title.trim().is_empty() {
            page_obj.insert("title".to_string(), Value::String(parsed.title.clone()));
        }
        if !page_description.is_empty() {
            page_obj.insert("description".to_string(), Value::String(page_description));
        }
        if let Some(cover) = &extracted_cover {
            page_obj.insert("thumb".to_string(), Value::String(cover.relative_path.clone()));
        }
        if let Some(lyrics) = &extracted_lyrics {
            page_obj.insert("lyrics".to_string(), Value::String(lyrics.relative_path.clone()));
        }
        page_patches.push(Value::Object(page_obj));

        if normalize_entry_key(entry) == normalize_entry_key(&target_entry) {
            target_parsed = Some(parsed);
            target_cover = extracted_cover;
            target_source_name = exported_file.source.trim().to_string();
        }
    }
    let parsed = target_parsed
        .ok_or_else(|| "Target audio was exported but tags could not be parsed".to_string())?;

    HostBridge::progress(85, "合并元数据输出...");
    let mut metadata = ensure_metadata_object(input.metadata);

    let next_title = first_non_empty(&[
        parsed.title.clone(),
        metadata_string(&metadata, "title"),
    ]);
    if !next_title.is_empty() {
        metadata.insert("title".to_string(), Value::String(next_title));
    }

    let summary = build_track_description(&parsed);
    if !summary.is_empty() {
        metadata.insert("description".to_string(), Value::String(summary));
    }

    let mut tags = if options.merge_existing {
        metadata_tags(&metadata)
    } else {
        Vec::new()
    };
    if options.include_artist_tag && !parsed.artist.is_empty() {
        tags.push(format!("artist:{}", parsed.artist));
    }
    if options.include_album_tag && !parsed.album.is_empty() {
        tags.push(format!("album:{}", parsed.album));
    }
    if options.include_genre_tag && !parsed.genre.is_empty() {
        tags.push(format!("genre:{}", parsed.genre));
    }
    if options.include_year_tag {
        if let Some(year) = parsed.year {
            tags.push(format!("year:{year}"));
        }
    }
    tags.push(format!("audio_entry:{}", target_entry));
    if !target_source_name.is_empty() {
        tags.push(format!("audio_source:{}", target_source_name));
    }
    metadata.insert("tags".to_string(), json!(unique_strings(tags)));

    metadata.insert("children".to_string(), Value::Array(vec![]));
    if let Some(cover) = target_cover {
        metadata.insert(
            "assets".to_string(),
            Value::Array(vec![json!({
                "key": "cover",
                "value": cover.relative_path.clone(),
            })]),
        );
    }
    if !page_patches.is_empty() {
        metadata.insert("pages".to_string(), Value::Array(page_patches));
    }
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "音频标签提取完成");
    Ok(Value::Object(metadata))
}

fn select_audio_entry(files: &[String], preferred: &str) -> Option<String> {
    if !preferred.trim().is_empty() {
        let preferred_lower = preferred.trim().to_ascii_lowercase();
        for file in files {
            if file.trim().to_ascii_lowercase() == preferred_lower {
                return Some(file.clone());
            }
        }
        if is_audio_file_name(preferred.trim()) {
            return Some(preferred.trim().to_string());
        }
    }

    let mut candidates = files
        .iter()
        .filter(|name| is_audio_file_name(name))
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    candidates.sort_by_key(|name| name.to_ascii_lowercase());
    candidates.into_iter().next()
}

fn collect_audio_entries(files: &[String]) -> Vec<String> {
    let mut candidates = files
        .iter()
        .filter(|name| is_audio_file_name(name))
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    candidates.sort_by_key(|name| normalize_entry_key(name));
    candidates
}

fn normalize_entry_key(path: &str) -> String {
    path.trim().replace('\\', "/").to_ascii_lowercase()
}

fn is_audio_file_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.ends_with(".mp3")
        || lower.ends_with(".flac")
        || lower.ends_with(".m4a")
        || lower.ends_with(".aac")
        || lower.ends_with(".ogg")
        || lower.ends_with(".opus")
        || lower.ends_with(".wav")
        || lower.ends_with(".wma")
        || lower.ends_with(".ape")
        || lower.ends_with(".alac")
}

fn read_audio_tags(path: &str) -> Result<ParsedAudioTags, String> {
    let tagged_file = Probe::open(path)
        .map_err(|e| format!("failed to open audio file: {e}"))?
        .read()
        .map_err(|e| format!("failed to parse tags: {e}"))?;

    let mut out = ParsedAudioTags::default();
    if let Some(primary) = tagged_file.primary_tag().or_else(|| tagged_file.first_tag()) {
        out.title = primary.title().unwrap_or_default().trim().to_string();
        out.artist = primary.artist().unwrap_or_default().trim().to_string();
        out.album = primary.album().unwrap_or_default().trim().to_string();
        out.genre = primary.genre().unwrap_or_default().trim().to_string();
        out.comment = primary.comment().unwrap_or_default().trim().to_string();
        out.year = primary.year();
        out.lyrics = primary
            .get_string(&ItemKey::Lyrics)
            .unwrap_or_default()
            .trim()
            .to_string();
    }

    if out.lyrics.trim().is_empty() {
        for tag in tagged_file.tags() {
            let candidate = tag
                .get_string(&ItemKey::Lyrics)
                .unwrap_or_default()
                .trim()
                .to_string();
            if !candidate.is_empty() {
                out.lyrics = candidate;
                break;
            }
        }
    }

    let duration = tagged_file.properties().duration();
    if duration.as_secs() > 0 {
        out.duration_seconds = Some(duration.as_secs());
    }

    Ok(out)
}

fn build_track_description(parsed: &ParsedAudioTags) -> String {
    let mut summary_parts = Vec::<String>::new();
    if !parsed.artist.is_empty() {
        summary_parts.push(format!("Artist: {}", parsed.artist));
    }
    if !parsed.album.is_empty() {
        summary_parts.push(format!("Album: {}", parsed.album));
    }
    if !parsed.genre.is_empty() {
        summary_parts.push(format!("Genre: {}", parsed.genre));
    }
    if let Some(year) = parsed.year {
        summary_parts.push(format!("Year: {year}"));
    }
    if let Some(seconds) = parsed.duration_seconds {
        summary_parts.push(format!("Duration: {seconds}s"));
    }
    if !parsed.comment.is_empty() {
        summary_parts.push(parsed.comment.clone());
    }
    summary_parts.join("\n")
}

fn extract_embedded_cover(
    runtime_audio_path: &str,
    exported_relative_path: &str,
    output_prefix: &str,
    execution_tag: &str,
) -> Result<Option<ExtractedCover>, String> {
    let tagged_file = Probe::open(runtime_audio_path)
        .map_err(|e| format!("failed to open audio file for picture extraction: {e}"))?
        .read()
        .map_err(|e| format!("failed to parse tags for picture extraction: {e}"))?;

    let picture_data = tagged_file
        .primary_tag()
        .and_then(|tag| tag.pictures().first())
        .or_else(|| {
            tagged_file
                .first_tag()
                .and_then(|tag| tag.pictures().first())
        })
        .map(|pic| pic.data().to_vec());

    let Some(bytes) = picture_data else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Ok(None);
    }

    let ext = detect_image_extension(&bytes);
    let output_name = build_runtime_output_name(output_prefix, execution_tag, ext);

    let runtime_audio = Path::new(runtime_audio_path);
    let runtime_parent = runtime_audio
        .parent()
        .ok_or_else(|| "failed to resolve runtime output directory".to_string())?;
    let runtime_cover_path = runtime_parent.join(&output_name);

    if let Err(e) = fs::write(&runtime_cover_path, &bytes) {
        return Err(format!("failed to write extracted cover: {e}"));
    }

    let rel_parent = Path::new(exported_relative_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(PathBuf::new);
    let rel_cover_path = if rel_parent.as_os_str().is_empty() {
        output_name
    } else {
        format!("{}/{}", path_to_forward_slash(&rel_parent), output_name)
    };

    Ok(Some(ExtractedCover {
        relative_path: format_runtime_path_for_host(&rel_cover_path),
    }))
}

fn extract_embedded_lyrics(
    runtime_audio_path: &str,
    exported_relative_path: &str,
    output_prefix: &str,
    lyrics_text: &str,
    execution_tag: &str,
) -> Result<Option<ExtractedLyrics>, String> {
    let text = lyrics_text.trim();
    if text.is_empty() {
        return Ok(None);
    }

    let has_time_tag = text
        .lines()
        .any(|line| line.trim_start().starts_with('[') && line.contains(':') && line.contains(']'));
    let ext = if has_time_tag { "lrc" } else { "txt" };
    let output_name = build_runtime_output_name(output_prefix, execution_tag, ext);

    let runtime_audio = Path::new(runtime_audio_path);
    let runtime_parent = runtime_audio
        .parent()
        .ok_or_else(|| "failed to resolve runtime output directory".to_string())?;
    let runtime_lyrics_path = runtime_parent.join(&output_name);

    if let Err(e) = fs::write(&runtime_lyrics_path, text.as_bytes()) {
        return Err(format!("failed to write extracted lyrics: {e}"));
    }

    let rel_parent = Path::new(exported_relative_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(PathBuf::new);
    let rel_lyrics_path = if rel_parent.as_os_str().is_empty() {
        output_name
    } else {
        format!("{}/{}", path_to_forward_slash(&rel_parent), output_name)
    };

    Ok(Some(ExtractedLyrics {
        relative_path: format_runtime_path_for_host(&rel_lyrics_path),
    }))
}

fn format_runtime_path_for_host(path: &str) -> String {
    let trimmed = path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("plugins/") {
        return trimmed.to_string();
    }
    format!("plugins/audiometa/{trimmed}")
}

fn build_runtime_output_name(output_prefix: &str, execution_tag: &str, ext: &str) -> String {
    if execution_tag.is_empty() {
        format!("{output_prefix}.{ext}")
    } else {
        format!("{execution_tag}_{output_prefix}.{ext}")
    }
}

fn sanitize_runtime_token(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect()
}

fn resolve_execution_tag(params: &Value) -> String {
    let host_tag = sanitize_runtime_token(&read_string_param(params, "__task_id", ""));
    if !host_tag.is_empty() {
        return host_tag;
    }

    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    if now_nanos == 0 {
        return "exec_fallback".to_string();
    }
    format!("exec_{now_nanos:x}")
}

fn path_to_forward_slash(path: &Path) -> String {
    let mut out = String::new();
    for (i, part) in path.components().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&part.as_os_str().to_string_lossy());
    }
    out
}

fn detect_image_extension(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return "jpg";
    }
    if bytes.len() >= 8
        && bytes[0] == 0x89
        && bytes[1] == 0x50
        && bytes[2] == 0x4E
        && bytes[3] == 0x47
        && bytes[4] == 0x0D
        && bytes[5] == 0x0A
        && bytes[6] == 0x1A
        && bytes[7] == 0x0A
    {
        return "png";
    }
    if bytes.len() >= 12
        && bytes[0] == 0x52
        && bytes[1] == 0x49
        && bytes[2] == 0x46
        && bytes[3] == 0x46
        && bytes[8] == 0x57
        && bytes[9] == 0x45
        && bytes[10] == 0x42
        && bytes[11] == 0x50
    {
        return "webp";
    }
    if bytes.len() >= 12
        && bytes[4] == 0x66
        && bytes[5] == 0x74
        && bytes[6] == 0x79
        && bytes[7] == 0x70
        && bytes[8] == 0x61
        && bytes[9] == 0x76
        && bytes[10] == 0x69
        && bytes[11] == 0x66
    {
        return "avif";
    }
    if bytes.len() >= 6
        && bytes[0] == 0x47
        && bytes[1] == 0x49
        && bytes[2] == 0x46
        && bytes[3] == 0x38
        && (bytes[4] == 0x37 || bytes[4] == 0x39)
        && bytes[5] == 0x61
    {
        return "gif";
    }
    "bin"
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn metadata_string(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn metadata_tags(map: &Map<String, Value>) -> Vec<String> {
    map.get("tags")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_ascii_lowercase()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn read_bool_param(params: &Value, key: &str, default_value: bool) -> bool {
    let Some(raw) = params.get(key) else {
        return default_value;
    };
    match raw {
        Value::Bool(v) => *v,
        Value::Number(v) => v.as_i64().map(|n| n != 0).unwrap_or(default_value),
        Value::String(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "y" | "on")
        }
        _ => default_value,
    }
}

fn read_i64_param(params: &Value, key: &str, default_value: i64) -> i64 {
    let Some(raw) = params.get(key) else {
        return default_value;
    };
    match raw {
        Value::Number(v) => v.as_i64().unwrap_or(default_value),
        Value::String(v) => v.trim().parse::<i64>().unwrap_or(default_value),
        _ => default_value,
    }
}

fn read_string_param(params: &Value, key: &str, default_value: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(default_value)
        .to_string()
}

fn first_non_empty(candidates: &[String]) -> String {
    candidates
        .iter()
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error.clear();
    });
}

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}

fn set_error_and_zero(message: String) -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.error = message.into_bytes();
    });
    0
}

unsafe fn read_guest_bytes(ptr: i32, len: i32) -> &'static [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}

struct HostBridge;

impl HostBridge {
    fn log(level: i32, message: &str) {
        if message.is_empty() {
            return;
        }
        unsafe {
            let _ = host_log(level, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn progress(percent: i32, message: &str) {
        unsafe {
            let _ = host_progress(percent, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn list_files(archive_id: &str) -> Result<ArchiveFilesResponse, String> {
        Self::call_typed("archive.list_files", json!({ "archive_id": archive_id }))
    }

    fn export_entries(
        archive_id: &str,
        entries: Vec<String>,
        levels_up: i64,
    ) -> Result<ExportEntriesResponse, String> {
        Self::call_typed(
            "archive.export_entries",
            json!({
                "archive_id": archive_id,
                "entries": entries,
                "levels_up": levels_up,
            }),
        )
    }

    fn call_typed<T: DeserializeOwned>(method: &str, params: Value) -> Result<T, String> {
        let value = Self::call(method, params)?;
        serde_json::from_value(value).map_err(|e| format!("invalid host response for {method}: {e}"))
    }

    fn call(method: &str, params: Value) -> Result<Value, String> {
        let req = json!({ "method": method, "params": params });
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;

        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 {
            let err = Self::read_last_error();
            let err_msg = if err.is_empty() {
                format!("host_call failed for {method} (rc={rc})")
            } else {
                err
            };
            Self::log(3, &err_msg);
            return Err(err_msg);
        }

        let response = Self::read_response();
        serde_json::from_slice::<Value>(&response)
            .map_err(|e| format!("failed to decode host response for {method}: {e}"))
    }

    fn read_response() -> Vec<u8> {
        let len = unsafe { host_response_len() };
        if len <= 0 {
            return b"{}".to_vec();
        }
        let mut buffer = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buffer.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return b"{}".to_vec();
        }
        buffer.truncate(read as usize);
        buffer
    }

    fn read_last_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 {
            return "host_call failed".to_string();
        }
        let mut buffer = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buffer.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return "host_call failed".to_string();
        }
        buffer.truncate(read as usize);
        String::from_utf8(buffer).unwrap_or_else(|_| "host_call failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::is_audio_file_name;

    #[test]
    fn test_audio_extension_detection() {
        assert!(is_audio_file_name("track01.FLAC"));
        assert!(is_audio_file_name("music/ep1.mp3"));
        assert!(!is_audio_file_name("cover.jpg"));
        assert!(!is_audio_file_name("notes.txt"));
    }
}
