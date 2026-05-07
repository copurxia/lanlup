use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;

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
    #[allow(dead_code)]
    #[serde(default, alias = "archiveId", alias = "archive_id")]
    archive_id: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct TranscriptionResponse {
    text: String,
}

#[derive(Debug, Deserialize)]
struct VerboseTranscriptionResponse {
    text: String,
    #[serde(default)]
    segments: Vec<TranscriptionSegmentItem>,
}

#[derive(Debug, Deserialize)]
struct TranscriptionSegmentItem {
    #[serde(default)]
    start: f64,
    #[allow(dead_code)]
    #[serde(default)]
    end: f64,
    #[serde(default)]
    text: String,
}

#[derive(Debug, Clone)]
struct TranscribedPage {
    entry_path: String,
    transcription: String,
    lrc_lines: Vec<String>,
}

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
        "name": "Whisper ASR (Rust/WASM)",
        "type": "metadata",
        "namespace": "whisper",
        "author": "codex",
        "version": "0.1.0",
        "description": "Transcribes audio files via OpenAI-compatible Whisper API and embeds lyrics into page metadata.",
        "permissions": [
            "metadata.read_input",
            "archive.list_files",
            "archive.export_entries",
            "tcp.connect",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "entry_name", "type": "string", "desc": "Preferred audio entry path inside archive/folder", "default_value": ""},
            {"name": "server_url", "type": "string", "desc": "OpenAI-compatible Whisper server base URL", "default_value": "http://192.168.0.112:8003"},
            {"name": "server_token", "type": "string", "desc": "Bearer token for server authentication (e.g. sk-xxx)", "default_value": ""},
            {"name": "model", "type": "string", "desc": "Whisper model name", "default_value": "whisper-1"},
            {"name": "language", "type": "string", "desc": "Language hint (ISO code, e.g. zh, en). Empty = auto-detect", "default_value": ""}
        ],
        "oneshot_arg": "Optional audio entry path (e.g. track01.mp3)",
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
        return Err("whisper-rs only supports Metadata plugins".to_string());
    }

    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err("Missing targetId".to_string());
    }

    let server_url = read_string_param(&input.params, "server_url", "http://192.168.0.112:8003");
    let server_token = read_string_param(&input.params, "server_token", "");
    let model = read_string_param(&input.params, "model", "whisper-1");
    let language = read_string_param(&input.params, "language", "");
    let preferred = first_non_empty(&[
        input.oneshot_param.trim().to_string(),
        read_string_param(&input.params, "entry_name", ""),
    ]);
    let execution_tag = resolve_execution_tag(&input.params);

    let target_type = normalized_target_type(&input.target_type, &input.params);

    if target_type == "tankoubon" || target_type == "tank" {
        return execute_tankoubon_mode(target_id, &preferred, &server_url, &server_token, &model, &language, &execution_tag, input.metadata);
    }

    execute_archive_mode(target_id, &preferred, &server_url, &server_token, &model, &language, &execution_tag, input.metadata)
}

fn execute_archive_mode(
    archive_id: &str,
    preferred: &str,
    server_url: &str,
    server_token: &str,
    model: &str,
    language: &str,
    execution_tag: &str,
    metadata_input: Value,
) -> Result<Value, String> {
    HostBridge::progress(5, "扫描归档音频文件...");
    let listing = HostBridge::list_files(archive_id)?;
    let audio_entries = collect_audio_entries(&listing.files);
    let target_entry = select_audio_entry(&audio_entries, preferred)
        .ok_or_else(|| "No audio file found in archive listing".to_string())?;

    let exported = export_audio_entries(archive_id, &audio_entries, 0)?;

    let mut transcribed_pages = Vec::<TranscribedPage>::new();

    for (idx, entry) in audio_entries.iter().enumerate() {
        let percent = 10 + (((idx + 1) * 80) / audio_entries.len()) as i32;
        HostBridge::progress(percent.min(90), &format!("转录音頻 {}/{}", idx + 1, audio_entries.len()));

        let exported_rel = match exported.get(&normalize_entry_key(entry)) {
            Some(path) => path.clone(),
            None => {
                if normalize_entry_key(entry) == normalize_entry_key(&target_entry) {
                    return Err(format!("failed to export target audio: {entry}"));
                }
                HostBridge::log(2, &format!("skip entry: not exported for archive={archive_id}, entry={entry}"));
                continue;
            }
        };

        let runtime_path = format!("/plugin/{exported_rel}");
        let audio_bytes = fs::read(&runtime_path)
            .map_err(|e| format!("failed to read exported audio at {runtime_path}: {e}"))?;

        let filename = entry.rsplit('/').next().unwrap_or(entry);
        let (transcription, lrc_lines) = transcribe_audio(&audio_bytes, filename, server_url, server_token, model, language)
            .map_err(|e| format!("transcription failed for {entry}: {e}"))?;

        HostBridge::log(1, &format!("transcription for {entry}: {} chars, {} segments", transcription.len(), lrc_lines.len()));

        transcribed_pages.push(TranscribedPage {
            entry_path: entry.clone(),
            transcription,
            lrc_lines,
        });
    }

    HostBridge::progress(95, "构建歌词元数据...");

    let target_page_text = transcribed_pages.iter()
        .find(|p| normalize_entry_key(&p.entry_path) == normalize_entry_key(&target_entry))
        .map(|p| p.transcription.clone())
        .unwrap_or_default();

    let mut metadata = ensure_metadata_object(metadata_input);

    if !target_page_text.is_empty() {
        let target_lrc = transcribed_pages.iter()
            .find(|p| normalize_entry_key(&p.entry_path) == normalize_entry_key(&target_entry))
            .map(|p| &p.lrc_lines)
            .filter(|l| !l.is_empty())
            .map(|l| l.join("\n"))
            .unwrap_or_else(|| target_page_text.clone());
        let has_timestamps = target_lrc.contains('[') && target_lrc.contains(']');
        let lyrics_out = write_lyrics_file(&target_lrc, "target", execution_tag, &exported, &target_entry, has_timestamps)?;
        let ext = if has_timestamps { "lrc" } else { "txt" };
        let attachment = json!({
            "slot": "lyrics",
            "path": lyrics_out,
            "name": attachment_name_from_path(&lyrics_out),
            "kind": ext,
            "mime_type": if has_timestamps { "text/x-lrc" } else { "text/plain" },
        });
        metadata.insert("attachments".to_string(), Value::Array(vec![attachment]));
    }

    let mut pages = Vec::<Value>::new();
    for (idx, tp) in transcribed_pages.iter().enumerate() {
        let has_timestamps = !tp.lrc_lines.is_empty();
        let content = if has_timestamps {
            tp.lrc_lines.join("\n")
        } else {
            tp.transcription.clone()
        };
        let ext = if has_timestamps { "lrc" } else { "txt" };
        let lyrics_out = write_lyrics_file(&content, &format!("page_{}", idx + 1), execution_tag, &exported, &tp.entry_path, has_timestamps)?;
        let mut page_obj = Map::<String, Value>::new();
        page_obj.insert("page_number".to_string(), Value::from((idx + 1) as i64));
        page_obj.insert("entry_path".to_string(), Value::String(tp.entry_path.clone()));
        page_obj.insert("attachments".to_string(), Value::Array(vec![json!({
            "slot": "lyrics",
            "path": lyrics_out,
            "name": attachment_name_from_path(&lyrics_out),
            "kind": ext,
            "mime_type": if has_timestamps { "text/x-lrc" } else { "text/plain" },
        })]));

        let short = if tp.transcription.len() > 200 {
            let trunc: String = tp.transcription.chars().take(200).collect();
            format!("{trunc}...")
        } else {
            tp.transcription.clone()
        };
        page_obj.insert("description".to_string(), Value::String(short));
        pages.push(Value::Object(page_obj));
    }
    metadata.insert("pages".to_string(), Value::Array(pages));

    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "语音识别完成");
    Ok(Value::Object(metadata))
}

fn execute_tankoubon_mode(
    tankoubon_id: &str,
    preferred: &str,
    server_url: &str,
    server_token: &str,
    model: &str,
    language: &str,
    execution_tag: &str,
    metadata_input: Value,
) -> Result<Value, String> {
    HostBridge::progress(5, "列出合集成员归档...");
    let archive_ids = HostBridge::list_tankoubon_archives(tankoubon_id)?
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    if archive_ids.is_empty() {
        return Err(format!("No member archives found in collection {tankoubon_id}"));
    }

    let mut root_metadata = ensure_metadata_object(metadata_input);
    let mut children = Vec::<Value>::with_capacity(archive_ids.len());

    for (index, archive_id) in archive_ids.iter().enumerate() {
        let percent = 10 + (((index + 1) * 80) / archive_ids.len()) as i32;
        HostBridge::progress(percent.min(90), &format!("处理合集成员 {}/{}", index + 1, archive_ids.len()));
        let member_tag = format!("{execution_tag}_v{}", index + 1);
        let result = execute_archive_mode(archive_id, preferred, server_url, server_token, model, language, &member_tag, json!({}))?;
        if let Value::Object(map) = result {
            let mut child = Map::<String, Value>::new();
            child.insert("entity_type".to_string(), Value::String("archive".to_string()));
            child.insert("entity_id".to_string(), Value::String(archive_id.clone()));
            child.insert("volume_no".to_string(), Value::from((index + 1) as i64));
            if let Some(title) = map.get("title") {
                child.insert("title".to_string(), title.clone());
            }
            if let Some(desc) = map.get("description") {
                child.insert("description".to_string(), desc.clone());
            }
            if let Some(pages) = map.get("pages") {
                child.insert("pages".to_string(), pages.clone());
            }
            child.insert("locator".to_string(), json!({
                "entity_type": "archive",
                "entity_id": archive_id,
                "volume_no": (index + 1) as i64,
            }));
            children.push(Value::Object(child));
        }
    }

    root_metadata.insert("pages".to_string(), Value::Array(vec![]));
    root_metadata.insert("children".to_string(), Value::Array(children));
    root_metadata.remove("archive");
    root_metadata.remove("archive_id");

    HostBridge::progress(100, "合集语音识别完成");
    Ok(Value::Object(root_metadata))
}

fn write_lyrics_file(
    text: &str,
    label: &str,
    execution_tag: &str,
    exported: &std::collections::HashMap<String, String>,
    entry_path: &str,
    has_timestamps: bool,
) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty transcription".to_string());
    }

    let ext = if has_timestamps { "lrc" } else { "txt" };
    let output_name = build_runtime_output_name(label, execution_tag, ext);
    let exported_rel = exported.get(&normalize_entry_key(entry_path))
        .ok_or_else(|| format!("missing exported path for {entry_path}"))?;
    let runtime_path = Path::new("/plugin").join(&exported_rel);
    let runtime_parent = runtime_path.parent()
        .ok_or_else(|| "failed to resolve runtime output parent".to_string())?;
    let runtime_out = runtime_parent.join(&output_name);

    if let Some(parent) = runtime_out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&runtime_out, text.as_bytes())
        .map_err(|e| format!("failed to write lyrics file: {e}"))?;

    let rel_parent = Path::new(exported_rel)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(PathBuf::new);
    let rel_out = if rel_parent.as_os_str().is_empty() {
        output_name
    } else {
        format!("{}/{}", path_to_forward_slash(&rel_parent), output_name)
    };

    Ok(format_runtime_path_for_host(&rel_out))
}

fn format_runtime_path_for_host(path: &str) -> String {
    let trimmed = path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("plugins/") {
        return trimmed.to_string();
    }
    format!("plugins/whisper/{trimmed}")
}

fn attachment_name_from_path(path: &str) -> String {
    let normalized = path.trim().replace('\\', "/");
    normalized
        .rsplit('/')
        .next()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("attachment")
        .to_string()
}

fn transcribe_audio(
    audio_bytes: &[u8],
    filename: &str,
    server_url: &str,
    server_token: &str,
    model: &str,
    language: &str,
) -> Result<(String, Vec<String>), String> {
    let parsed = parse_url(server_url)?;
    let boundary = format_boundary();
    let mime_type = detect_mime_from_filename(filename);
    let mut body = Vec::new();

    append_multipart_part(&mut body, &boundary, "model", None, None, model.as_bytes());
    if !language.is_empty() {
        append_multipart_part(&mut body, &boundary, "language", None, None, language.as_bytes());
    }
    append_multipart_part(&mut body, &boundary, "response_format", None, None, b"verbose_json");
    append_multipart_part(&mut body, &boundary, "timestamp_granularities[]", None, None, b"segment");
    append_multipart_part(&mut body, &boundary, "file", Some(filename), Some(&mime_type), audio_bytes);
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");

    let content_type = format!("multipart/form-data; boundary={boundary}");
    let api_path = "/v1/audio/transcriptions";
    let base = parsed.path_and_query.trim_end_matches('/');
    let request_path = if base.is_empty() || base == "/" {
        api_path.to_string()
    } else {
        format!("{base}{api_path}")
    };
    let request = build_http_request("POST", &request_path, &parsed.host, parsed.port, &content_type, &body, server_token);

    let response = http_request_raw(&parsed.host, parsed.port, &request)?;

    let json_body = extract_json_body(&response)?;

    if let Ok(verbose) = serde_json::from_str::<VerboseTranscriptionResponse>(&json_body) {
        let lrc_lines: Vec<String> = verbose.segments.iter()
            .filter(|s| !s.text.trim().is_empty())
            .map(|s| {
                let start_secs = s.start.max(0.0);
                let m = (start_secs / 60.0) as u64;
                let sec = (start_secs % 60.0) as u64;
                let cs = ((start_secs - start_secs.floor()) * 100.0) as u64;
                let text = s.text.trim();
                format!("[{:02}:{:02}.{:02}]{}", m, sec, cs, text)
            })
            .collect();
        return Ok((verbose.text, lrc_lines));
    }

    let tr: TranscriptionResponse = serde_json::from_str(&json_body)
        .map_err(|e| format!("failed to parse whisper response: {e}, body: {json_body}"))?;

    Ok((tr.text, Vec::new()))
}

fn format_boundary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("----WhisperPluginBoundary{nanos:x}")
}

fn detect_mime_from_filename(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".mp3") { "audio/mpeg".to_string() }
    else if lower.ends_with(".flac") { "audio/flac".to_string() }
    else if lower.ends_with(".m4a") || lower.ends_with(".aac") { "audio/mp4".to_string() }
    else if lower.ends_with(".ogg") || lower.ends_with(".opus") { "audio/ogg".to_string() }
    else if lower.ends_with(".wav") { "audio/wav".to_string() }
    else if lower.ends_with(".wma") { "audio/x-ms-wma".to_string() }
    else if lower.ends_with(".ape") { "audio/x-ape".to_string() }
    else { "application/octet-stream".to_string() }
}

fn append_multipart_part(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: Option<&str>,
    content_type: Option<&str>,
    data: &[u8],
) {
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"").as_bytes());
    if let Some(fname) = filename {
        body.extend_from_slice(format!("; filename=\"{fname}\"").as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    if let Some(ct) = content_type {
        body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
}

fn build_http_request(
    method: &str,
    path: &str,
    host: &str,
    port: u16,
    content_type: &str,
    body: &[u8],
    bearer_token: &str,
) -> Vec<u8> {
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut request = Vec::new();
    request.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    request.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    if !bearer_token.is_empty() {
        request.extend_from_slice(format!("Authorization: Bearer {bearer_token}\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n");
    request.extend_from_slice(b"Accept: application/json\r\n");
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    request
}

#[cfg(target_arch = "wasm32")]
struct WasiStream {
    stream: WasiTcpStream,
}

#[cfg(target_arch = "wasm32")]
impl Read for WasiStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(target_arch = "wasm32")]
impl Write for WasiStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(target_arch = "wasm32")]
fn connect_tcp(host: &str, port: u16, timeout_ms: u64) -> Result<WasiStream, String> {
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| format!("tcp connect failed: {e}"))?;
    let _ = stream.as_mut().set_recv_timeout(Some(timeout));
    let _ = stream.as_mut().set_send_timeout(Some(timeout));
    Ok(WasiStream { stream })
}

#[cfg(not(target_arch = "wasm32"))]
fn connect_tcp(host: &str, port: u16, timeout_ms: u64) -> Result<std::net::TcpStream, String> {
    use std::net::ToSocketAddrs;
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let addr = format!("{host}:{port}");
    let sock_addrs = addr.to_socket_addrs().map_err(|e| format!("DNS: {e}"))?;
    let addr = sock_addrs.as_slice().first().ok_or("No address resolved")?.to_owned();
    let stream = std::net::TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    Ok(stream)
}

fn http_request_raw(host: &str, port: u16, request: &[u8]) -> Result<String, String> {
    let timeout_ms = 300_000;
    let mut stream = connect_tcp(host, port, timeout_ms)?;
    stream.write_all(request).map_err(|e| format!("tcp write failed: {e}"))?;
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).map_err(|e| format!("tcp read failed: {e}"))?;
        if n == 0 { break; }
        response.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(response).map_err(|e| format!("invalid utf8 response: {e}"))
}

fn extract_json_body(response: &str) -> Result<String, String> {
    let parts: Vec<&str> = response.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err(format!("invalid HTTP response (no body): {response:.200}"));
    }
    let header = parts[0];
    let body = parts[1..].join("\r\n\r\n");
    let status_line = header.lines().next().unwrap_or("");
    if !status_line.contains("200") && !status_line.contains("201") {
        return Err(format!("whisper server returned error: {status_line}, body: {body:.200}"));
    }
    let content_length = header.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok());
    if let Some(len) = content_length {
        if body.len() < len {
            return Err(format!("response body too short: expected {len}, got {}", body.len()));
        }
        let safe_len = body.floor_char_boundary(len);
        Ok(body[..safe_len].to_string())
    } else {
        Ok(body.to_string())
    }
}

fn export_audio_entries(
    archive_id: &str,
    audio_entries: &[String],
    levels_up: i64,
) -> Result<std::collections::HashMap<String, String>, String> {
    let exported = HostBridge::export_entries(archive_id, audio_entries.to_vec(), levels_up)?;
    let mut by_source = std::collections::HashMap::<String, String>::new();
    for file in exported.files {
        let source_key = normalize_entry_key(&file.source);
        let relative_path = file.relative_path.trim().trim_start_matches('/').to_string();
        if !source_key.is_empty() && !relative_path.is_empty() {
            by_source.insert(source_key, relative_path);
        }
    }
    Ok(by_source)
}

struct ParsedUrl {
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let rest = if let Some(s) = url.strip_prefix("http://") { s }
    else if url.strip_prefix("https://").is_some() {
        return Err("HTTPS not supported, use HTTP".to_string());
    } else { return Err("URL must start with http://".to_string()); };

    let (host_part, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "/")
    };

    let (host, port) = if let Some(pos) = host_part.find(':') {
        let p: u16 = host_part[pos + 1..].parse().map_err(|_| "Invalid port".to_string())?;
        (&host_part[..pos], p)
    } else {
        (host_part, 80)
    };

    Ok(ParsedUrl {
        host: host.to_string(),
        port,
        path_and_query: path.to_string(),
    })
}

fn normalized_target_type(target_type: &str, params: &Value) -> String {
    let direct = target_type.trim().to_ascii_lowercase();
    if !direct.is_empty() {
        return direct;
    }
    let fallback = read_string_param(params, "__target_type", "");
    let normalized = fallback.trim().to_ascii_lowercase();
    if normalized.is_empty() { "archive".to_string() } else { normalized }
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
    let mut candidates = files.iter()
        .filter(|name| is_audio_file_name(name))
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    candidates.sort_by_key(|name| name.to_ascii_lowercase());
    candidates.into_iter().next()
}

fn collect_audio_entries(files: &[String]) -> Vec<String> {
    let mut candidates = files.iter()
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

fn build_runtime_output_name(prefix: &str, execution_tag: &str, ext: &str) -> String {
    if execution_tag.is_empty() {
        format!("{prefix}.{ext}")
    } else {
        format!("{execution_tag}_{prefix}.{ext}")
    }
}

fn resolve_execution_tag(params: &Value) -> String {
    let host_tag = sanitize_runtime_token(&read_string_param(params, "__task_id", ""));
    if !host_tag.is_empty() {
        return host_tag;
    }
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    if now_nanos == 0 {
        return "exec_fallback".to_string();
    }
    format!("exec_{now_nanos:x}")
}

fn sanitize_runtime_token(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect()
}

fn path_to_forward_slash(path: &Path) -> String {
    let mut out = String::new();
    for (i, part) in path.components().enumerate() {
        if i > 0 { out.push('/'); }
        out.push_str(&part.as_os_str().to_string_lossy());
    }
    out
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn first_non_empty(candidates: &[String]) -> String {
    candidates.iter()
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn read_string_param(params: &Value, key: &str, default_value: &str) -> String {
    params.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(default_value)
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
        if message.is_empty() { return; }
        unsafe { let _ = host_log(level, message.as_ptr() as i32, message.len() as i32); }
    }

    fn progress(percent: i32, message: &str) {
        unsafe { let _ = host_progress(percent, message.as_ptr() as i32, message.len() as i32); }
    }

    fn list_files(archive_id: &str) -> Result<ArchiveFilesResponse, String> {
        Self::call_typed("archive.list_files", json!({ "archive_id": archive_id }))
    }

    fn export_entries(archive_id: &str, entries: Vec<String>, levels_up: i64) -> Result<ExportEntriesResponse, String> {
        Self::call_typed("archive.export_entries", json!({
            "archive_id": archive_id,
            "entries": entries,
            "levels_up": levels_up,
        }))
    }

    fn list_tankoubon_archives(tankoubon_id: &str) -> Result<Vec<String>, String> {
        let response = Self::call_typed::<TankoubonArchivesResponse>(
            "tankoubon.list_archives",
            json!({ "tankoubon_id": tankoubon_id }),
        )?;
        Ok(response.archive_ids)
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
            } else { err };
            Self::log(3, &err_msg);
            return Err(err_msg);
        }
        let response = Self::read_response();
        serde_json::from_slice::<Value>(&response)
            .map_err(|e| format!("failed to decode host response for {method}: {e}"))
    }

    fn read_response() -> Vec<u8> {
        let len = unsafe { host_response_len() };
        if len <= 0 { return b"{}".to_vec(); }
        let mut buffer = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buffer.as_mut_ptr() as i32, len) };
        if read <= 0 { return b"{}".to_vec(); }
        buffer.truncate(read as usize);
        buffer
    }

    fn read_last_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 { return "host_call failed".to_string(); }
        let mut buffer = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buffer.as_mut_ptr() as i32, len) };
        if read <= 0 { return "host_call failed".to_string(); }
        buffer.truncate(read as usize);
        String::from_utf8(buffer).unwrap_or_else(|_| "host_call failed".to_string())
    }
}

#[derive(Debug, Deserialize)]
struct TankoubonArchivesResponse {
    #[serde(default)]
    archive_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_extension_detection() {
        assert!(is_audio_file_name("track01.FLAC"));
        assert!(is_audio_file_name("music/ep1.mp3"));
        assert!(!is_audio_file_name("cover.jpg"));
        assert!(!is_audio_file_name("notes.txt"));
    }

    #[test]
    fn test_parse_url() {
        let url = parse_url("http://192.168.0.112:8003").unwrap();
        assert_eq!(url.host, "192.168.0.112");
        assert_eq!(url.port, 8003);
        assert_eq!(url.path_and_query, "/");

        let url = parse_url("http://example.com:8080/v1/audio/transcriptions").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path_and_query, "/v1/audio/transcriptions");
    }

    #[test]
    fn test_detect_mime() {
        assert_eq!(detect_mime_from_filename("test.mp3"), "audio/mpeg");
        assert_eq!(detect_mime_from_filename("test.flac"), "audio/flac");
        assert_eq!(detect_mime_from_filename("test.wav"), "audio/wav");
    }

    #[test]
    fn test_normalize_entry_key() {
        assert_eq!(normalize_entry_key("Music/Track01.MP3"), "music/track01.mp3");
        assert_eq!(normalize_entry_key("music\\track01.flac"), "music/track01.flac");
    }
}
