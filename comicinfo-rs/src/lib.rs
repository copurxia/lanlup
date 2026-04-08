use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::slice;
use time::macros::format_description;
use time::OffsetDateTime;

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

#[derive(Debug, Deserialize)]
struct TextResponse {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Default)]
struct ParsedXml {
    tags: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default)]
struct XmlElementContext {
    name: String,
    text: String,
    attrs: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
struct ComicInfoOptions {
    merge_existing: bool,
    include_writer_artist: bool,
    include_web_source: bool,
    include_release_date: bool,
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
        "name": "ComicInfo (Rust/WASM)",
        "type": "metadata",
        "namespace": "comicinfo",
        "author": "codex",
        "version": "0.1.0",
        "description": "Rust/WASM port of the ComicInfo metadata plugin.",
        "permissions": [
            "metadata.read_input",
            "archive.list_files",
            "archive.read_text",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "comicinfo_name", "type": "string", "desc": "Preferred ComicInfo filename inside archive", "default_value": "ComicInfo.xml"},
            {"name": "merge_existing", "type": "bool", "desc": "Merge extracted tags with existing archive tags", "default_value": "1"},
            {"name": "include_writer_artist", "type": "bool", "desc": "Add artist:<Writer> tag", "default_value": "1"},
            {"name": "include_web_source", "type": "bool", "desc": "Map <Web> to metadata.source_url", "default_value": "1"},
            {"name": "include_release_date", "type": "bool", "desc": "Map Year/Month/Day to metadata.release_at (UTC timestamp string)", "default_value": "1"}
        ],
        "oneshot_arg": "Optional ComicInfo filename inside archive (e.g. ComicInfo.xml)",
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
        return Err("comicinfo-rs only supports Metadata plugins".to_string());
    }

    let archive_id = input.target_id.trim();
    if archive_id.is_empty() {
        return Err("Missing targetId".to_string());
    }

    let options = ComicInfoOptions {
        merge_existing: read_bool_param(&input.params, "merge_existing", true),
        include_writer_artist: read_bool_param(&input.params, "include_writer_artist", true),
        include_web_source: read_bool_param(&input.params, "include_web_source", true),
        include_release_date: read_bool_param(&input.params, "include_release_date", true),
    };

    let preferred = first_non_empty(&[
        input.oneshot_param.trim().to_string(),
        read_string_param(&input.params, "comicinfo_name", "ComicInfo.xml"),
        "ComicInfo.xml".to_string(),
    ]);

    HostBridge::progress(5, "扫描归档内 ComicInfo 元数据文件...");
    let listing = HostBridge::list_files(archive_id)?;
    let _ = &listing.archive_id;
    if listing.files.is_empty() {
        return Err("No files found in archive".to_string());
    }

    let entry_name = pick_comicinfo_entry(&listing.files, &preferred)
        .ok_or_else(|| format!("No ComicInfo.xml found in archive. Preferred: {preferred}"))?;

    HostBridge::progress(35, &format!("读取 {entry_name} ..."));
    let xml = HostBridge::read_text(archive_id, &entry_name)?;
    let parsed = parse_xml(&xml);

    let title = read_first_tag(&parsed, "title");
    let series = read_first_tag(&parsed, "series");
    let summary = read_first_tag(&parsed, "summary");
    let writer = read_first_tag(&parsed, "writer");
    let web = read_first_tag(&parsed, "web");
    let mut extracted_tags = split_csv_tags(&read_first_tag(&parsed, "tags"));
    if options.include_writer_artist && !writer.is_empty() {
        extracted_tags.push(format!("artist:{writer}"));
    }
    let extracted_tags = unique_strings(extracted_tags);

    let mut metadata = ensure_metadata_object(input.metadata);
    let mut final_tags = if options.merge_existing {
        let mut tags = metadata_tags(&metadata);
        tags.extend(extracted_tags);
        unique_strings(tags)
    } else {
        extracted_tags
    };
    final_tags = unique_strings(final_tags);

    let next_title = first_non_empty(&[title, series]);
    if !next_title.is_empty() {
        metadata.insert("title".to_string(), Value::String(next_title));
    }
    if !summary.is_empty() {
        metadata.insert("description".to_string(), Value::String(summary));
    }
    metadata.insert("tags".to_string(), json!(final_tags));
    if options.include_web_source && !web.is_empty() {
        metadata.insert("source_url".to_string(), Value::String(web));
    }
    if options.include_release_date {
        if let Some(release_at) = parse_release_at(&parsed) {
            if let Some(release_text) = epoch_seconds_to_utc_timestamp(release_at) {
                metadata.insert("release_at".to_string(), Value::String(release_text));
            }
        }
    }
    metadata.insert("children".to_string(), Value::Array(vec![]));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "ComicInfo 元数据导入完成");
    Ok(Value::Object(metadata))
}

struct HostBridge;

impl HostBridge {
    fn progress(percent: i32, message: &str) {
        let bytes = message.as_bytes();
        unsafe {
            let _ = host_progress(percent, bytes.as_ptr() as i32, bytes.len() as i32);
        }
    }

    #[allow(dead_code)]
    fn log(level: i32, message: &str) {
        let bytes = message.as_bytes();
        unsafe {
            let _ = host_log(level, bytes.as_ptr() as i32, bytes.len() as i32);
        }
    }

    fn list_files(archive_id: &str) -> Result<ArchiveFilesResponse, String> {
        Self::call("archive.list_files", json!({ "archive_id": archive_id }))
    }

    fn read_text(archive_id: &str, entry_name: &str) -> Result<String, String> {
        let response: TextResponse = Self::call(
            "archive.read_text",
            json!({ "archive_id": archive_id, "entry_name": entry_name }),
        )?;
        Ok(response.text)
    }

    fn call<T: DeserializeOwned>(method: &str, params: Value) -> Result<T, String> {
        let request = json!({
            "method": method,
            "params": params,
        });
        let req_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 {
            return Err(read_host_last_error());
        }

        let response_len = unsafe { host_response_len() };
        if response_len <= 0 {
            return Err("empty host response".to_string());
        }
        let mut buffer = vec![0u8; response_len as usize];
        let read = unsafe { host_response_read(buffer.as_mut_ptr() as i32, response_len) };
        if read <= 0 {
            return Err("failed to read host response".to_string());
        }
        serde_json::from_slice::<T>(&buffer[..read as usize]).map_err(|e| e.to_string())
    }
}

fn pick_comicinfo_entry(files: &[String], preferred: &str) -> Option<String> {
    let preferred_trimmed = preferred.trim();
    if !preferred_trimmed.is_empty() {
        if let Some(found) = files.iter().find(|file| file == &preferred_trimmed) {
            return Some(found.clone());
        }
        let lower = preferred_trimmed.to_ascii_lowercase();
        if let Some(found) = files.iter().find(|file| file.to_ascii_lowercase() == lower) {
            return Some(found.clone());
        }
    }

    files
        .iter()
        .find(|file| base_name(file).eq_ignore_ascii_case("comicinfo.xml"))
        .cloned()
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn parse_xml(xml: &str) -> ParsedXml {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut parsed = ParsedXml::default();
    let mut stack = Vec::<XmlElementContext>::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                stack.push(XmlElementContext {
                    name: xml_name(event.name().as_ref()),
                    text: String::new(),
                    attrs: collect_xml_attrs(&reader, &event),
                });
            }
            Ok(Event::Empty(event)) => {
                finalize_xml_node(
                    &mut parsed,
                    &mut stack,
                    XmlElementContext {
                        name: xml_name(event.name().as_ref()),
                        text: String::new(),
                        attrs: collect_xml_attrs(&reader, &event),
                    },
                );
            }
            Ok(Event::Text(event)) => {
                if let Some(current) = stack.last_mut() {
                    if let Ok(text) = event.xml_content() {
                        current.text.push_str(text.as_ref());
                    }
                }
            }
            Ok(Event::CData(event)) => {
                if let Some(current) = stack.last_mut() {
                    if let Ok(text) = event.decode() {
                        current.text.push_str(text.as_ref());
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some(node) = stack.pop() {
                    finalize_xml_node(&mut parsed, &mut stack, node);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return ParsedXml::default(),
            _ => {}
        }
    }

    parsed
}

fn xml_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn collect_xml_attrs(reader: &Reader<&[u8]>, event: &BytesStart<'_>) -> Vec<(String, String)> {
    event
        .attributes()
        .flatten()
        .filter_map(|attr| {
            let key = xml_name(attr.key.as_ref());
            let value = attr
                .decode_and_unescape_value(reader.decoder())
                .ok()?
                .into_owned();
            Some((key, value))
        })
        .collect()
}

fn finalize_xml_node(
    parsed: &mut ParsedXml,
    stack: &mut [XmlElementContext],
    node: XmlElementContext,
) {
    let _ = &node.attrs;
    let normalized = node.text.trim();
    if !normalized.is_empty() {
        parsed
            .tags
            .entry(node.name.clone())
            .or_default()
            .push(normalized.to_string());
    }
    if let Some(parent) = stack.last_mut() {
        parent.text.push_str(&node.text);
    }
}

fn read_first_tag(parsed: &ParsedXml, tag_name: &str) -> String {
    parsed
        .tags
        .get(tag_name)
        .and_then(|values| values.first())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn split_csv_tags(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .collect()
}

fn parse_release_at(parsed: &ParsedXml) -> Option<i64> {
    let year = read_first_tag(parsed, "year").parse::<i32>().ok()?;
    let month = read_first_tag(parsed, "month").parse::<u32>().ok()?;
    let day = match read_first_tag(parsed, "day").trim() {
        "" => 1,
        value => value.parse::<u32>().ok()?,
    };
    if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400)
}

fn epoch_seconds_to_utc_timestamp(secs: i64) -> Option<String> {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(fmt).ok())
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_prime = month as i32 + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era as i64) * 146_097 + (doe as i64) - 719_468
}

fn read_string_param(params: &Value, key: &str, default_value: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

fn read_bool_param(params: &Value, key: &str, default_value: bool) -> bool {
    match params.get(key) {
        None | Some(Value::Null) => default_value,
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(v)) => v.as_i64().unwrap_or(0) != 0,
        Some(Value::String(v)) => match v.trim().to_ascii_lowercase().as_str() {
            "" => default_value,
            "0" | "false" | "no" | "n" | "off" => false,
            "1" | "true" | "yes" | "y" | "on" => true,
            _ => default_value,
        },
        _ => default_value,
    }
}

fn ensure_metadata_object(value: Value) -> Map<String, Value> {
    let mut map = match value {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    map.entry("title".to_string())
        .or_insert_with(|| Value::String(String::new()));
    map.entry("type".to_string()).or_insert_with(|| json!(0));
    map.entry("description".to_string())
        .or_insert_with(|| Value::String(String::new()));
    map.entry("tags".to_string())
        .or_insert_with(|| Value::Array(vec![]));
    map.entry("assets".to_string())
        .or_insert_with(|| Value::Array(vec![]));
    map.entry("archive".to_string())
        .or_insert_with(|| Value::Array(vec![]));
    map
}

fn metadata_tags(map: &Map<String, Value>) -> Vec<String> {
    map.get("tags")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let owned = trimmed.to_string();
        if seen.insert(owned.clone()) {
            out.push(owned);
        }
    }
    out
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error.clear();
    });
}

fn set_error_and_zero(message: String) -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error = message.into_bytes();
    });
    0
}

fn read_host_last_error() -> String {
    let error_len = unsafe { host_last_error_len() };
    if error_len <= 0 {
        return "host_call failed".to_string();
    }
    let mut buffer = vec![0u8; error_len as usize];
    let read = unsafe { host_last_error_read(buffer.as_mut_ptr() as i32, error_len) };
    if read <= 0 {
        return "host_call failed".to_string();
    }
    String::from_utf8_lossy(&buffer[..read as usize]).to_string()
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_fields_and_invalid_release_date() {
        let xml = include_str!(
            "/config/project/lanlu/data/cache/plugins/comicinfo/cache/4cf6b4f9a1a7b3df6bb4ae059f90bf4f889580fa/ComicInfo.xml"
        );
        let parsed = parse_xml(xml);

        assert!(read_first_tag(&parsed, "title").starts_with("(C79)"));
        assert_eq!(read_first_tag(&parsed, "writer"), "rit.");
        assert_eq!(
            split_csv_tags(&read_first_tag(&parsed, "tags"))[0],
            "language:chinese"
        );
        assert_eq!(parse_release_at(&parsed), None);
    }

    #[test]
    fn parses_valid_release_date() {
        let xml = r#"<ComicInfo><Year>2024</Year><Month>2</Month><Day>29</Day></ComicInfo>"#;
        let parsed = parse_xml(xml);
        assert_eq!(parse_release_at(&parsed), Some(1_709_164_800));
    }
}
