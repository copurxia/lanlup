use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::slice;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "lanlu_host")]
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
struct AdjacentFilesResponse {
    #[serde(default, alias = "archiveId", alias = "archive_id")]
    archive_id: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AdjacentTextResponse {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Default)]
struct ParsedXml {
    tags: HashMap<String, Vec<String>>,
    meta_attrs: Vec<Vec<(String, String)>>,
}

#[derive(Debug, Default)]
struct XmlElementContext {
    name: String,
    text: String,
    attrs: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
struct OpfOptions {
    merge_existing: bool,
    include_artist: bool,
    include_timestamp: bool,
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
        "name": "OPF Sidecar (Rust/WASM)",
        "type": "metadata",
        "namespace": "opfmeta",
        "author": "codex",
        "version": "0.1.0",
        "description": "Rust/WASM port of the OPF sidecar metadata plugin.",
        "permissions": [
            "metadata.read_input",
            "archive.list_adjacent_files",
            "archive.read_adjacent_text",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "sidecar_name", "type": "string", "desc": "Preferred OPF sidecar filename", "default_value": "metadata.opf"},
            {"name": "merge_existing", "type": "bool", "desc": "Merge extracted tags with existing archive tags", "default_value": "1"},
            {"name": "include_artist", "type": "bool", "desc": "Add artist:<dc:creator> tag", "default_value": "1"},
            {"name": "include_timestamp", "type": "bool", "desc": "Map calibre:timestamp to metadata.updated_at (unix epoch seconds)", "default_value": "1"}
        ],
        "oneshot_arg": "Optional OPF filename in archive directory (e.g. metadata.opf)",
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
        return Err("opfmeta-rs only supports Metadata plugins".to_string());
    }

    let archive_id = input.target_id.trim();
    if archive_id.is_empty() {
        return Err("Missing targetId".to_string());
    }

    let options = OpfOptions {
        merge_existing: read_bool_param(&input.params, "merge_existing", true),
        include_artist: read_bool_param(&input.params, "include_artist", true),
        include_timestamp: read_bool_param(&input.params, "include_timestamp", true),
    };

    let preferred = first_non_empty(&[
        input.oneshot_param.trim().to_string(),
        read_string_param(&input.params, "sidecar_name", "metadata.opf"),
        "metadata.opf".to_string(),
    ]);

    HostBridge::progress(5, "扫描归档旁路元数据文件...");
    let listing = HostBridge::list_adjacent_files(archive_id)?;
    let _ = &listing.archive_id;
    if listing.files.is_empty() {
        return Err("No adjacent files found".to_string());
    }

    let opf_file = pick_opf_file(&listing.files, &preferred)
        .ok_or_else(|| format!("No OPF sidecar found. Preferred: {preferred}"))?;

    HostBridge::progress(35, &format!("读取 {opf_file} ..."));
    let xml = HostBridge::read_adjacent_text(archive_id, &opf_file)?;
    let parsed = parse_xml(&xml);

    let title = read_first_tag(&parsed, "title");
    let summary = read_first_tag(&parsed, "description");
    let mut extracted_tags = read_all_tags(&parsed, "subject");
    if options.include_artist {
        let creator = read_first_tag(&parsed, "creator");
        if !creator.is_empty() {
            extracted_tags.push(format!("artist:{creator}"));
        }
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

    if !title.is_empty() {
        metadata.insert("title".to_string(), Value::String(title));
    }
    if !summary.is_empty() {
        metadata.insert("description".to_string(), Value::String(summary));
    }
    metadata.insert("tags".to_string(), json!(final_tags));
    if options.include_timestamp {
        if let Some(updated_at) = read_calibre_timestamp(&parsed) {
            metadata.insert(
                "updated_at".to_string(),
                Value::String(updated_at.to_string()),
            );
        }
    }
    metadata.insert("children".to_string(), Value::Array(vec![]));
    metadata.remove("archive");
    metadata.remove("archive_id");

    HostBridge::progress(100, "OPF 元数据导入完成");
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

    fn list_adjacent_files(archive_id: &str) -> Result<AdjacentFilesResponse, String> {
        Self::call(
            "archive.list_adjacent_files",
            json!({ "archive_id": archive_id, "levels_up": 0 }),
        )
    }

    fn read_adjacent_text(archive_id: &str, file_name: &str) -> Result<String, String> {
        let response: AdjacentTextResponse = Self::call(
            "archive.read_adjacent_text",
            json!({ "archive_id": archive_id, "file_name": file_name, "levels_up": 0 }),
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

fn pick_opf_file(files: &[String], preferred: &str) -> Option<String> {
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
        .find(|file| file.to_ascii_lowercase().ends_with(".opf"))
        .cloned()
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
    let normalized = node.text.trim();
    if !normalized.is_empty() {
        parsed
            .tags
            .entry(node.name.clone())
            .or_default()
            .push(normalized.to_string());
    }
    if node.name == "meta" && !node.attrs.is_empty() {
        parsed.meta_attrs.push(node.attrs.clone());
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

fn read_all_tags(parsed: &ParsedXml, tag_name: &str) -> Vec<String> {
    parsed
        .tags
        .get(tag_name)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn read_calibre_timestamp(parsed: &ParsedXml) -> Option<i64> {
    let raw = parsed.meta_attrs.iter().find_map(|attrs| {
        let name = attrs
            .iter()
            .find(|(key, _)| key == "name")
            .map(|(_, value)| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if name != "calibre:timestamp" {
            return None;
        }
        attrs
            .iter()
            .find(|(key, _)| key == "content")
            .map(|(_, value)| value.trim().to_string())
    })?;
    parse_timestamp_to_epoch(&raw)
}

fn parse_timestamp_to_epoch(raw: &str) -> Option<i64> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    let (date_part, time_part) = if let Some((date, time)) = text.split_once('T') {
        (date, time)
    } else if let Some((date, time)) = text.split_once(' ') {
        (date, time)
    } else {
        return None;
    };

    let (year, month, day) = parse_date_parts(date_part)?;
    validate_ymd(year, month, day)?;

    let mut time_core = time_part.trim();
    let mut offset_seconds = 0i64;
    if let Some(stripped) = time_core.strip_suffix('Z') {
        time_core = stripped;
    } else if let Some((core, offset)) = split_timezone_suffix(time_core) {
        time_core = core;
        offset_seconds = parse_timezone_offset(offset)?;
    }

    let (hour, minute, second) = parse_time_parts(time_core)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64 - offset_seconds)
}

fn split_timezone_suffix(raw: &str) -> Option<(&str, &str)> {
    let bytes = raw.as_bytes();
    for index in 1..bytes.len() {
        if bytes[index] == b'+' || bytes[index] == b'-' {
            return Some((&raw[..index], &raw[index..]));
        }
    }
    None
}

fn parse_timezone_offset(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let sign = match trimmed.as_bytes()[0] {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let rest = &trimmed[1..];
    let (hours, minutes) = if let Some((hh, mm)) = rest.split_once(':') {
        (hh, mm)
    } else if rest.len() == 4 {
        (&rest[..2], &rest[2..])
    } else if rest.len() == 2 {
        (rest, "0")
    } else {
        return None;
    };
    let hour = hours.parse::<u32>().ok()?;
    let minute = minutes.parse::<u32>().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(sign * (hour as i64 * 3_600 + minute as i64 * 60))
}

fn parse_date_parts(raw: &str) -> Option<(i32, u32, u32)> {
    let mut parts = raw.split('-');
    let year = parts.next()?.trim().parse::<i32>().ok()?;
    let month = parts.next()?.trim().parse::<u32>().ok()?;
    let day = parts.next()?.trim().parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((year, month, day))
}

fn parse_time_parts(raw: &str) -> Option<(u32, u32, u32)> {
    let main = raw.split('.').next()?.trim();
    let mut parts = main.split(':');
    let hour = parts.next()?.trim().parse::<u32>().ok()?;
    let minute = parts.next()?.trim().parse::<u32>().ok()?;
    let second = parts.next()?.trim().parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((hour, minute, second))
}

fn validate_ymd(year: i32, month: u32, day: u32) -> Option<()> {
    if !(1..=12).contains(&month) || day == 0 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }
    Some(())
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
    fn parses_opf_core_fields() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns:dc="http://purl.org/dc/elements/1.1/">
  <metadata>
    <dc:title>Example Title</dc:title>
    <dc:description>Example Summary</dc:description>
    <dc:subject>tag:a</dc:subject>
    <dc:subject>tag:b</dc:subject>
    <dc:creator>Jane Doe</dc:creator>
    <meta name="calibre:timestamp" content="2025-03-01T12:34:56+00:00" />
  </metadata>
</package>"#;
        let parsed = parse_xml(xml);

        assert_eq!(read_first_tag(&parsed, "title"), "Example Title");
        assert_eq!(read_first_tag(&parsed, "description"), "Example Summary");
        assert_eq!(read_all_tags(&parsed, "subject"), vec!["tag:a", "tag:b"]);
        assert_eq!(read_first_tag(&parsed, "creator"), "Jane Doe");
        assert_eq!(read_calibre_timestamp(&parsed), Some(1_740_832_496));
    }
}
