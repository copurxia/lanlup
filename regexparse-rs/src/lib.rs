use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashSet;
use std::slice;

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
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

const COMMON_EXTRANEOUS_VALUES: &[&str] = &[
    "uncensored",
    "decensored",
    "ongoing",
    "pixiv",
    "twitter",
    "fanbox",
    "cosplay",
    "digital",
];

const PLUGIN_TAG_NS: &str = "parsed:";

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
        "name": "Filename Parsing",
        "type": "metadata",
        "namespace": "regexparse",
        "author": "codex",
        "version": "1.0.0",
        "description": "Derive tags from the filename of the given archive. Follows the doujinshi naming standard (Event) [Artist] TITLE (Series) [Language]. Supports custom regex with named capture groups.",
        "permissions": [
            "metadata.read_input",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {
                "name": "check_trailing_tags",
                "type": "bool",
                "desc": "If the filename ends with a pair of curly braces, return the contents inside them as a list of simple tags",
                "default_value": "0"
            },
            {
                "name": "keep_all_captures",
                "type": "bool",
                "desc": "Capture everything between parentheses/brackets and make it available under the parsed: namespace",
                "default_value": "0"
            },
            {
                "name": "regex",
                "type": "string",
                "desc": "Regex to use for parsing",
                "default_value": r#"(\((?<event>[^\(\[]+)\))?\s*(\[(?<artist>[^\]]+)\])?\s*(?<title>[^\(\[]+)\s*(\((?<series>[^\(\[\)]+)\))?\s*(\[(?<language>[^\]]+)\])?(?<tail>.*)?"#
            }
        ],
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
        return Err("regexparse-rs only supports Metadata plugins".to_string());
    }

    let filename = input
        .metadata
        .get("filename")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if filename.is_empty() {
        return Err("Missing filename in metadata".to_string());
    }

    let (tags, title) = parse_filename(&filename, &input.params, &input.oneshot_param)?;

    let mut metadata = ensure_metadata_object(input.metadata);
    if !title.is_empty() {
        metadata.insert("title".to_string(), Value::String(title));
    }
    metadata.insert("tags".to_string(), json!(tags));
    metadata.insert("children".to_string(), Value::Array(vec![]));
    metadata.remove("archive");
    metadata.remove("archive_id");

    Ok(Value::Object(metadata))
}

fn parse_filename(filename: &str, params: &Value, oneshot_param: &str) -> Result<(Vec<String>, String), String> {
    let mut filename = filename.replace('_', " ");

    // Remove extension if present (like Perl basename without ext)
    if let Some(dot) = filename.rfind('.') {
        filename.truncate(dot);
    }

    let default_regex = r#"(\((?<event>[^\(\[]+)\))?\s*(\[(?<artist>[^\]]+)\])?\s*(?<title>[^\(\[]+)\s*(\((?<series>[^\(\[\)]+)\))?\s*(\[(?<language>[^\]]+)\])?(?<tail>.*)?"#;

    let regex_str = if !oneshot_param.trim().is_empty() {
        oneshot_param.trim()
    } else {
        params
            .get("regex")
            .and_then(Value::as_str)
            .unwrap_or(default_regex)
    };

    let regex = Regex::new(regex_str).map_err(|e| format!("invalid regex: {e}"))?;
    let caps = regex.captures(&filename).ok_or("regex did not match")?;

    let title = caps
        .name("title")
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let tail = caps
        .name("tail")
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();

    let check_trailing_tags = read_bool_param(params, "check_trailing_tags", false);
    let keep_all_captures = read_bool_param(params, "keep_all_captures", false);

    let mut trailing_tags = String::new();
    let mut other_captures = String::new();
    let mut remaining_tail = tail.clone();

    if check_trailing_tags && !remaining_tail.is_empty() {
        let trailing_re = Regex::new(r"^(?<head>.*)\{(?<ttags>[^}]*)\}$").unwrap();
        if let Some(tcaps) = trailing_re.captures(&remaining_tail) {
            trailing_tags = tcaps
                .name("ttags")
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            remaining_tail = tcaps
                .name("head")
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
        }
    }

    if keep_all_captures && !remaining_tail.is_empty() {
        let items_re = Regex::new(r"\(([^)]+)\)|\{([^}]+)\}|\[([^]]+)\]").unwrap();
        let items: Vec<String> = items_re
            .captures_iter(&remaining_tail)
            .filter_map(|c| {
                c.get(1)
                    .or(c.get(2))
                    .or(c.get(3))
                    .map(|m| m.as_str().trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .collect();
        other_captures = items.join(",");
    }

    let mut tags = Vec::new();

    // Process all named capture groups dynamically
    for name in regex.capture_names().flatten() {
        if name == "title" || name == "tail" {
            continue;
        }
        let value = match caps.name(name) {
            Some(m) => m.as_str().trim(),
            None => continue,
        };
        if value.is_empty() {
            continue;
        }

        // Strip trailing digits to get the namespace (e.g., artist2 -> artist)
        let namespace = name.trim_end_matches(|c: char| c.is_ascii_digit());

        if namespace == "tag" {
            for part in value.split(',') {
                let t = part.trim();
                if !t.is_empty() {
                    tags.push(t.to_string());
                }
            }
        } else if namespace == "artist" {
            tags.extend(parse_artist_value(value));
        } else if namespace == "event" {
            tags.push(format!("event:{}", value));
        } else {
            tags.extend(parse_captured_value_for_namespace(value, &format!("{}:", namespace)));
        }
    }

    if !other_captures.is_empty() {
        tags.extend(parse_captured_value_for_namespace(
            &other_captures,
            PLUGIN_TAG_NS,
        ));
    }
    if !trailing_tags.is_empty() {
        tags.extend(parse_captured_value_for_namespace(&trailing_tags, ""));
    }

    if !keep_all_captures {
        tags.retain(|t| !t.starts_with(PLUGIN_TAG_NS));
    }

    // Stable deduplication
    let mut seen = HashSet::new();
    tags.retain(|t| seen.insert(t.clone()));

    Ok((tags, title))
}

fn parse_artist_value(artist: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut remaining = artist;

    // Special case for "Circle (Artist)" format
    if let Some(open) = remaining.rfind(" (") {
        if let Some(close) = remaining[open..].find(')') {
            let circle = remaining[..open].trim();
            let inner = remaining[open + 2..open + close].trim();
            if !circle.is_empty() {
                tags.push(format!("group:{}", circle));
            }
            remaining = inner;
        }
    }

    tags.extend(parse_captured_value_for_namespace(remaining, "artist:"));
    tags
}

fn parse_captured_value_for_namespace(capture: &str, namespace: &str) -> Vec<String> {
    capture
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|item| classify_item(item, namespace))
        .collect()
}

fn classify_item(item: &str, namespace: &str) -> String {
    let lower = item.to_ascii_lowercase();
    let is_extraneous = COMMON_EXTRANEOUS_VALUES.contains(&lower.as_str());
    let is_number = item.parse::<f64>().is_ok();

    if !namespace.is_empty() && (is_extraneous || is_number) {
        format!("{}{}", PLUGIN_TAG_NS, item)
    } else {
        format!("{}{}", namespace, item)
    }
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

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    slice::from_raw_parts(ptr as *const u8, len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_regex_standard_filename() {
        let params = json!({});
        let (tags, title) = parse_filename(
            "[Artist] Title (Series) [Language].zip",
            &params,
            "",
        )
        .unwrap();
        assert_eq!(title, "Title");
        assert!(tags.contains(&"artist:Artist".to_string()));
        assert!(tags.contains(&"series:Series".to_string()));
        assert!(tags.contains(&"language:Language".to_string()));
    }

    #[test]
    fn test_default_regex_with_event() {
        let params = json!({});
        let (tags, title) = parse_filename(
            "(Event) [Artist] Title (Series) [Language].cbz",
            &params,
            "",
        )
        .unwrap();
        assert_eq!(title, "Title");
        assert!(tags.contains(&"event:Event".to_string()));
        assert!(tags.contains(&"artist:Artist".to_string()));
        assert!(tags.contains(&"series:Series".to_string()));
    }

    #[test]
    fn test_artist_circle_format() {
        let params = json!({});
        let (tags, title) = parse_filename(
            "[Circle (Artist)] Title.zip",
            &params,
            "",
        )
        .unwrap();
        assert!(tags.contains(&"group:Circle".to_string()));
        assert!(tags.contains(&"artist:Artist".to_string()));
    }

    #[test]
    fn test_trailing_tags() {
        let params = json!({"check_trailing_tags": true});
        let (tags, title) = parse_filename(
            "[Artist] Title (Series) [Language] {tag1, tag2}.zip",
            &params,
            "",
        )
        .unwrap();
        assert_eq!(title, "Title");
        assert!(tags.contains(&"series:Series".to_string()));
        assert!(tags.contains(&"language:Language".to_string()));
        assert!(tags.contains(&"tag1".to_string()));
        assert!(tags.contains(&"tag2".to_string()));
    }

    #[test]
    fn test_keep_all_captures() {
        let params = json!({"keep_all_captures": true});
        let (tags, title) = parse_filename(
            "[Artist] Title (Series) [Language] (extra1) [extra2].zip",
            &params,
            "",
        )
        .unwrap();
        assert_eq!(title, "Title");
        assert!(tags.contains(&"series:Series".to_string()));
        assert!(tags.contains(&"language:Language".to_string()));
        assert!(tags.contains(&"parsed:extra1".to_string()));
        assert!(tags.contains(&"parsed:extra2".to_string()));
    }

    #[test]
    fn test_extraneous_filtering_keep_false() {
        let params = json!({});
        let (tags, _) = parse_filename(
            "[Artist] Title (uncensored, 123).zip",
            &params,
            "",
        )
        .unwrap();
        // With keep_all_captures=false, parsed: tags are filtered out
        assert!(!tags.contains(&"parsed:uncensored".to_string()));
        assert!(!tags.contains(&"parsed:123".to_string()));
        // They should not appear as series: either because they are filtered into parsed: then dropped
        assert!(!tags.contains(&"series:uncensored".to_string()));
        assert!(!tags.contains(&"series:123".to_string()));
    }

    #[test]
    fn test_extraneous_filtering_keep_true() {
        let params = json!({"keep_all_captures": true});
        let (tags, _) = parse_filename(
            "[Artist] Title (uncensored, 123).zip",
            &params,
            "",
        )
        .unwrap();
        assert!(tags.contains(&"parsed:uncensored".to_string()));
        assert!(tags.contains(&"parsed:123".to_string()));
    }

    #[test]
    fn test_underscore_replacement() {
        let params = json!({});
        let (tags, title) = parse_filename(
            "[Artist_Name] My_Title.zip",
            &params,
            "",
        )
        .unwrap();
        assert_eq!(title, "My Title");
        assert!(tags.contains(&"artist:Artist Name".to_string()));
    }

    #[test]
    fn test_no_match() {
        let params = json!({});
        let result = parse_filename("", &params, "");
        assert!(result.is_err());
    }
}
