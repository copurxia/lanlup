use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
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
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct TagListItem {
    id: i64,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    translation_text: String,
}

#[derive(Debug, Deserialize)]
struct TagsListResponse {
    #[serde(default)]
    total: i64,
    #[serde(default)]
    items: Vec<TagListItem>,
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

    fn call(method: &str, params: Value) -> Result<Value, String> {
        let req = json!({
            "method": method,
            "params": params,
        });
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 {
            return Err(Self::read_error());
        }
        Self::read_response()
    }

    fn call_typed<T: DeserializeOwned>(method: &str, params: Value) -> Result<T, String> {
        let value = Self::call(method, params)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    fn list_tags_page(lang: &str, limit: i64, offset: i64) -> Result<TagsListResponse, String> {
        Self::call_typed(
            "tags.list",
            json!({
                "lang": lang,
                "limit": limit,
                "offset": offset,
            }),
        )
    }

    fn merge_tags(source_id: i64, target_id: i64, delete_source: bool) -> Result<(), String> {
        let _ = Self::call(
            "tags.merge",
            json!({
                "sourceId": source_id,
                "targetId": target_id,
                "deleteSource": delete_source,
            }),
        )?;
        Ok(())
    }

    fn read_response() -> Result<Value, String> {
        let len = unsafe { host_response_len() };
        if len < 0 {
            return Err("host_response_len returned negative length".to_string());
        }
        if len == 0 {
            return Ok(Value::Null);
        }

        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buf.as_mut_ptr() as i32, len) };
        if read < 0 {
            return Err("host_response_read failed".to_string());
        }
        serde_json::from_slice(&buf[..read as usize]).map_err(|e| e.to_string())
    }

    fn read_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 {
            return "host call failed".to_string();
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buf.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return "host call failed".to_string();
        }
        String::from_utf8_lossy(&buf[..read as usize]).to_string()
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
        "name": "Tag Merge (Rust/WASM)",
        "type": "script",
        "namespace": "tag_merge",
        "author": "lanlu",
        "version": "2.1.0-rs",
        "description": "Merge duplicate tags based on translation/name rules.",
        "permissions": [
            "tags.list",
            "tags.merge",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "lang", "type": "string", "desc": "Translation language to use", "default_value": "zh"},
            {"name": "page_size", "type": "int", "desc": "Pagination size for tags.list", "default_value": "1000"},
            {"name": "dry_run", "type": "bool", "desc": "Only compute merges; do not change DB", "default_value": "1"},
            {"name": "delete_source", "type": "bool", "desc": "Delete source tag after merge", "default_value": "1"},
            {"name": "max_merges", "type": "int", "desc": "Max merges to apply (0 = unlimited)", "default_value": "0"},
            {"name": "merge_source_prefixes", "type": "string", "desc": "JSON array or comma/newline separated namespaces treated as merge sources", "default_value": "[\"other\",\"\"]"}
        ],
        "cron_enabled": false,
        "cron_expression": "0 3 * * *",
        "cron_priority": 50,
        "cron_timeout_seconds": 3600,
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
    if !input.plugin_type.trim().eq_ignore_ascii_case("script") {
        return Err("tagmerge-rs only supports Script plugins".to_string());
    }

    let lang = read_string_param(&input.params, "lang", "zh");
    let page_size = read_int_param(&input.params, "page_size", 1000).clamp(1, 2000);
    let dry_run = read_bool_param(&input.params, "dry_run", true);
    let delete_source = read_bool_param(&input.params, "delete_source", true);
    let max_merges = read_int_param(&input.params, "max_merges", 0).max(0);
    let merge_source_prefixes = parse_merge_source_prefixes(input.params.get("merge_source_prefixes"));

    HostBridge::log(
        1,
        &format!(
            "tag_merge started lang={lang} pageSize={page_size} dryRun={dry_run} deleteSource={delete_source} maxMerges={max_merges}"
        ),
    );

    let mut tags: Vec<TagListItem> = Vec::new();
    let mut translation_index: HashMap<String, i64> = HashMap::new();
    let mut canonical_candidates: HashMap<String, HashSet<i64>> = HashMap::new();
    let mut id_to_ns: HashMap<i64, String> = HashMap::new();

    let first_page = HostBridge::list_tags_page(&lang, page_size, 0)?;
    let total = first_page.total.max(0);

    ingest_items(
        &first_page.items,
        &merge_source_prefixes,
        &mut tags,
        &mut translation_index,
        &mut canonical_candidates,
        &mut id_to_ns,
    );

    let mut offset = page_size;
    while offset < total {
        let pct = ((offset * 60) / total.max(1)) as i32;
        HostBridge::progress(pct.clamp(0, 60), &format!("Loading tags {offset}/{total}"));
        let page = HostBridge::list_tags_page(&lang, page_size, offset)?;
        ingest_items(
            &page.items,
            &merge_source_prefixes,
            &mut tags,
            &mut translation_index,
            &mut canonical_candidates,
            &mut id_to_ns,
        );
        offset += page_size;
    }

    HostBridge::progress(65, &format!("Building merge plan (tags={})", tags.len()));

    let mut source_to_target: HashMap<i64, i64> = HashMap::new();
    for tag in &tags {
        let source_id = tag.id;
        if source_id <= 0 {
            continue;
        }

        let ns = tag.namespace.trim().to_string();
        let name_key = norm(&tag.name);
        if name_key.is_empty() {
            continue;
        }

        if is_merge_source_namespace(&ns, &merge_source_prefixes) {
            let Some(set) = canonical_candidates.get(&name_key) else {
                continue;
            };
            if set.len() != 1 {
                continue;
            }
            let Some(target_id) = set.iter().next().copied() else {
                continue;
            };
            if target_id > 0 && target_id != source_id {
                source_to_target.insert(source_id, target_id);
            }
            continue;
        }

        let key = ns_key(&ns, &name_key);
        let Some(target_id) = translation_index.get(&key).copied() else {
            continue;
        };
        if target_id <= 0 || target_id == source_id {
            continue;
        }
        source_to_target.insert(source_id, target_id);
    }

    let mut merges: Vec<(i64, i64)> = Vec::new();
    for (source_id, target_id) in &source_to_target {
        let final_target = resolve_target(*target_id, &source_to_target);
        if final_target == *source_id {
            continue;
        }

        let source_ns = id_to_ns.get(source_id).cloned().unwrap_or_default();
        let target_ns = id_to_ns.get(&final_target).cloned().unwrap_or_default();
        if is_merge_source_namespace(&source_ns, &merge_source_prefixes)
            && is_merge_source_namespace(&target_ns, &merge_source_prefixes)
        {
            continue;
        }

        merges.push((*source_id, final_target));
    }

    merges.sort_by_key(|(source_id, _)| *source_id);

    HostBridge::log(
        1,
        &format!(
            "merge plan built candidates={} merges={}",
            source_to_target.len(),
            merges.len()
        ),
    );

    let merge_plan_preview: Vec<Value> = merges
        .iter()
        .take(200)
        .map(|(source_id, target_id)| json!({ "sourceId": source_id, "targetId": target_id }))
        .collect();

    if dry_run {
        return Ok(json!({
            "dry_run": true,
            "total_tags": tags.len(),
            "planned_merges": merges.len(),
            "merge_plan": {
                "total": merges.len(),
                "items": merge_plan_preview,
            }
        }));
    }

    let to_apply = if max_merges > 0 {
        merges.iter().take(max_merges as usize).copied().collect::<Vec<_>>()
    } else {
        merges.clone()
    };

    let mut applied = 0usize;
    let apply_len = to_apply.len();
    let total_apply = apply_len.max(1);
    for (source_id, target_id) in to_apply {
        if applied % 50 == 0 {
            let pct = 70 + ((applied * 30) / total_apply) as i32;
            HostBridge::progress(pct.clamp(70, 100), &format!("Merging {applied}/{apply_len}"));
        }
        HostBridge::merge_tags(source_id, target_id, delete_source)?;
        applied += 1;
    }

    Ok(json!({
        "dry_run": false,
        "total_tags": tags.len(),
        "planned_merges": merges.len(),
        "applied_merges": applied,
        "merge_plan": {
            "total": merges.len(),
            "items": merge_plan_preview,
        }
    }))
}

fn ingest_items(
    items: &[TagListItem],
    merge_source_prefixes: &HashSet<String>,
    tags: &mut Vec<TagListItem>,
    translation_index: &mut HashMap<String, i64>,
    canonical_candidates: &mut HashMap<String, HashSet<i64>>,
    id_to_ns: &mut HashMap<i64, String>,
) {
    for item in items {
        let id = item.id;
        if id <= 0 {
            continue;
        }
        let ns = item.namespace.trim().to_string();
        let name = item.name.trim().to_string();
        let tr = item.translation_text.trim().to_string();

        tags.push(TagListItem {
            id,
            namespace: ns.clone(),
            name: name.clone(),
            translation_text: tr.clone(),
        });
        id_to_ns.insert(id, ns.clone());

        if !is_merge_source_namespace(&ns, merge_source_prefixes) {
            let name_key = norm(&name);
            if !name_key.is_empty() {
                canonical_candidates.entry(name_key).or_default().insert(id);
            }

            let tr_key = norm(&tr);
            if !tr_key.is_empty() {
                canonical_candidates.entry(tr_key.clone()).or_default().insert(id);

                let key = ns_key(&ns, &tr_key);
                match translation_index.get(&key).copied() {
                    None => {
                        translation_index.insert(key, id);
                    }
                    Some(prev) if prev != id => {
                        translation_index.insert(key, 0);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn resolve_target(id: i64, source_to_target: &HashMap<i64, i64>) -> i64 {
    let mut current = id;
    let mut seen = HashSet::<i64>::new();
    loop {
        let Some(next) = source_to_target.get(&current).copied() else {
            return current;
        };
        if seen.contains(&next) {
            return current;
        }
        seen.insert(next);
        current = next;
    }
}

fn parse_merge_source_prefixes(value: Option<&Value>) -> HashSet<String> {
    let mut out = HashSet::<String>::new();

    let add_value = |set: &mut HashSet<String>, raw: &Value| {
        if raw.is_null() {
            return;
        }
        if let Some(s) = raw.as_str() {
            set.insert(normalize_namespace(s));
        } else {
            set.insert(normalize_namespace(raw.to_string()));
        }
    };

    match value {
        Some(Value::Array(items)) => {
            for item in items {
                add_value(&mut out, item);
            }
            if !out.is_empty() {
                return out;
            }
        }
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                out.insert("other".to_string());
                out.insert("".to_string());
                return out;
            }
            if let Ok(parsed) = serde_json::from_str::<Vec<Value>>(trimmed) {
                for item in &parsed {
                    add_value(&mut out, item);
                }
                if !out.is_empty() {
                    return out;
                }
            }
            for piece in trimmed.split(|c| c == ',' || c == '\n') {
                let token = piece.trim();
                if token.is_empty() {
                    continue;
                }
                out.insert(normalize_namespace(token));
            }
            if !out.is_empty() {
                return out;
            }
        }
        Some(other) => {
            add_value(&mut out, other);
            if !out.is_empty() {
                return out;
            }
        }
        None => {}
    }

    out.insert("other".to_string());
    out.insert("".to_string());
    out
}

fn normalize_namespace(raw: impl AsRef<str>) -> String {
    raw.as_ref().trim().to_ascii_lowercase()
}

fn is_merge_source_namespace(ns: &str, merge_source_prefixes: &HashSet<String>) -> bool {
    merge_source_prefixes.contains(&normalize_namespace(ns))
}

fn norm(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn ns_key(ns: &str, value: &str) -> String {
    format!("{}\u{0000}{}", ns, value)
}

fn read_string_param(params: &Value, key: &str, default_value: &str) -> String {
    let value = params.get(key).cloned().unwrap_or_else(|| Value::String(default_value.to_string()));
    let text = match value {
        Value::String(s) => s,
        other => other.to_string(),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        default_value.to_string()
    } else {
        trimmed.to_string()
    }
}

fn read_int_param(params: &Value, key: &str, default_value: i64) -> i64 {
    match params.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(default_value),
        Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(default_value),
        Some(Value::Bool(v)) => {
            if *v {
                1
            } else {
                0
            }
        }
        _ => default_value,
    }
}

fn read_bool_param(params: &Value, key: &str, default_value: bool) -> bool {
    match params.get(key) {
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(n)) => n.as_i64().map(|v| v != 0).unwrap_or(default_value),
        Some(Value::String(s)) => {
            let normalized = s.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "" | "0" | "false" | "no" | "n" | "off" => false,
                "1" | "true" | "yes" | "y" | "on" => true,
                _ => default_value,
            }
        }
        _ => default_value,
    }
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
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error = message.into_bytes();
    });
    0
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr as *const u8, len as usize)
    }
}
