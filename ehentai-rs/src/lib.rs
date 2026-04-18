use regex::Regex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;
use time::macros::format_description;
use time::OffsetDateTime;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
use wasmedge_wasi_socket::TcpStream as WasiTcpStream;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!("ehentai-rs requires wasm32-wasip1 (target_os = \"wasi\") for socket support.");

#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
const EH_API_URL: &str = "https://api.e-hentai.org/api.php";
const DEFAULT_TIMEOUT_MS: i32 = 30_000;
const MAX_REDIRECTS: usize = 5;
const AUTH_DATA_KEY: &str = "__lanlu.phase.ehlogin.data";

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

#[derive(Clone, Debug, Default, Deserialize)]
struct EhAuthData {
    #[serde(default)]
    ipb_member_id: String,
    #[serde(default)]
    ipb_pass_hash: String,
    #[serde(default)]
    star: String,
    #[serde(default)]
    igneous: String,
}

#[derive(Debug, Deserialize)]
struct TankoubonArchivesResponse {
    #[serde(default)]
    archive_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ArchiveMetadataResponse {
    #[serde(default)]
    archive_id: String,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
struct CoverExportResponse {
    #[serde(default)]
    archive_id: String,
    #[serde(default)]
    entry_name: String,
    #[serde(default)]
    original_path: String,
    #[serde(default)]
    original_sha1: String,
    #[serde(default)]
    upload_path: String,
    #[serde(default)]
    upload_sha1: String,
}

#[derive(Debug, Deserialize)]
struct HttpResponseData {
    #[serde(default)]
    status: i64,
    #[serde(default)]
    ok: bool,
    #[serde(default, rename = "body_text")]
    text: String,
}

#[derive(Clone, Debug)]
struct Settings {
    lang: String,
    usethumbs: bool,
    search_gid: bool,
    enablepanda: bool,
    jpntitle: bool,
    additionaltags: bool,
    expunged: bool,
    debug: bool,
}

#[derive(Clone, Debug)]
struct LookupContext {
    archive_id: String,
    archive_title: String,
    existing_tags: String,
    thumbnail_hash: String,
    login_cookies: Vec<LoginCookie>,
    oneshot_param: String,
    debug: bool,
}

#[derive(Clone, Debug)]
struct GalleryMatch {
    gid: String,
    token: String,
}

#[derive(Clone, Debug)]
struct SearchPayload {
    tags_csv: String,
    title: String,
    updated_at: String,
}

#[derive(Clone, Debug)]
struct EhGalleryCandidate {
    gid: String,
    token: String,
    title: String,
    url: String,
    cover: String,
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

    fn task_kv_get(key: &str) -> Result<Option<Value>, String> {
        let response = Self::call("task_kv.get", json!({ "key": key }))?;
        let found = response
            .get("found")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !found {
            return Ok(None);
        }
        Ok(response.get("value").cloned())
    }

    fn http_fetch(
        method: &str,
        url: &str,
        body_text: Option<String>,
        cookies: &[LoginCookie],
        extra_headers: &[(&str, String)],
    ) -> Result<HttpResponseData, String> {
        let headers = extra_headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect::<Vec<_>>();
        let response = http_request_text_follow_redirects(
            method,
            url,
            body_text.as_deref().map(str::as_bytes),
            None,
            cookies,
            &headers,
        )?;
        Ok(HttpResponseData {
            status: response.status as i64,
            ok: (200..300).contains(&response.status),
            text: response.text,
        })
    }

    fn export_cover_for_search(archive_id: &str) -> Result<CoverExportResponse, String> {
        Self::call_typed(
            "archive.export_cover_for_search",
            json!({
                "archive_id": archive_id,
                "export_jpeg": true,
                "max_side": 1280,
                "jpeg_quality": 85,
            }),
        )
    }

    fn get_archive_metadata(archive_id: &str) -> Result<Value, String> {
        let response: ArchiveMetadataResponse =
            Self::call_typed("archive.get_metadata", json!({ "archive_id": archive_id }))?;
        let _ = response.archive_id;
        Ok(response.metadata)
    }

    fn list_tankoubon_archives(tankoubon_id: &str) -> Result<Vec<String>, String> {
        let response: TankoubonArchivesResponse =
            Self::call_typed("tankoubon.list_archives", json!({ "tankoubon_id": tankoubon_id }))?;
        Ok(response.archive_ids)
    }

    fn select_index(
        title: &str,
        options: Vec<Value>,
        message: &str,
        default_index: i32,
        timeout_seconds: i32,
    ) -> Result<usize, String> {
        let value = Self::call(
            "ui.select",
            json!({
                "title": title,
                "message": message,
                "default_index": default_index,
                "timeout_seconds": timeout_seconds,
                "options": options,
            }),
        )?;
        let index = value
            .get("index")
            .and_then(Value::as_i64)
            .ok_or_else(|| "ui.select returned missing index".to_string())?;
        usize::try_from(index).map_err(|_| "ui.select returned invalid index".to_string())
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
        Ok(value) => value,
        Err(err) => return set_error_and_zero(format!("invalid plugin input: {err}")),
    };

    let payload = build_result_payload(input);
    let result = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(err) => return set_error_and_zero(format!("failed to encode result: {err}")),
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
        "name": "E-Hentai",
        "type": "metadata",
        "namespace": "ehentai",
        "pre": ["ehlogin"],
        "author": "Difegue and others",
        "version": "2.6",
        "description": "Searches g.e-hentai for tags matching your archive. This plugin will use the source: tag of the archive if it exists.",
        "parameters": [
            {"name": "lang", "type": "string", "desc": "Forced language to use in searches (Japanese won't work due to EH limitations)"},
            {"name": "usethumbs", "type": "bool", "desc": "Fetch using thumbnail first (falls back to title)"},
            {"name": "search_gid", "type": "bool", "desc": "Search using gID from title (falls back to title)"},
            {"name": "enablepanda", "type": "bool", "desc": "Use ExHentai (enable to search for fjorded content without star cookie)"},
            {"name": "jpntitle", "type": "bool", "desc": "Save the original title when available instead of the English or romanised title"},
            {"name": "additionaltags", "type": "bool", "desc": "Fetch additional uploader metadata and set metadata.updated_at (time posted)"},
            {"name": "expunged", "type": "bool", "desc": "Search only expunged galleries"},
            {"name": "debug", "type": "bool", "desc": "Write verbose debug logs to data/logs/plugins.log"},
        ],
        "oneshot_arg": "E-H Gallery URL (Will attach tags matching this exact gallery to your archive)",
        "cooldown": 4,
        "permissions": [
            "net=e-hentai.org",
            "net=exhentai.org",
            "net=api.e-hentai.org",
            "metadata.read_input",
            "archive.get_metadata",
            "tankoubon.list_archives",
            "ui.select",
            "archive.export_cover_for_search",
            "tcp.connect",
            "log.write",
            "progress.report",
            "task_kv.read"
        ],
        "icon": "https://e-hentai.org/favicon.ico",
        "update_url": "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/EHentai.ts"
    })
}

fn build_result_payload(input: PluginInput) -> Value {
    let _ = &input.plugin_type;
    let settings = settings_from_params(&input.params);
    let target_type = normalize_target_type(&input.target_type, &input.params);
    let target_id = if input.target_id.trim().is_empty() {
        param_string(&input.params, "__target_id")
    } else {
        input.target_id.trim().to_string()
    };

    HostBridge::progress(5, "初始化元数据搜索...");
    let auth = match load_eh_auth() {
        Ok(v) => v,
        Err(error) => return json!({ "success": false, "error": error }),
    };
    let login_cookies = build_eh_login_cookies(&auth);

    if is_collection_target_type(&target_type) {
        match process_collection(&input.metadata, &target_id, &settings, &login_cookies) {
            Ok(data) => {
                HostBridge::progress(100, "元数据获取完成");
                json!({ "success": true, "data": data })
            }
            Err(error) => json!({ "success": false, "error": error }),
        }
    } else {
        match process_archive(&input, &target_id, &settings, &login_cookies) {
            Ok(data) => {
                HostBridge::progress(100, "元数据获取完成");
                json!({ "success": true, "data": data })
            }
            Err(error) => json!({ "success": false, "error": error }),
        }
    }
}

fn load_eh_auth() -> Result<EhAuthData, String> {
    let Some(value) = HostBridge::task_kv_get(AUTH_DATA_KEY)? else {
        return Err("Missing E-Hentai auth data in task KV. Ensure ehlogin ran as a pre hook.".to_string());
    };
    serde_json::from_value(value).map_err(|e| format!("Invalid E-Hentai auth data in task KV: {e}"))
}

fn build_eh_login_cookies(auth: &EhAuthData) -> Vec<LoginCookie> {
    let member_id = auth.ipb_member_id.trim();
    let pass_hash = auth.ipb_pass_hash.trim();
    if member_id.is_empty() || pass_hash.is_empty() {
        return Vec::new();
    }

    let mut cookies = Vec::new();
    for domain in ["e-hentai.org", "exhentai.org"] {
        cookies.push(LoginCookie {
            name: "ipb_member_id".to_string(),
            value: member_id.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
        });
        cookies.push(LoginCookie {
            name: "ipb_pass_hash".to_string(),
            value: pass_hash.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
        });
        if !auth.star.trim().is_empty() {
            cookies.push(LoginCookie {
                name: "star".to_string(),
                value: auth.star.trim().to_string(),
                domain: domain.to_string(),
                path: "/".to_string(),
            });
        }
        if !auth.igneous.trim().is_empty() {
            cookies.push(LoginCookie {
                name: "igneous".to_string(),
                value: auth.igneous.trim().to_string(),
                domain: domain.to_string(),
                path: "/".to_string(),
            });
        }
    }
    cookies
}

fn process_archive(
    input: &PluginInput,
    target_id: &str,
    settings: &Settings,
    login_cookies: &[LoginCookie],
) -> Result<Value, String> {
    HostBridge::progress(10, "准备搜索参数...");
    let lookup = LookupContext {
        archive_id: target_id.trim().to_string(),
        archive_title: metadata_title(&input.metadata),
        existing_tags: metadata_tags_csv(&input.metadata),
        thumbnail_hash: metadata_thumbnail_hash(&input.metadata),
        login_cookies: login_cookies.to_vec(),
        oneshot_param: input.oneshot_param.trim().to_string(),
        debug: settings.debug,
    };

    HostBridge::progress(20, "开始搜索 E-Hentai...");
    let payload = get_tags(&lookup, settings)?;

    let mut next = metadata_object_clone(&input.metadata);
    if !payload.title.trim().is_empty() {
        next.insert("title".to_string(), Value::String(payload.title));
    }
    next.insert("tags".to_string(), tags_array_from_csv(&payload.tags_csv));
    if !payload.updated_at.trim().is_empty() {
        next.insert(
            "updated_at".to_string(),
            Value::String(payload.updated_at.trim().to_string()),
        );
    }
    next.insert("children".to_string(), Value::Array(Vec::new()));
    next.remove("archive");
    next.remove("archive_id");
    Ok(Value::Object(next))
}

fn process_collection(
    root_metadata: &Value,
    tankoubon_id: &str,
    settings: &Settings,
    login_cookies: &[LoginCookie],
) -> Result<Value, String> {
    if tankoubon_id.trim().is_empty() {
        return Err("Missing tankoubon target id".to_string());
    }

    let archive_ids = HostBridge::list_tankoubon_archives(tankoubon_id)?
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    if archive_ids.is_empty() {
        return Err(format!(
            "No member archives found in collection {}",
            tankoubon_id
        ));
    }

    let mut patches = Vec::<Value>::with_capacity(archive_ids.len());

    for (index, archive_id) in archive_ids.iter().enumerate() {
        let percent = (10 + (((index + 1) * 80) / archive_ids.len())) as i32;
        HostBridge::progress(
            percent.clamp(10, 95),
            &format!("处理合集成员 {}/{}", index + 1, archive_ids.len()),
        );

        let archive_metadata = HostBridge::get_archive_metadata(archive_id)?;
        let lookup = LookupContext {
            archive_id: archive_id.clone(),
            archive_title: metadata_title(&archive_metadata),
            existing_tags: metadata_tags_csv(&archive_metadata),
            thumbnail_hash: metadata_thumbnail_hash(&archive_metadata),
            login_cookies: login_cookies.to_vec(),
            oneshot_param: String::new(),
            debug: settings.debug,
        };

        let payload = get_tags(&lookup, settings)?;
        patches.push(json!({
            "title": if payload.title.trim().is_empty() { metadata_title(&archive_metadata) } else { payload.title.clone() },
            "type": 0,
            "description": metadata_description(&archive_metadata),
            "tags": tags_array_from_csv(&payload.tags_csv),
            "updated_at": if payload.updated_at.trim().is_empty() { Value::Null } else { Value::String(payload.updated_at.clone()) },
            "assets": metadata_assets_array(&archive_metadata),
            "volume_no": (index + 1) as i64,
            "entity_id": archive_id,
            "locator": {
                "entity_type": "archive",
                "entity_id": archive_id,
                "volume_no": (index + 1) as i64,
            }
        }));
    }

    let mut next = metadata_object_clone(root_metadata);
    next.insert("children".to_string(), Value::Array(patches));
    next.remove("archive");
    next.remove("archive_id");
    Ok(Value::Object(next))
}

fn get_tags(lookup: &LookupContext, settings: &Settings) -> Result<SearchPayload, String> {
    let domain = if settings.enablepanda {
        "https://exhentai.org"
    } else {
        "https://e-hentai.org"
    };

    debug_log(
        lookup.debug,
        "getTags:context",
        json!({
            "archiveId": lookup.archive_id,
            "domain": domain,
            "title": truncate_for_log(&lookup.archive_title, 200),
            "thumbhash": abbreviate_value(&lookup.thumbnail_hash, 8),
            "cookie_count": lookup.login_cookies.len(),
        }),
    );

    let mut gallery = parse_oneshot_gallery(&lookup.oneshot_param)
        .inspect(|gallery| {
            debug_log(
                lookup.debug,
                "getTags:use_oneshot",
                json!({
                    "gID": gallery.gid,
                    "gToken": abbreviate_value(&gallery.token, 6),
                }),
            );
        })
        .or_else(|| {
            parse_source_gallery(&lookup.existing_tags).inspect(|gallery| {
                debug_log(
                    lookup.debug,
                    "getTags:use_source_tag",
                    json!({
                        "gID": gallery.gid,
                        "gToken": abbreviate_value(&gallery.token, 6),
                    }),
                );
            })
        });

    if gallery.is_none() {
        gallery = Some(lookup_gallery(lookup, settings, domain)?);
    }

    let gallery = gallery.ok_or_else(|| "No matching EH Gallery Found!".to_string())?;
    debug_log(
        lookup.debug,
        "getTags:lookup_success",
        json!({
            "gID": gallery.gid,
            "gToken": abbreviate_value(&gallery.token, 6),
        }),
    );
    let mut payload = get_tags_from_eh(&gallery.gid, &gallery.token, settings)?;
    if !payload.tags_csv.trim().is_empty() {
        payload.tags_csv.push_str(&format!(
            ", source:https://exhentai.org/g/{}/{}, source:https://e-hentai.org/g/{}/{}",
            gallery.gid, gallery.token, gallery.gid, gallery.token
        ));
    }
    Ok(payload)
}

fn lookup_gallery(
    lookup: &LookupContext,
    settings: &Settings,
    domain: &str,
) -> Result<GalleryMatch, String> {
    if settings.usethumbs && !lookup.archive_id.trim().is_empty() {
        if let Ok(cover) = HostBridge::export_cover_for_search(&lookup.archive_id) {
            let _ = (&cover.archive_id, &cover.entry_name, &cover.original_path, &cover.upload_sha1);
            debug_log(
                lookup.debug,
                "lookup:cover_exported",
                json!({
                    "archiveId": lookup.archive_id,
                    "entryName": cover.entry_name,
                    "originalSha1": abbreviate_value(&cover.original_sha1, 8),
                    "uploadPath": cover.upload_path,
                }),
            );
            if !cover.original_sha1.trim().is_empty() {
                let url = format!(
                    "{}?f_shash={}&fs_similar=on&fs_covers=on",
                    domain, cover.original_sha1
                );
                debug_log(
                    lookup.debug,
                    "lookup:shash_search:start",
                    json!({ "sha1": abbreviate_value(&cover.original_sha1, 8) }),
                );
                if let Ok(found) = ehentai_parse(&url, &lookup.login_cookies) {
                    return Ok(found);
                }
                debug_log(
                    lookup.debug,
                    "lookup:shash_search:miss",
                    json!({ "error": "unknown" }),
                );
            }
        } else {
            warn_log(
                "lookup:cover_export_failed",
                json!({ "archiveId": lookup.archive_id, "error": "cover export failed" }),
            );
        }
    }

    if settings.search_gid {
        if let Some(captures) = regex(r"\[(\d+)\]").captures(&lookup.archive_title) {
            let gid = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let url = format!("{}?f_search=gid:{}", domain, gid);
            debug_log(lookup.debug, "lookup:gid_search:start", json!({ "gid": gid }));
            if let Ok(found) = ehentai_parse(&url, &lookup.login_cookies) {
                return Ok(found);
            }
            debug_log(
                lookup.debug,
                "lookup:gid_search:miss",
                json!({ "error": "unknown" }),
            );
        }
    }

    let mut url = format!(
        "{}?advsearch=1&f_sfu=on&f_sft=on&f_sfl=on&f_search={}",
        domain,
        urlencoding::encode(&format!("\"{}\"", lookup.archive_title))
    );
    debug_log(
        lookup.debug,
        "lookup:title_search:base",
        json!({ "title": truncate_for_log(&lookup.archive_title, 200) }),
    );

    if let Some(artist) = extract_ascii_artist(&lookup.existing_tags) {
        url.push('+');
        url.push_str(&urlencoding::encode(&format!("artist:{artist}")));
        debug_log(
            lookup.debug,
            "lookup:title_search:add_artist",
            json!({ "artist": artist }),
        );
    }

    if !settings.lang.trim().is_empty() {
        url.push('+');
        url.push_str(&urlencoding::encode(&format!("language:{}", settings.lang.trim())));
        debug_log(
            lookup.debug,
            "lookup:title_search:add_language",
            json!({ "language": settings.lang.trim() }),
        );
    }

    if settings.expunged {
        url.push_str("&f_sh=on");
        debug_log(lookup.debug, "lookup:title_search:expunged", json!({}));
    }

    ehentai_parse(&url, &lookup.login_cookies)
}

fn ehentai_parse(url: &str, cookies: &[LoginCookie]) -> Result<GalleryMatch, String> {
    let response = HostBridge::http_fetch("GET", url, None, cookies, &[])?;
    if !is_http_success(&response) {
        return Err(format!("HTTP {}: search failed", response.status));
    }
    parse_gallery_from_html(&response.text)
}

fn parse_gallery_from_html(html: &str) -> Result<GalleryMatch, String> {
    if html.contains("Your IP address has been") {
        return Err("Temporarily banned from EH for excessive pageloads.".to_string());
    }

    let candidates = extract_gallery_candidates(html);
    if !candidates.is_empty() {
        if candidates.len() == 1 {
            let only = &candidates[0];
            return Ok(GalleryMatch {
                gid: only.gid.clone(),
                token: only.token.clone(),
            });
        }

        let resolved = enrich_candidates_with_api_covers(&candidates).unwrap_or(candidates);
        let options = resolved
            .iter()
            .enumerate()
            .map(|(index, item)| {
                json!({
                    "label": if item.title.trim().is_empty() { format!("候选 {}", index + 1) } else { item.title.clone() },
                    "description": format!("gid:{} | {}", item.gid, item.url),
                    "cover": item.cover,
                })
            })
            .collect::<Vec<_>>();
        let picked = HostBridge::select_index(
            "E-Hentai 候选匹配",
            options,
            "检测到多个匹配画廊，请选择最合适的一项",
            0,
            120,
        )?;
        let chosen = resolved.get(picked).unwrap_or(&resolved[0]);
        return Ok(GalleryMatch {
            gid: chosen.gid.clone(),
            token: chosen.token.clone(),
        });
    }

    if let Some(direct) = extract_direct_gallery(html) {
        return Ok(direct);
    }

    if html.contains("No hits found") {
        return Err("No gallery found in search results".to_string());
    }
    Err("No gallery found in search results".to_string())
}

fn extract_gallery_candidates(html: &str) -> Vec<EhGalleryCandidate> {
    let pattern = regex(
        r#"<a[^>]*href="([^"]*\/g\/(\d+)\/([^"\/?#]+)\/?[^"]*)"[^>]*>\s*<div[^>]*class="glink"[^>]*>([\s\S]*?)</div>"#,
    );
    let tag_re = regex(r"<[^>]+>");
    let ws_re = regex(r"\s+");

    let mut out = Vec::<EhGalleryCandidate>::new();
    for captures in pattern.captures_iter(html) {
        let gid = captures.get(2).map(|m| m.as_str().trim()).unwrap_or_default();
        let token = captures.get(3).map(|m| m.as_str().trim()).unwrap_or_default();
        if gid.is_empty() || token.is_empty() {
            continue;
        }
        if out.iter().any(|item| item.gid == gid && item.token == token) {
            continue;
        }
        let href = captures.get(1).map(|m| m.as_str().trim()).unwrap_or_default();
        let url = if href.starts_with("http://") || href.starts_with("https://") {
            href.to_string()
        } else {
            format!(
                "https://e-hentai.org{}{}",
                if href.starts_with('/') { "" } else { "/" },
                href
            )
        };
        let raw_title = captures.get(4).map(|m| m.as_str()).unwrap_or_default();
        let without_tags = tag_re.replace_all(raw_title, " ");
        let collapsed = ws_re.replace_all(without_tags.trim(), " ");
        let title = html_unescape(collapsed.as_ref()).trim().to_string();

        let match_range = captures.get(0).map(|m| (m.start(), m.end())).unwrap_or((0, 0));
        let start = match_range.0.saturating_sub(350);
        let end = (match_range.1 + 600).min(html.len());
        let context = &html[start..end];
        let cover = extract_cover_from_context(context, &url);

        out.push(EhGalleryCandidate {
            gid: gid.to_string(),
            token: token.to_string(),
            title,
            url,
            cover,
        });
    }
    out
}

fn extract_cover_from_context(context: &str, base_url: &str) -> String {
    if let Some(captures) = regex(r#"<(?:img|source)[^>]+(?:data-src|data-lazy-src|src)="([^"]+)""#)
        .captures(context)
    {
        if let Some(raw) = captures.get(1) {
            return normalize_cover_url(raw.as_str(), base_url);
        }
    }

    if let Some(captures) = regex(r#"url\(\s*['"]?([^'"\)]+)['"]?\s*\)"#).captures(context) {
        if let Some(raw) = captures.get(1) {
            return normalize_cover_url(raw.as_str(), base_url);
        }
    }
    String::new()
}

fn normalize_cover_url(raw: &str, base_url: &str) -> String {
    let value = html_unescape(raw.trim());
    if value.is_empty() {
        return String::new();
    }
    if value.starts_with("data:image/") {
        return value;
    }
    if value.starts_with("//") {
        return format!("https:{}", value);
    }
    if let Ok(parsed) = Url::parse(&value) {
        return parsed.to_string();
    }
    if let Ok(base) = Url::parse(base_url) {
        if let Ok(joined) = base.join(&value) {
            return joined.to_string();
        }
    }
    String::new()
}

fn enrich_candidates_with_api_covers(
    candidates: &[EhGalleryCandidate],
) -> Result<Vec<EhGalleryCandidate>, String> {
    let thumb_map = fetch_thumb_map_from_api(candidates)?;
    if thumb_map.is_empty() {
        return Ok(candidates.to_vec());
    }

    Ok(candidates
        .iter()
        .map(|item| {
            let mut next = item.clone();
            if let Some(cover) = thumb_map.get(&format!("{}:{}", item.gid, item.token)) {
                if !cover.trim().is_empty() {
                    next.cover = cover.clone();
                }
            }
            next
        })
        .collect())
}

fn fetch_thumb_map_from_api(
    candidates: &[EhGalleryCandidate],
) -> Result<std::collections::HashMap<String, String>, String> {
    let gidlist = candidates
        .iter()
        .filter_map(|item| item.gid.parse::<i64>().ok().map(|gid| json!([gid, item.token])))
        .collect::<Vec<_>>();
    if gidlist.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let body = json!({
        "method": "gdata",
        "gidlist": gidlist,
        "namespace": 1,
    })
    .to_string();
    let response = HostBridge::http_fetch(
        "POST",
        EH_API_URL,
        Some(body),
        &[],
        &[("Content-Type", "application/json".to_string())],
    )?;
    if !is_http_success(&response) {
        return Ok(std::collections::HashMap::new());
    }

    let json: Value = serde_json::from_str(&response.text).map_err(|e| e.to_string())?;
    let mut out = std::collections::HashMap::<String, String>::new();
    if let Some(list) = json.get("gmetadata").and_then(Value::as_array) {
        for item in list {
            let gid = item
                .get("gid")
                .and_then(value_to_string)
                .unwrap_or_default();
            let token = item
                .get("token")
                .and_then(value_to_string)
                .unwrap_or_default();
            let thumb = item
                .get("thumb")
                .and_then(value_to_string)
                .unwrap_or_default();
            if gid.is_empty() || token.is_empty() {
                continue;
            }
            let cover = normalize_cover_url(&thumb, "https://e-hentai.org/");
            if !cover.is_empty() {
                out.insert(format!("{}:{}", gid, token), cover);
            }
        }
    }
    Ok(out)
}

fn extract_direct_gallery(html: &str) -> Option<GalleryMatch> {
    let patterns = [
        r#"<meta[^>]+property="og:url"[^>]+content="[^"]*/g/(\d+)/([^"/?#]+)/?"#,
        r#"<link[^>]+rel="canonical"[^>]+href="[^"]*/g/(\d+)/([^"/?#]+)/?"#,
    ];
    for pattern in patterns {
        if let Some(captures) = regex(pattern).captures(html) {
            let gid = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let token = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
            if !gid.is_empty() && !token.is_empty() {
                return Some(GalleryMatch {
                    gid: gid.to_string(),
                    token: token.to_string(),
                });
            }
        }
    }
    None
}

fn get_tags_from_eh(
    gid: &str,
    token: &str,
    settings: &Settings,
) -> Result<SearchPayload, String> {
    let gid_value = gid.parse::<i64>().map_err(|_| "invalid gid".to_string())?;
    let body = json!({
        "method": "gdata",
        "gidlist": [[gid_value, token]],
        "namespace": 1,
    })
    .to_string();
    let response = HostBridge::http_fetch(
        "POST",
        EH_API_URL,
        Some(body),
        &[],
        &[("Content-Type", "application/json".to_string())],
    )?;
    if !is_http_success(&response) {
        return Err(format!("API request failed: HTTP {}", response.status));
    }

    let json: Value = serde_json::from_str(&response.text).map_err(|e| e.to_string())?;
    if let Some(error) = json.get("error").and_then(value_to_string) {
        if !error.trim().is_empty() {
            return Err(error);
        }
    }

    let data = json
        .get("gmetadata")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| "No metadata returned from API".to_string())?;

    let mut tags = data
        .get("tags")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(value_to_string)
                .filter(|value| !value.trim().is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if let Some(category) = data.get("category").and_then(value_to_string) {
        if !category.trim().is_empty() {
            tags.push(format!("category:{}", category.to_ascii_lowercase()));
        }
    }

    let mut updated_at = String::new();
    if settings.additionaltags {
        if let Some(uploader) = data.get("uploader").and_then(value_to_string) {
            if !uploader.trim().is_empty() {
                tags.push(format!("uploader:{}", uploader));
            }
        }
        if let Some(posted) = data.get("posted").and_then(value_to_string) {
            if let Some(formatted) = epoch_seconds_to_utc_timestamp(posted.trim()) {
                updated_at = formatted;
            }
        }
    }

    let title = if settings.jpntitle {
        data.get("title_jpn")
            .and_then(value_to_string)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| data.get("title").and_then(value_to_string))
            .unwrap_or_default()
    } else {
        data.get("title")
            .and_then(value_to_string)
            .unwrap_or_default()
    };

    Ok(SearchPayload {
        tags_csv: tags.join(", "),
        title: html_unescape(title.trim()),
        updated_at,
    })
}

fn epoch_seconds_to_utc_timestamp(raw: &str) -> Option<String> {
    let secs = raw.parse::<i64>().ok()?;
    let dt = OffsetDateTime::from_unix_timestamp(secs).ok()?;
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    dt.format(fmt).ok()
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
#[derive(Debug)]
struct HostTcpStream {
    stream: WasiTcpStream,
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let mut stream = WasiTcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
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
        Ok(())
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
        let _ = stream.set_nodelay(true);
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
    Plain(HostTcpStream),
    Tls(Box<StreamOwned<ClientConnection, HostTcpStream>>),
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            HttpStream::Plain(s) => s.read(buf),
            HttpStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            HttpStream::Plain(s) => s.write(buf),
            HttpStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            HttpStream::Plain(s) => s.flush(),
            HttpStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Debug)]
struct RawHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpTextResponse {
    status: u16,
    text: String,
}

fn http_request_text_follow_redirects(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<HttpTextResponse, String> {
    let response =
        http_request_bytes_follow_redirects(method, url, body, referer, cookies, extra_headers)?;
    Ok(HttpTextResponse {
        status: response.status,
        text: String::from_utf8_lossy(&response.body).to_string(),
    })
}

fn http_request_bytes_follow_redirects(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<RawHttpResponse, String> {
    let mut current_method = method.to_ascii_uppercase();
    let mut current_url = url.to_string();
    let mut current_body = body.map(|v| v.to_vec());

    for _ in 0..=MAX_REDIRECTS {
        let resp = http_request_once(
            &current_method,
            &current_url,
            current_body.as_deref(),
            referer,
            cookies,
            extra_headers,
        )?;
        if !is_redirect_status(resp.status) {
            return Ok(resp);
        }
        let Some(location) = header_value(&resp.headers, "Location") else {
            return Ok(resp);
        };
        let base = Url::parse(&current_url).map_err(|e| e.to_string())?;
        let resolved = base.join(location).map_err(|e| e.to_string())?;
        if resp.status == 303 || ((resp.status == 301 || resp.status == 302) && current_method == "POST")
        {
            current_method = "GET".to_string();
            current_body = None;
        }
        current_url = resolved.to_string();
    }
    Err(format!("too many redirects while requesting {url}"))
}

fn http_request_once(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    referer: Option<&str>,
    cookies: &[LoginCookie],
    extra_headers: &[(String, String)],
) -> Result<RawHttpResponse, String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("missing host in URL: {url}"))?
        .to_string();
    let scheme = parsed.scheme().to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("missing port for URL: {url}"))?;
    let mut stream = connect_http_stream(&scheme, &host, port)?;
    let mut req = Vec::with_capacity(1024 + body.map(|v| v.len()).unwrap_or(0));
    let path = request_path(&parsed);

    req.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        req.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    } else {
        req.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
    }
    req.extend_from_slice(format!("User-Agent: {USER_AGENT}\r\n").as_bytes());
    req.extend_from_slice(b"Accept: */*\r\n");
    req.extend_from_slice(b"Accept-Encoding: identity\r\n");
    req.extend_from_slice(b"Connection: close\r\n");
    if let Some(v) = referer {
        req.extend_from_slice(format!("Referer: {v}\r\n").as_bytes());
    }

    let has_content_type = extra_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Content-Type"));
    for (k, v) in extra_headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    let cookie_header = build_cookie_header(url, cookies);
    if !cookie_header.is_empty() {
        req.extend_from_slice(format!("Cookie: {cookie_header}\r\n").as_bytes());
    }
    if method.eq_ignore_ascii_case("POST") && !has_content_type {
        req.extend_from_slice(b"Content-Type: application/x-www-form-urlencoded\r\n");
    }
    if let Some(v) = body {
        req.extend_from_slice(format!("Content-Length: {}\r\n", v.len()).as_bytes());
    } else if method.eq_ignore_ascii_case("POST") {
        req.extend_from_slice(b"Content-Length: 0\r\n");
    }
    req.extend_from_slice(b"\r\n");

    stream.write_all(&req).map_err(|e| e.to_string())?;
    if let Some(v) = body {
        if !v.is_empty() {
            stream.write_all(v).map_err(|e| e.to_string())?;
        }
    }
    stream.flush().map_err(|e| e.to_string())?;
    read_http_response(&mut stream)
}

fn connect_http_stream(scheme: &str, host: &str, port: u16) -> Result<HttpStream, String> {
    let tcp = if scheme.eq_ignore_ascii_case("https") {
        if let Some((proxy_host, proxy_port)) = resolve_proxy_for_scheme(scheme) {
            let mut proxy_stream = HostTcpStream::connect(&proxy_host, proxy_port, DEFAULT_TIMEOUT_MS)?;
            establish_proxy_connect_tunnel(&mut proxy_stream, host, port)?;
            proxy_stream
        } else {
            HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
        }
    } else {
        HostTcpStream::connect(host, port, DEFAULT_TIMEOUT_MS)?
    };
    if scheme.eq_ignore_ascii_case("https") {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| format!("invalid dns name: {host}"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
        Ok(HttpStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
    } else if scheme.eq_ignore_ascii_case("http") {
        Ok(HttpStream::Plain(tcp))
    } else {
        Err(format!("unsupported URL scheme: {scheme}"))
    }
}

fn resolve_proxy_for_scheme(scheme: &str) -> Option<(String, u16)> {
    let keys: &[&str] = if scheme.eq_ignore_ascii_case("https") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            if let Some(parsed) = parse_proxy_endpoint(&raw) {
                return Some(parsed);
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
    let normalized = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(8080);
    Some((host, port))
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

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    path
}

fn read_http_response(stream: &mut HttpStream) -> Result<RawHttpResponse, String> {
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

    let header_bytes = &buf[..header_end];
    let pending = buf[header_end + 4..].to_vec();
    let (status, headers) = parse_response_headers(header_bytes)?;
    let body = read_response_body(stream, &headers, pending)?;
    Ok(RawHttpResponse { status, headers, body })
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
    let _http_ver = parts
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
    if is_chunked(headers) {
        let mut raw = Vec::new();
        if !pending.is_empty() {
            raw.extend_from_slice(&pending);
        }
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = read_stream_chunk(stream, &mut buf, true)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        return decode_chunked_lenient(&raw);
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

    let mut out = Vec::new();
    if !pending.is_empty() {
        out.extend_from_slice(&pending);
    }
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

fn read_stream_chunk(stream: &mut HttpStream, buf: &mut [u8], allow_tls_eof: bool) -> Result<usize, String> {
    match stream.read(buf) {
        Ok(n) => Ok(n),
        Err(e) => {
            if allow_tls_eof && is_tls_close_notify_eof(&e) {
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

fn decode_chunked_lenient(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut pending = raw.to_vec();
    let mut out = Vec::new();
    loop {
        let line = match extract_line_crlf(&mut pending) {
            Some(v) => v,
            None => {
                if pending.is_empty() {
                    return Ok(out);
                }
                let v = String::from_utf8_lossy(&pending).to_string();
                pending.clear();
                v
            }
        };
        let size_hex = line.split(';').next().unwrap_or("").trim();
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
    if let Some(pos) = pending.windows(2).position(|v| v == b"\r\n") {
        let line = String::from_utf8_lossy(&pending[..pos]).to_string();
        pending.drain(..pos + 2);
        Some(line)
    } else {
        None
    }
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header_value(headers, "Transfer-Encoding")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn build_cookie_header(url: &str, cookies: &[LoginCookie]) -> String {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|v| v.to_ascii_lowercase()))
        .unwrap_or_default();
    let mut pairs = Vec::new();
    for c in cookies {
        let name = c.name.trim();
        let value = c.value.trim();
        if name.is_empty() {
            continue;
        }
        let domain = c.domain.trim().trim_start_matches('.').to_ascii_lowercase();
        if !domain.is_empty() && !host.is_empty() && host != domain && !host.ends_with(&format!(".{domain}")) {
            continue;
        }
        pairs.push(format!("{name}={value}"));
    }
    pairs.join("; ")
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = format!("{host}:{port}").to_socket_addrs().map_err(|e| e.to_string())?;
    addrs
        .next()
        .ok_or_else(|| format!("failed to resolve host: {host}:{port}"))
}

fn normalize_target_type(raw: &str, params: &Value) -> String {
    let from_input = raw.trim().to_ascii_lowercase();
    if !from_input.is_empty() {
        return from_input;
    }
    param_string(params, "__target_type").to_ascii_lowercase()
}

fn is_collection_target_type(target_type: &str) -> bool {
    matches!(target_type, "tankoubon" | "tank")
}

fn settings_from_params(params: &Value) -> Settings {
    Settings {
        lang: param_string(params, "lang"),
        usethumbs: param_bool(params, "usethumbs"),
        search_gid: param_bool(params, "search_gid"),
        enablepanda: param_bool(params, "enablepanda"),
        jpntitle: param_bool(params, "jpntitle"),
        additionaltags: param_bool(params, "additionaltags"),
        expunged: param_bool(params, "expunged"),
        debug: param_bool(params, "debug"),
    }
}

fn param_bool(params: &Value, key: &str) -> bool {
    match params.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_i64().unwrap_or_default() != 0,
        Some(Value::String(value)) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        ),
        _ => false,
    }
}

fn param_string(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(value_to_string)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn metadata_object_clone(value: &Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    }
}

fn metadata_title(value: &Value) -> String {
    value.get("title")
        .and_then(value_to_string)
        .unwrap_or_default()
}

fn metadata_description(value: &Value) -> String {
    value.get("description")
        .and_then(value_to_string)
        .unwrap_or_default()
}

fn metadata_thumbnail_hash(value: &Value) -> String {
    value.get("thumbnail_hash")
        .and_then(value_to_string)
        .unwrap_or_default()
}

fn metadata_tags_csv(value: &Value) -> String {
    value.get("tags")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(value_to_string)
                .filter(|value| !value.trim().is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn metadata_assets_array(value: &Value) -> Value {
    value.get("assets").cloned().unwrap_or_else(|| Value::Array(Vec::new()))
}

fn tags_array_from_csv(csv: &str) -> Value {
    Value::Array(
        csv.split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| Value::String(part.to_string()))
            .collect(),
    )
}

fn parse_oneshot_gallery(raw: &str) -> Option<GalleryMatch> {
    let captures = regex(r"/g/(\d+)/([0-9A-Za-z]+)/?")
        .captures(raw)
        .or_else(|| regex(r"/g/(\d+)/([0-9A-Za-z]+)/?").captures(raw.trim()))?;
    let gid = captures.get(1)?.as_str();
    let token = captures.get(2)?.as_str();
    Some(GalleryMatch {
        gid: gid.to_string(),
        token: token.to_string(),
    })
}

fn parse_source_gallery(existing_tags: &str) -> Option<GalleryMatch> {
    let captures =
        regex(r"source:\s*(?:https?://)?e(?:x|-)?hentai\.org/g/(\d+)/([0-9A-Za-z]+)/?")
            .captures(existing_tags)?;
    let gid = captures.get(1)?.as_str();
    let token = captures.get(2)?.as_str();
    Some(GalleryMatch {
        gid: gid.to_string(),
        token: token.to_string(),
    })
}

fn extract_ascii_artist(existing_tags: &str) -> Option<String> {
    for part in existing_tags.split(',') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix("artist:") {
            let artist = value.trim();
            if !artist.is_empty() && artist.is_ascii() {
                return Some(artist.to_string());
            }
        }
    }
    None
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(if *flag { "true" } else { "false" }.to_string()),
        _ => None,
    }
}

fn is_http_success(response: &HttpResponseData) -> bool {
    response.ok || (200..300).contains(&response.status)
}

fn warn_log(message: &str, meta: Value) {
    log_with_level(2, message, meta);
}

fn debug_log(enabled: bool, message: &str, meta: Value) {
    if enabled {
        log_with_level(0, message, meta);
    }
}

fn log_with_level(level: i32, message: &str, meta: Value) {
    let rendered = serde_json::to_string(&meta).unwrap_or_else(|_| "{}".to_string());
    let final_message = if rendered == "{}" {
        message.to_string()
    } else {
        format!("{message} {rendered}")
    };
    HostBridge::log(level, &final_message);
}

fn abbreviate_value(value: &str, prefix_len: usize) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let abbreviated = trimmed.chars().take(prefix_len).collect::<String>();
    if trimmed.chars().count() > prefix_len {
        format!("{abbreviated}…")
    } else {
        abbreviated
    }
}

fn truncate_for_log(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect::<String>()
}

fn html_unescape(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
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
    HostBridge::log(0, &message);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error = message.into_bytes();
    });
    0
}

unsafe fn read_guest_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) }
}
