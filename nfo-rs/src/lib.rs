use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::slice;

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
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
struct AdjacentFilesResponse {
    #[serde(default)]
    base_dir: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AdjacentTextResponse {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Deserialize)]
struct AdjacentTextsResponse {
    #[serde(default)]
    texts: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TankoubonArchivesResponse {
    #[serde(default)]
    archive_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EpisodeMeta {
    title: String,
    summary: String,
    season: i64,
    episode: i64,
    aired: String,
}

#[derive(Debug, Clone, Default)]
struct SourceTagCandidate {
    tag: String,
    score: i64,
}

#[derive(Debug, Clone, Default)]
struct TvshowMeta {
    title: String,
    summary: String,
    source_tag: String,
    tags: Vec<String>,
    cover: String,
    backdrop: String,
    clearlogo: String,
}

#[derive(Debug, Clone, Default)]
struct SeasonMeta {
    title: String,
    summary: String,
    source_tag: String,
    tags: Vec<String>,
    cover: String,
    backdrop: String,
    clearlogo: String,
    pages: Vec<Value>,
}

#[derive(Debug, Clone, Default)]
struct ParsedNfo {
    root_name: String,
    tags: HashMap<String, Vec<String>>,
    unique_ids: Vec<ParsedUniqueId>,
}

#[derive(Debug, Clone, Default)]
struct ParsedUniqueId {
    value: String,
    source_type: String,
    default_attr: String,
}

#[derive(Debug, Clone, Default)]
struct XmlElementContext {
    name: String,
    text: String,
    attrs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
enum ArtworkKey {
    Backdrop,
    Clearlogo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Nfo,
    Video,
    Image,
    Other,
}

#[derive(Debug, Clone)]
struct IndexedFile {
    name: String,
    lower: String,
    stem_lower: String,
    kind: FileKind,
    episode_stem: bool,
}

#[derive(Debug, Clone)]
struct PageAttachmentCandidate {
    path: String,
    slot: String,
    name: String,
    mime_type: String,
    kind: String,
    language: String,
}

#[derive(Debug, Clone, Default)]
struct ListingIndex {
    entries: Vec<IndexedFile>,
    by_stem: HashMap<String, Vec<usize>>,
    sidecar_images_by_base: HashMap<String, Vec<usize>>,
    non_page_image_indices: Vec<usize>,
}

impl ListingIndex {
    fn new(files: Vec<String>) -> Self {
        let mut entries = Vec::with_capacity(files.len());
        let mut by_stem = HashMap::<String, Vec<usize>>::new();

        for name in files {
            let lower = name.to_ascii_lowercase();
            let stem_lower = strip_extension(&name).to_ascii_lowercase();
            let kind = classify_file_kind(&lower);
            let episode_stem = looks_like_episode_stem(&stem_lower);
            let index = entries.len();
            entries.push(IndexedFile {
                name,
                lower,
                stem_lower: stem_lower.clone(),
                kind,
                episode_stem,
            });
            by_stem.entry(stem_lower).or_default().push(index);
        }

        let mut sidecar_images_by_base = HashMap::<String, Vec<usize>>::new();
        let mut non_page_image_indices = Vec::new();

        for index in 0..entries.len() {
            let entry = &entries[index];
            if entry.kind != FileKind::Image {
                continue;
            }
            let base = strip_sidecar_cover_suffix(&entry.stem_lower);
            let is_page_sidecar = !base.is_empty()
                && base != entry.stem_lower
                && by_stem.get(&base).is_some_and(|indices| {
                    indices.iter().any(|other| {
                        *other != index && entries[*other].kind != FileKind::Other
                    })
                });
            if is_page_sidecar {
                sidecar_images_by_base.entry(base).or_default().push(index);
            } else if !entry.episode_stem {
                non_page_image_indices.push(index);
            }
        }

        Self {
            entries,
            by_stem,
            sidecar_images_by_base,
            non_page_image_indices,
        }
    }

    fn find_file_ignore_ascii_case(&self, file_name: &str) -> Option<String> {
        let lower = file_name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|entry| entry.lower == lower)
            .map(|entry| entry.name.clone())
    }

    fn nfo_files_sorted(&self) -> Vec<String> {
        let mut files = self
            .entries
            .iter()
            .filter(|entry| entry.kind == FileKind::Nfo)
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        files.sort_by_key(|file| file.to_ascii_lowercase());
        files
    }

    fn best_media_file(&self, base_name: &str) -> String {
        let base_lower = base_name.to_ascii_lowercase();
        let Some(indices) = self.by_stem.get(&base_lower) else {
            return String::new();
        };
        indices
            .iter()
            .map(|index| &self.entries[*index])
            .find(|entry| entry.kind == FileKind::Video)
            .or_else(|| {
                indices
                    .iter()
                    .map(|index| &self.entries[*index])
                    .find(|entry| entry.kind == FileKind::Image)
            })
            .map(|entry| entry.name.clone())
            .unwrap_or_default()
    }

    fn cover_candidates(&self, base_name: &str, selected_media: &str) -> Vec<String> {
        let base_lower = base_name.to_ascii_lowercase();
        let selected_lower = selected_media.to_ascii_lowercase();
        let mut seen = HashSet::<String>::new();
        let mut out = Vec::<(String, i64)>::new();

        let mut push_entry = |entry: &IndexedFile| {
            if entry.kind != FileKind::Image || entry.lower == selected_lower {
                return;
            }
            if seen.insert(entry.lower.clone()) {
                out.push((
                    entry.name.clone(),
                    score_cover_candidate(&entry.stem_lower, &base_lower),
                ));
            }
        };

        if let Some(indices) = self.by_stem.get(&base_lower) {
            for index in indices {
                push_entry(&self.entries[*index]);
            }
        }
        if let Some(indices) = self.sidecar_images_by_base.get(&base_lower) {
            for index in indices {
                push_entry(&self.entries[*index]);
            }
        }

        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.into_iter().map(|item| item.0).collect()
    }

    fn page_attachment_candidates(&self, base_name: &str) -> Vec<PageAttachmentCandidate> {
        let mut out = Vec::<PageAttachmentCandidate>::new();
        let mut seen = HashSet::<String>::new();

        for entry in &self.entries {
            let Some((language, kind)) = match_page_attachment_to_base(&entry.name, base_name) else {
                continue;
            };
            if !seen.insert(entry.lower.clone()) {
                continue;
            }
            out.push(PageAttachmentCandidate {
                path: entry.name.clone(),
                slot: "subtitle".to_string(),
                name: entry.name.clone(),
                mime_type: attachment_mime_type(&kind).to_string(),
                kind,
                language,
            });
        }

        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn general_cover_candidates(&self) -> Vec<String> {
        self.rank_paths(&self.non_page_image_indices, |entry| {
            score_general_cover_candidate(&entry.stem_lower)
        })
    }

    fn artwork_candidates(&self, season_number: i64, asset_key: ArtworkKey) -> Vec<String> {
        let season_tokens = build_season_tokens(season_number);
        self.rank_paths(&self.non_page_image_indices, |entry| {
            let mut score = score_general_artwork_candidate(&entry.stem_lower, asset_key);
            for token in &season_tokens {
                score = score.max(score_season_artwork_candidate(
                    &entry.stem_lower,
                    token,
                    asset_key,
                ));
            }
            score
        })
    }

    fn season_specific_cover_candidates(&self, season_number: i64) -> Vec<String> {
        let season_tokens = build_season_tokens(season_number);
        if season_tokens.is_empty() {
            return vec![];
        }
        self.rank_paths(&self.non_page_image_indices, |entry| {
            season_tokens
                .iter()
                .map(|token| score_season_specific_cover_candidate(&entry.stem_lower, token))
                .max()
                .unwrap_or(0)
        })
    }

    fn season_cover_candidates(&self, season_number: i64) -> Vec<String> {
        let season_tokens = build_season_tokens(season_number);
        self.rank_paths(&self.non_page_image_indices, |entry| {
            let stem = &entry.stem_lower;
            let mut score = score_general_cover_candidate(stem);
            for token in &season_tokens {
                if stem == token
                    || stem == &format!("{token}-poster")
                    || stem == &format!("{token}_poster")
                {
                    score = score.max(1300);
                } else if stem.contains(token) && stem.contains("poster") {
                    score = score.max(1200);
                } else if stem.contains(token) && stem.contains("cover") {
                    score = score.max(1100);
                } else if stem.contains(token) && stem.contains("thumb") {
                    score = score.max(1000);
                }
            }
            score
        })
    }

    fn season_specific_artwork_candidates(
        &self,
        season_number: i64,
        asset_key: ArtworkKey,
    ) -> Vec<String> {
        let season_tokens = build_season_tokens(season_number);
        if season_tokens.is_empty() {
            return vec![];
        }
        self.rank_paths(&self.non_page_image_indices, |entry| {
            season_tokens
                .iter()
                .map(|token| {
                    score_season_specific_artwork_candidate(&entry.stem_lower, token, asset_key)
                })
                .max()
                .unwrap_or(0)
        })
    }

    fn archive_cover(&self, parent: &ListingIndex, season_number: i64) -> String {
        self.season_specific_cover_candidates(season_number)
            .first()
            .map(|path| adjacent_ref(path, 0))
            .or_else(|| {
                parent
                    .season_specific_cover_candidates(season_number)
                    .first()
                    .map(|path| adjacent_ref(path, 1))
            })
            .or_else(|| {
                self.season_cover_candidates(season_number)
                    .first()
                    .map(|path| adjacent_ref(path, 0))
            })
            .or_else(|| {
                parent
                    .season_cover_candidates(season_number)
                    .first()
                    .map(|path| adjacent_ref(path, 1))
            })
            .or_else(|| {
                parent
                    .general_cover_candidates()
                    .first()
                    .map(|path| adjacent_ref(path, 1))
            })
            .unwrap_or_default()
    }

    fn archive_artwork(
        &self,
        parent: &ListingIndex,
        season_number: i64,
        asset_key: ArtworkKey,
    ) -> String {
        self.season_specific_artwork_candidates(season_number, asset_key)
            .first()
            .map(|path| adjacent_ref(path, 0))
            .or_else(|| {
                parent
                    .season_specific_artwork_candidates(season_number, asset_key)
                    .first()
                    .map(|path| adjacent_ref(path, 1))
            })
            .or_else(|| {
                self.artwork_candidates(season_number, asset_key)
                    .first()
                    .map(|path| adjacent_ref(path, 0))
            })
            .or_else(|| {
                parent
                    .artwork_candidates(season_number, asset_key)
                    .first()
                    .map(|path| adjacent_ref(path, 1))
            })
            .unwrap_or_default()
    }

    fn rank_paths<F>(&self, indices: &[usize], mut scorer: F) -> Vec<String>
    where
        F: FnMut(&IndexedFile) -> i64,
    {
        let mut out = Vec::<(String, i64)>::new();
        for index in indices {
            let entry = &self.entries[*index];
            let score = scorer(entry);
            if score > 0 {
                out.push((entry.name.clone(), score));
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.into_iter().map(|item| item.0).collect()
    }
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
        serde_json::from_slice::<Value>(&buf[..read as usize]).map_err(|e| e.to_string())
    }

    fn read_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 {
            return "host_call failed".to_string();
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buf.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return "host_call failed".to_string();
        }
        String::from_utf8_lossy(&buf[..read as usize]).to_string()
    }

    fn list_adjacent_files(
        archive_id: &str,
        levels_up: i64,
    ) -> Result<AdjacentFilesResponse, String> {
        let value = Self::call(
            "archive.list_adjacent_files",
            json!({
                "archive_id": archive_id,
                "levels_up": levels_up,
            }),
        )?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    fn read_adjacent_text(
        archive_id: &str,
        file_name: &str,
        levels_up: i64,
    ) -> Result<String, String> {
        let value = Self::call(
            "archive.read_adjacent_text",
            json!({
                "archive_id": archive_id,
                "file_name": file_name,
                "levels_up": levels_up,
            }),
        )?;
        let parsed: AdjacentTextResponse =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        Ok(parsed.text)
    }

    fn read_adjacent_texts(
        archive_id: &str,
        file_names: &[String],
        levels_up: i64,
    ) -> Result<HashMap<String, String>, String> {
        let value = Self::call(
            "archive.read_adjacent_texts",
            json!({
                "archive_id": archive_id,
                "file_names": file_names,
                "levels_up": levels_up,
            }),
        )?;
        let parsed: AdjacentTextsResponse =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        Ok(parsed.texts)
    }

    fn list_tankoubon_archives(tankoubon_id: &str) -> Result<Vec<String>, String> {
        let value = Self::call(
            "tankoubon.list_archives",
            json!({
                "tankoubon_id": tankoubon_id,
            }),
        )?;
        let parsed: TankoubonArchivesResponse =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        Ok(parsed.archive_ids)
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

    let result = match run_plugin(input) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(e),
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
        "name": "NFO Sidecar (Rust/WASM)",
        "type": "metadata",
        "namespace": "nfo",
        "author": "codex",
        "version": "0.1.0",
        "description": "Rust/WASM port of the NFO sidecar metadata plugin.",
        "permissions": [
            "metadata.read_input",
            "archive.list_adjacent_files",
            "archive.read_adjacent_text",
            "archive.read_adjacent_texts",
            "tankoubon.list_archives",
            "log.write",
            "progress.report"
        ],
        "parameters": [
            {"name": "hide_thumb_images", "type": "bool", "desc": "Hide sidecar thumb/cover images from files list when episode NFO exists", "default_value": "1"},
            {"name": "apply_episode_sort", "type": "bool", "desc": "Apply season/episode based sort index to media entries", "default_value": "1"},
            {"name": "include_episode_plot", "type": "bool", "desc": "Write episode plot (fallback outline) into page description", "default_value": "1"},
            {"name": "tag_with_source", "type": "bool", "desc": "Add source id tag from NFO uniqueid, e.g. tmdb:4196410", "default_value": "1"}
        ],
        "runtime": "wamr",
        "abi_version": 1
    })
}

fn run_plugin(input: PluginInput) -> Result<Vec<u8>, String> {
    if input.plugin_type.to_ascii_lowercase() != "metadata" {
        return Err("nfo-rs only supports Metadata plugins".to_string());
    }

    let params = input.params;
    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err("missing targetId".to_string());
    }

    let target_type = normalized_target_type(&input.target_type, &params);
    let options = ArchiveModeOptions {
        hide_thumb_images: read_bool_param(&params, "hide_thumb_images", true),
        apply_episode_sort: read_bool_param(&params, "apply_episode_sort", true),
        include_episode_plot: read_bool_param(&params, "include_episode_plot", true),
        tag_with_source: read_bool_param(&params, "tag_with_source", true),
    };

    let metadata = ensure_metadata_object(input.metadata);
    HostBridge::progress(5, "starting nfo-rs");
    let output = if target_type == "tankoubon" || target_type == "tank" {
        run_tankoubon_mode(target_id, options, metadata)?
    } else {
        run_archive_mode(target_id, options, metadata)?
    };

    serde_json::to_vec(&json!({
        "success": true,
        "data": output,
    }))
    .map_err(|e| e.to_string())
}

#[derive(Clone, Copy)]
struct ArchiveModeOptions {
    hide_thumb_images: bool,
    apply_episode_sort: bool,
    include_episode_plot: bool,
    tag_with_source: bool,
}

fn run_archive_mode(
    archive_id: &str,
    options: ArchiveModeOptions,
    mut metadata: Map<String, Value>,
) -> Result<Value, String> {
    HostBridge::progress(10, "listing adjacent files");
    let listing = HostBridge::list_adjacent_files(archive_id, 0)?;
    let index = ListingIndex::new(listing.files);
    let nfo_files = index.nfo_files_sorted();
    let text_map = HostBridge::read_adjacent_texts(archive_id, &nfo_files, 0).unwrap_or_default();
    HostBridge::progress(18, &format!("found {} nfo sidecar files", nfo_files.len()));

    let mut archive_title = metadata_string(&metadata, "title");
    let mut archive_summary = metadata_string(&metadata, "description");
    let mut season_number_hint = 0i64;
    let mut selected_source: Option<SourceTagCandidate> = None;
    let mut discovered_tags: BTreeSet<String> = BTreeSet::new();
    let mut page_patches: HashMap<String, Value> = HashMap::new();
    let mut first_page_cover_fallback = String::new();
    let mut first_page_cover_sort = 0i64;

    if !nfo_files.is_empty() {
        HostBridge::progress(28, "parsing NFO sidecars");
    }

    for nfo_file in nfo_files.iter() {
        let Some(xml) = text_map.get(nfo_file) else {
            continue;
        };
        let doc = parse_nfo(xml);
        let lower = nfo_file.to_ascii_lowercase();
        selected_source = pick_better_source(selected_source, parse_source_tag_candidate(&doc));
        if lower == "season.nfo" {
            for tag in parse_tv_tags(&doc, false) {
                discovered_tags.insert(tag);
            }
            let season_title = read_xml_tag(&doc, &["title"]);
            let season_summary = first_non_empty(&[
                read_xml_tag(&doc, &["plot"]),
                read_xml_tag(&doc, &["outline"]),
            ]);
            let season_number = read_xml_int(&doc, &["seasonnumber", "season"]);
            if season_number > 0 {
                season_number_hint = season_number;
            }
            discovered_tags.insert("media:tv".to_string());
            discovered_tags.insert("media:season".to_string());
            if season_number > 0 {
                discovered_tags.insert(format!("season:{season_number}"));
            }
            if !season_title.is_empty() {
                archive_title = season_title;
            }
            if !season_summary.is_empty() {
                archive_summary = season_summary;
            }
            continue;
        }

        let base_name = strip_extension(nfo_file);
        let episode_meta = parse_episode_nfo(&doc, nfo_file);
        if season_number_hint <= 0 && episode_meta.season > 0 {
            season_number_hint = episode_meta.season;
        }

        if is_movie_nfo(&doc) {
            for tag in parse_tv_tags(&doc, false) {
                discovered_tags.insert(tag);
            }
            let movie_title = read_xml_tag(&doc, &["title"]);
            if !movie_title.is_empty() {
                archive_title = movie_title;
            }
            let movie_summary = first_non_empty(&[
                read_xml_tag(&doc, &["plot"]),
                read_xml_tag(&doc, &["outline"]),
            ]);
            if !movie_summary.is_empty() {
                archive_summary = movie_summary;
            }
        }

        let media_path = index.best_media_file(&base_name);
        if media_path.is_empty() {
            continue;
        }
        let attachment_candidates = index.page_attachment_candidates(&base_name);

        let mut patch = Map::new();
        patch.insert("entry_path".to_string(), Value::String(media_path.clone()));
        patch.insert(
            "title".to_string(),
            Value::String(build_episode_display_title(&episode_meta)),
        );
        if options.include_episode_plot && !episode_meta.summary.is_empty() {
            patch.insert(
                "description".to_string(),
                Value::String(episode_meta.summary.clone()),
            );
        }
        if !episode_meta.aired.is_empty() {
            patch.insert(
                "release_at".to_string(),
                Value::String(episode_meta.aired.clone()),
            );
        }

        let sort = if options.apply_episode_sort {
            build_sort_index(&base_name, &episode_meta)
        } else {
            0
        };
        if sort > 0 {
            patch.insert("order_index".to_string(), json!(sort));
        }

        let cover_candidates = index.cover_candidates(&base_name, &media_path);
        let thumb_ref = cover_candidates
            .first()
            .map(|path| adjacent_ref(path, 0))
            .unwrap_or_default();
        if !thumb_ref.is_empty() {
            patch.insert("thumb".to_string(), Value::String(thumb_ref.clone()));
            if first_page_cover_fallback.is_empty()
                || (sort > 0 && (first_page_cover_sort <= 0 || sort < first_page_cover_sort))
            {
                first_page_cover_fallback = thumb_ref;
                first_page_cover_sort = sort;
            }
        }
        if !attachment_candidates.is_empty() {
            patch.insert(
                "attachments".to_string(),
                Value::Array(
                    attachment_candidates
                        .iter()
                        .map(|attachment| {
                            json!({
                                "slot": attachment.slot,
                                "path": adjacent_ref(&attachment.path, 0),
                                "name": attachment.name,
                                "mime_type": attachment.mime_type,
                                "kind": attachment.kind,
                                "language": attachment.language,
                            })
                        })
                        .collect(),
                ),
            );
        }

        page_patches.insert(media_path.clone(), Value::Object(patch));
        if options.hide_thumb_images {
            for cover_path in cover_candidates {
                page_patches.insert(
                    cover_path.clone(),
                    json!({
                        "entry_path": cover_path,
                        "hidden_in_files": true
                    }),
                );
            }
        }
    }

    HostBridge::progress(64, "finalizing page metadata");
    HostBridge::progress(80, "resolving archive artwork");
    let parent_index = HostBridge::list_adjacent_files(archive_id, 1)
        .map(|parent_listing| ListingIndex::new(parent_listing.files))
        .unwrap_or_default();
    let mut archive_cover = index.archive_cover(&parent_index, season_number_hint);
    if archive_cover.is_empty() {
        archive_cover = first_page_cover_fallback;
    }
    let archive_backdrop = index.archive_artwork(&parent_index, season_number_hint, ArtworkKey::Backdrop);
    let archive_clearlogo =
        index.archive_artwork(&parent_index, season_number_hint, ArtworkKey::Clearlogo);

    HostBridge::progress(90, "composing archive metadata");
    let mut tags = metadata_tags(&metadata);
    tags.extend(discovered_tags.into_iter());
    let parent_tvshow = read_tvshow_info_for_archive(archive_id).unwrap_or_default();
    tags.extend(parent_tvshow.tags.clone());
    if season_number_hint > 0 {
        tags.push("media:tv".to_string());
        tags.push("media:season".to_string());
        tags.push(format!("season:{season_number_hint}"));
    }
    if options.tag_with_source {
        tags.retain(|tag| tag.to_ascii_lowercase() != "source:nfo");
        if let Some(source) = selected_source {
            if !source.tag.is_empty() {
                tags.push(source.tag);
            } else if !parent_tvshow.source_tag.is_empty() {
                tags.push(parent_tvshow.source_tag);
            }
        } else if !parent_tvshow.source_tag.is_empty() {
            tags.push(parent_tvshow.source_tag);
        }
    }
    if archive_title.trim().is_empty() && season_number_hint > 0 && !parent_tvshow.title.is_empty() {
        archive_title = format_season_title(&parent_tvshow.title, season_number_hint);
    }
    if archive_summary.trim().is_empty() && !parent_tvshow.summary.is_empty() {
        archive_summary = parent_tvshow.summary;
    }

    if !archive_title.trim().is_empty() {
        metadata.insert("title".to_string(), Value::String(archive_title));
    }
    metadata.insert("description".to_string(), Value::String(archive_summary));
    metadata.insert("tags".to_string(), json!(unique_strings(tags)));
    set_asset_value(&mut metadata, "cover", &archive_cover);
    set_asset_value(&mut metadata, "backdrop", &archive_backdrop);
    set_asset_value(&mut metadata, "clearlogo", &archive_clearlogo);
    metadata.insert("children".to_string(), Value::Array(vec![]));
    metadata.remove("archive");
    metadata.remove("archive_id");
    metadata.insert(
        "pages".to_string(),
        Value::Array(page_patches.into_values().collect()),
    );

    HostBridge::progress(100, "nfo-rs metadata done");
    Ok(Value::Object(metadata))
}

fn run_tankoubon_mode(
    tankoubon_id: &str,
    options: ArchiveModeOptions,
    mut metadata: Map<String, Value>,
) -> Result<Value, String> {
    HostBridge::progress(10, "listing collection archives");
    let archive_ids = HostBridge::list_tankoubon_archives(tankoubon_id)?;
    HostBridge::progress(
        18,
        &format!("found {} collection archives", archive_ids.len()),
    );
    HostBridge::progress(22, "reading collection tvshow metadata");
    let collection_meta = read_tvshow_metadata_for_tankoubon(&archive_ids).unwrap_or_default();

    let mut patches = Vec::new();
    let mut first_archive_cover = String::new();
    let mut first_archive_backdrop = String::new();
    let mut first_archive_clearlogo = String::new();

    if !archive_ids.is_empty() {
        HostBridge::progress(32, "parsing collection archives");
    }

    for (index, archive_id) in archive_ids.iter().enumerate() {
        let Some(season_meta) = read_season_metadata(archive_id, options) else {
            continue;
        };

        let mut patch_tags = season_meta.tags.clone();
        if options.tag_with_source {
            if !season_meta.source_tag.is_empty() {
                patch_tags.push(season_meta.source_tag.clone());
            } else if !collection_meta.source_tag.is_empty() {
                patch_tags.push(collection_meta.source_tag.clone());
            }
        }

        if first_archive_cover.is_empty() && !season_meta.cover.is_empty() {
            first_archive_cover = season_meta.cover.clone();
        }
        if first_archive_backdrop.is_empty() && !season_meta.backdrop.is_empty() {
            first_archive_backdrop = season_meta.backdrop.clone();
        }
        if first_archive_clearlogo.is_empty() && !season_meta.clearlogo.is_empty() {
            first_archive_clearlogo = season_meta.clearlogo.clone();
        }

        let mut child = Map::new();
        child.insert("title".to_string(), Value::String(season_meta.title));
        child.insert("type".to_string(), json!(0));
        child.insert(
            "description".to_string(),
            Value::String(season_meta.summary),
        );
        child.insert("tags".to_string(), json!(unique_strings(patch_tags)));
        child.insert(
            "assets".to_string(),
            json!(build_assets_json(
                &season_meta.cover,
                &season_meta.backdrop,
                &season_meta.clearlogo
            )),
        );
        child.insert("pages".to_string(), Value::Array(season_meta.pages));
        child.insert("volume_no".to_string(), json!(index + 1));
        child.insert("entity_id".to_string(), Value::String(archive_id.clone()));
        child.insert(
            "locator".to_string(),
            json!({
                "entity_type": "archive",
                "entity_id": archive_id,
                "volume_no": index + 1
            }),
        );
        patches.push(Value::Object(child));
    }

    HostBridge::progress(84, "finalizing collection patches");
    HostBridge::progress(92, "composing collection metadata");
    let mut collection_tags = collection_meta.tags;
    if !archive_ids.is_empty() {
        collection_tags.push("media:tv".to_string());
    }
    if options.tag_with_source && !collection_meta.source_tag.is_empty() {
        collection_tags.push(collection_meta.source_tag);
    }
    if !collection_meta.title.is_empty() {
        metadata.insert("title".to_string(), Value::String(collection_meta.title));
    }
    if !collection_meta.summary.is_empty() {
        metadata.insert(
            "description".to_string(),
            Value::String(collection_meta.summary),
        );
    }
    metadata.insert("tags".to_string(), json!(unique_strings(collection_tags)));
    set_asset_value(
        &mut metadata,
        "cover",
        if !collection_meta.cover.is_empty() {
            &collection_meta.cover
        } else {
            &first_archive_cover
        },
    );
    set_asset_value(
        &mut metadata,
        "backdrop",
        if !collection_meta.backdrop.is_empty() {
            &collection_meta.backdrop
        } else {
            &first_archive_backdrop
        },
    );
    set_asset_value(
        &mut metadata,
        "clearlogo",
        if !collection_meta.clearlogo.is_empty() {
            &collection_meta.clearlogo
        } else {
            &first_archive_clearlogo
        },
    );
    metadata.insert("children".to_string(), Value::Array(patches));
    metadata.remove("archive");
    metadata.remove("archive_id");
    HostBridge::progress(100, "collection nfo-rs metadata done");
    Ok(Value::Object(metadata))
}

fn read_season_metadata(archive_id: &str, options: ArchiveModeOptions) -> Option<SeasonMeta> {
    let listing = HostBridge::list_adjacent_files(archive_id, 0).ok()?;
    let index = ListingIndex::new(listing.files);
    let nfo_files = index.nfo_files_sorted();
    if nfo_files.is_empty() {
        return None;
    }
    let text_map = HostBridge::read_adjacent_texts(archive_id, &nfo_files, 0).ok()?;
    let season_doc = index
        .find_file_ignore_ascii_case("season.nfo")
        .and_then(|season_nfo| text_map.get(&season_nfo).map(|xml| parse_nfo(xml)));
    let parent_tvshow = read_tvshow_info_for_archive(archive_id).unwrap_or_default();
    let mut season_number = match (&season_doc) {
        Some(doc) => read_xml_int(doc, &["seasonnumber", "season"]),
        None => 0,
    }
    .max(extract_season_number_from_text(&listing.base_dir));
    let parent_index = HostBridge::list_adjacent_files(archive_id, 1)
        .map(|parent_listing| ListingIndex::new(parent_listing.files))
        .unwrap_or_default();

    let mut page_patches: HashMap<String, Value> = HashMap::new();
    let mut first_page_cover = String::new();
    let mut first_page_cover_sort = 0i64;
    for nfo_file in nfo_files {
        let lower = nfo_file.to_ascii_lowercase();
        if lower == "season.nfo" || lower == "tvshow.nfo" {
            continue;
        }
        let Some(page_xml) = text_map.get(&nfo_file) else {
            continue;
        };
        let page_doc = parse_nfo(page_xml);
        let base_name = strip_extension(&nfo_file);
        let episode_meta = parse_episode_nfo(&page_doc, &nfo_file);
        if season_number <= 0 && episode_meta.season > 0 {
            season_number = episode_meta.season;
        }
        let sort = build_sort_index(&base_name, &episode_meta);
        let media_path = index.best_media_file(&base_name);
        if media_path.is_empty() {
            continue;
        }

        let mut patch = Map::new();
        patch.insert("entry_path".to_string(), Value::String(media_path.clone()));
        patch.insert(
            "title".to_string(),
            Value::String(build_episode_display_title(&episode_meta)),
        );
        if options.include_episode_plot && !episode_meta.summary.is_empty() {
            patch.insert(
                "description".to_string(),
                Value::String(episode_meta.summary.clone()),
            );
        }
        if !episode_meta.aired.is_empty() {
            patch.insert("release_at".to_string(), Value::String(episode_meta.aired.clone()));
        }
        if options.apply_episode_sort {
            if sort > 0 {
                patch.insert("order_index".to_string(), json!(sort));
            }
        }
        let cover_candidates = index.cover_candidates(&base_name, &media_path);
        let attachment_candidates = index.page_attachment_candidates(&base_name);
        if let Some(first) = cover_candidates.first() {
            patch.insert("thumb".to_string(), Value::String(adjacent_ref(first, 0)));
            if first_page_cover.is_empty()
                || (sort > 0 && (first_page_cover_sort <= 0 || sort < first_page_cover_sort))
            {
                first_page_cover = adjacent_ref(first, 0);
                first_page_cover_sort = sort;
            }
        }
        if !attachment_candidates.is_empty() {
            patch.insert(
                "attachments".to_string(),
                Value::Array(
                    attachment_candidates
                        .iter()
                        .map(|attachment| {
                            json!({
                                "slot": attachment.slot,
                                "path": adjacent_ref(&attachment.path, 0),
                                "name": attachment.name,
                                "mime_type": attachment.mime_type,
                                "kind": attachment.kind,
                                "language": attachment.language,
                            })
                        })
                        .collect(),
                ),
            );
        }
        page_patches.insert(media_path, Value::Object(patch));
        if options.hide_thumb_images {
            for cover_path in cover_candidates {
                page_patches.insert(
                    cover_path.clone(),
                    json!({"entry_path": cover_path, "hidden_in_files": true}),
                );
            }
        }
    }

    let mut cover = index.archive_cover(&parent_index, season_number);
    if cover.is_empty() {
        cover = first_page_cover;
    }
    let backdrop = index.archive_artwork(&parent_index, season_number, ArtworkKey::Backdrop);
    let clearlogo = index.archive_artwork(&parent_index, season_number, ArtworkKey::Clearlogo);
    let season_title = match (&season_doc) {
        Some(doc) => read_xml_tag(doc, &["title"]),
        None => String::new(),
    };
    let season_summary = match (&season_doc) {
        Some(doc) => first_non_empty(&[
            read_xml_tag(doc, &["plot"]),
            read_xml_tag(doc, &["outline"]),
        ]),
        None => String::new(),
    };
    let source_tag = match (&season_doc) {
        Some(doc) => {
            let from_season = parse_source_tag(doc);
            if !from_season.is_empty() {
                from_season
            } else {
                parent_tvshow.source_tag.clone()
            }
        }
        None => parent_tvshow.source_tag.clone(),
    };
    let tags = if let Some(doc) = &season_doc {
        let mut tags = build_season_tags(doc, season_number);
        tags.extend(parent_tvshow.tags.clone());
        unique_strings(tags)
    } else {
        let mut tags = parent_tvshow.tags.clone();
        tags.push("media:tv".to_string());
        tags.push("media:season".to_string());
        if season_number > 0 {
            tags.push(format!("season:{season_number}"));
        }
        unique_strings(tags)
    };

    Some(SeasonMeta {
        title: if !season_title.is_empty() {
            season_title
        } else if !parent_tvshow.title.is_empty() && season_number > 0 {
            format_season_title(&parent_tvshow.title, season_number)
        } else {
            parent_tvshow.title.clone()
        },
        summary: if !season_summary.is_empty() {
            season_summary
        } else {
            parent_tvshow.summary.clone()
        },
        source_tag,
        tags,
        cover,
        backdrop,
        clearlogo,
        pages: page_patches.into_values().collect(),
    })
}

fn read_tvshow_metadata_for_tankoubon(archive_ids: &[String]) -> Option<TvshowMeta> {
    let mut visited = HashSet::new();
    for archive_id in archive_ids {
        let listing = HostBridge::list_adjacent_files(archive_id, 1).ok()?;
        if !listing.base_dir.is_empty() && !visited.insert(listing.base_dir.clone()) {
            continue;
        }
        let index = ListingIndex::new(listing.files);
        let tvshow_nfo = index.find_file_ignore_ascii_case("tvshow.nfo")?;
        let xml = HostBridge::read_adjacent_text(archive_id, &tvshow_nfo, 1).ok()?;
        let doc = parse_nfo(&xml);
        let title = read_xml_tag(&doc, &["title"]);
        let summary = first_non_empty(&[
            read_xml_tag(&doc, &["plot"]),
            read_xml_tag(&doc, &["outline"]),
        ]);
        let source_tag = parse_source_tag(&doc);
        let tags = build_tvshow_tags(&doc);
        let cover = index
            .general_cover_candidates()
            .first()
            .map(|path| adjacent_ref(path, 1))
            .unwrap_or_default();
        let backdrop = index
            .artwork_candidates(0, ArtworkKey::Backdrop)
            .first()
            .map(|path| adjacent_ref(path, 1))
            .unwrap_or_default();
        let clearlogo = index
            .artwork_candidates(0, ArtworkKey::Clearlogo)
            .first()
            .map(|path| adjacent_ref(path, 1))
            .unwrap_or_default();
        if !title.is_empty()
            || !summary.is_empty()
            || !source_tag.is_empty()
            || !tags.is_empty()
            || !cover.is_empty()
            || !backdrop.is_empty()
            || !clearlogo.is_empty()
        {
            return Some(TvshowMeta {
                title,
                summary,
                source_tag,
                tags,
                cover,
                backdrop,
                clearlogo,
            });
        }
    }
    None
}

fn read_tvshow_info_for_archive(archive_id: &str) -> Result<TvshowMeta, String> {
    let listing = HostBridge::list_adjacent_files(archive_id, 1)?;
    let index = ListingIndex::new(listing.files);
    let Some(tvshow_nfo) = index.find_file_ignore_ascii_case("tvshow.nfo") else {
        return Ok(TvshowMeta::default());
    };
    let xml = HostBridge::read_adjacent_text(archive_id, &tvshow_nfo, 1)?;
    let doc = parse_nfo(&xml);
    Ok(TvshowMeta {
        title: read_xml_tag(&doc, &["title"]),
        summary: first_non_empty(&[
            read_xml_tag(&doc, &["plot"]),
            read_xml_tag(&doc, &["outline"]),
        ]),
        source_tag: parse_source_tag(&doc),
        tags: build_tvshow_tags(&doc),
        ..TvshowMeta::default()
    })
}

fn parse_episode_nfo(doc: &ParsedNfo, file_name: &str) -> EpisodeMeta {
    let season = read_xml_int(doc, &["season", "seasonnumber"]);
    let episode = read_xml_int(doc, &["episode"]);
    EpisodeMeta {
        title: first_non_empty(&[
            read_xml_tag(doc, &["title"]),
            read_xml_tag(doc, &["originaltitle"]),
            strip_extension(file_name),
        ]),
        summary: first_non_empty(&[
            read_xml_tag(doc, &["plot"]),
            read_xml_tag(doc, &["outline"]),
        ]),
        season,
        episode,
        aired: first_non_empty(&[
            read_xml_tag(doc, &["aired"]),
            read_xml_tag(doc, &["premiered"]),
        ]),
    }
}

fn build_episode_display_title(meta: &EpisodeMeta) -> String {
    let plain_title = meta.title.trim();
    if meta.season > 0 && meta.episode > 0 {
        if plain_title.is_empty() {
            return format!("S{:02}E{:02}", meta.season, meta.episode);
        }
        return format!("S{:02}E{:02} {}", meta.season, meta.episode, plain_title);
    }
    plain_title.to_string()
}

fn format_season_title(base_title: &str, season_number: i64) -> String {
    let title = base_title.trim();
    if title.is_empty() || season_number <= 0 {
        return title.to_string();
    }
    format!("{title} Season {season_number}")
}

fn build_tvshow_tags(doc: &ParsedNfo) -> Vec<String> {
    let mut tags = parse_tv_tags(doc, true);
    tags.push("media:tv".to_string());
    unique_strings(tags)
}

fn build_season_tags(doc: &ParsedNfo, season_number: i64) -> Vec<String> {
    let mut tags = parse_tv_tags(doc, true);
    tags.push("media:tv".to_string());
    tags.push("media:season".to_string());
    if season_number > 0 {
        tags.push(format!("season:{season_number}"));
    }
    unique_strings(tags)
}

fn parse_tv_tags(doc: &ParsedNfo, include_people: bool) -> Vec<String> {
    let mut tags = Vec::new();
    tags.extend(read_xml_tags(doc, &["genre"]).into_iter().map(|value| format!("genre:{value}")));
    tags.extend(read_xml_tags(doc, &["tag"]).into_iter().map(|value| format!("tag:{value}")));
    tags.extend(read_xml_tags(doc, &["studio"]).into_iter().map(|value| format!("studio:{value}")));
    tags.extend(read_xml_tags(doc, &["country"]).into_iter().map(|value| format!("country:{value}")));
    tags.extend(read_xml_tags(doc, &["status"]).into_iter().map(|value| format!("status:{}", value.to_ascii_lowercase())));
    tags.extend(read_xml_tags(doc, &["mpaa", "certification"]).into_iter().map(|value| format!("certification:{value}")));

    let year = read_xml_tag(doc, &["year"]);
    if !year.is_empty() {
        tags.push(format!("year:{year}"));
    }
    let premiered = read_xml_tag(doc, &["premiered"]);
    if !premiered.is_empty() {
        tags.push(format!("aired:{premiered}"));
    }
    let end_date = read_xml_tag(doc, &["enddate"]);
    if !end_date.is_empty() {
        tags.push(format!("ended:{end_date}"));
    }
    let runtime = read_xml_tag(doc, &["runtime"]);
    if !runtime.is_empty() {
        tags.push(format!("runtime:{runtime}"));
    }
    let season = read_xml_int(doc, &["season", "seasonnumber"]);
    if season > 0 {
        tags.push(format!("season:{season}"));
    }
    let episode = read_xml_int(doc, &["episode"]);
    if episode > 0 {
        tags.push(format!("episode:{episode}"));
    }

    if include_people {
        tags.extend(read_xml_tags(doc, &["name"]).into_iter().map(|value| format!("cast:{value}")));
        tags.extend(read_xml_tags(doc, &["director"]).into_iter().map(|value| format!("director:{value}")));
        tags.extend(read_xml_tags(doc, &["credits"]).into_iter().map(|value| format!("writer:{value}")));
    }

    unique_strings(tags)
}

fn parse_source_tag(doc: &ParsedNfo) -> String {
    parse_source_tag_candidate(doc)
        .map(|candidate| candidate.tag)
        .unwrap_or_default()
}

fn parse_source_tag_candidate(doc: &ParsedNfo) -> Option<SourceTagCandidate> {
    if let Some(best) = extract_best_unique_id(doc) {
        return Some(best);
    }

    for (keys, tag_type, score) in [
        (&["tmdbid", "tmdb"][..], "tmdb", 450),
        (&["tvdbid", "tvdb"][..], "tvdb", 430),
        (&["imdbid", "imdb"][..], "imdb", 420),
        (&["traktid", "trakt"][..], "trakt", 410),
    ] {
        let value = read_xml_tag(doc, keys);
        if value.is_empty() {
            continue;
        }
        let normalized = normalize_source_value(tag_type, &value);
        if normalized.is_empty() {
            continue;
        }
        return Some(SourceTagCandidate {
            tag: format!("source:{tag_type}:{normalized}"),
            score,
        });
    }

    None
}

fn extract_best_unique_id(doc: &ParsedNfo) -> Option<SourceTagCandidate> {
    let mut best: Option<SourceTagCandidate> = None;

    for unique_id in &doc.unique_ids {
        let raw_value = unique_id.value.trim();
        if raw_value.is_empty() {
            continue;
        }
        let source_type = normalize_source_type(&unique_id.source_type);
        if source_type.is_empty() {
            continue;
        }
        let normalized = normalize_source_value(&source_type, raw_value);
        if normalized.is_empty() {
            continue;
        }
        let default_attr = unique_id.default_attr.to_ascii_lowercase();
        let is_default = matches!(default_attr.as_str(), "true" | "1" | "yes");
        let candidate = SourceTagCandidate {
            tag: format!("source:{source_type}:{normalized}"),
            score: source_type_priority(&source_type) + if is_default { 100 } else { 0 },
        };
        best = pick_better_source(best, Some(candidate));
    }

    best
}

fn pick_better_source(
    current: Option<SourceTagCandidate>,
    candidate: Option<SourceTagCandidate>,
) -> Option<SourceTagCandidate> {
    match (current, candidate) {
        (None, None) => None,
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (Some(current), Some(candidate)) => {
            if candidate.score > current.score {
                Some(candidate)
            } else {
                Some(current)
            }
        }
    }
}

fn parse_nfo(xml: &str) -> ParsedNfo {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut parsed = ParsedNfo::default();
    let mut stack = Vec::<XmlElementContext>::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let name = xml_name(event.name().as_ref());
                if parsed.root_name.is_empty() {
                    parsed.root_name = name.clone();
                }
                stack.push(XmlElementContext {
                    name,
                    text: String::new(),
                    attrs: collect_xml_attrs(&reader, &event),
                });
            }
            Ok(Event::Empty(event)) => {
                let name = xml_name(event.name().as_ref());
                if parsed.root_name.is_empty() {
                    parsed.root_name = name.clone();
                }
                finalize_xml_node(
                    &mut parsed,
                    &mut stack,
                    XmlElementContext {
                        name,
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
            Err(_) => return ParsedNfo::default(),
            _ => {}
        }
    }

    parsed
}

fn xml_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    name.rsplit(':')
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
    parsed: &mut ParsedNfo,
    stack: &mut Vec<XmlElementContext>,
    node: XmlElementContext,
) {
    let normalized = normalize_xml_text(&node.text);
    if !normalized.is_empty() {
        parsed
            .tags
            .entry(node.name.clone())
            .or_default()
            .push(normalized.clone());

        if node.name == "uniqueid" {
            parsed.unique_ids.push(ParsedUniqueId {
                value: normalized,
                source_type: node
                    .attrs
                    .iter()
                    .find(|(key, _)| key == "type")
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default(),
                default_attr: node
                    .attrs
                    .iter()
                    .find(|(key, _)| key == "default")
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default(),
            });
        }
    }

    if let Some(parent) = stack.last_mut() {
        parent.text.push_str(&node.text);
    }
}

fn normalize_xml_text(value: &str) -> String {
    value.trim().to_string()
}

fn read_xml_tag(doc: &ParsedNfo, tag_names: &[&str]) -> String {
    read_xml_tags(doc, tag_names)
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn read_xml_tags(doc: &ParsedNfo, tag_names: &[&str]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for tag_name in tag_names {
        if let Some(values) = doc.tags.get(*tag_name) {
            for value in values {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    out.insert(trimmed.to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

fn read_xml_int(doc: &ParsedNfo, tag_names: &[&str]) -> i64 {
    read_xml_tag(doc, tag_names)
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
}

fn is_movie_nfo(doc: &ParsedNfo) -> bool {
    doc.root_name == "movie"
}

fn source_type_priority(value: &str) -> i64 {
    match value {
        "tmdb" => 900,
        "tvdb" => 800,
        "imdb" => 700,
        "trakt" => 600,
        _ => 500,
    }
}

fn normalize_source_type(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "tmdb" | "themoviedb" => "tmdb".to_string(),
        "tvdb" | "thetvdb" => "tvdb".to_string(),
        "imdb" => "imdb".to_string(),
        "trakt" => "trakt".to_string(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn normalize_source_value(source_type: &str, value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if source_type == "imdb" {
        let pure = trimmed.trim_start_matches("tt");
        if pure.chars().all(|ch| ch.is_ascii_digit()) {
            return format!("tt{pure}");
        }
        return String::new();
    }
    trimmed.to_string()
}

fn normalized_target_type(raw: &str, params: &Value) -> String {
    if !raw.trim().is_empty() {
        return raw.trim().to_ascii_lowercase();
    }
    params
        .get("__target_type")
        .and_then(Value::as_str)
        .unwrap_or("archive")
        .trim()
        .to_ascii_lowercase()
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

fn metadata_string(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
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

fn set_asset_value(metadata: &mut Map<String, Value>, key: &str, value: &str) {
    let mut assets = metadata
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assets.retain(|item| item.get("key").and_then(Value::as_str) != Some(key));
    if !value.trim().is_empty() {
        assets.push(json!({"key": key, "value": value}));
    }
    metadata.insert("assets".to_string(), Value::Array(assets));
}

fn build_assets_json(cover: &str, backdrop: &str, clearlogo: &str) -> Vec<Value> {
    let mut assets = Vec::new();
    if !cover.is_empty() {
        assets.push(json!({"key":"cover","value":cover}));
    }
    if !backdrop.is_empty() {
        assets.push(json!({"key":"backdrop","value":backdrop}));
    }
    if !clearlogo.is_empty() {
        assets.push(json!({"key":"clearlogo","value":clearlogo}));
    }
    assets
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

fn strip_extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(left, _)| left.to_string())
        .unwrap_or_else(|| name.to_string())
}

fn parse_page_attachment_stem(name: &str) -> Option<(String, String, String)> {
    let lower = name.to_ascii_lowercase();
    let (without_kind, kind) = lower.rsplit_once('.')?;
    if !matches!(
        kind,
        "ass" | "ssa" | "srt" | "vtt" | "sub" | "idx" | "sup"
    ) {
        return None;
    }
    let mut base = without_kind.to_string();
    let mut language = String::new();
    if let Some((candidate_base, candidate_language)) = without_kind.rsplit_once('.') {
        if looks_like_attachment_language(candidate_language) {
            base = candidate_base.to_string();
            language = candidate_language.to_string();
        }
    }
    Some((base, language, kind.to_string()))
}

fn match_page_attachment_to_base(name: &str, media_base: &str) -> Option<(String, String)> {
    let (attachment_base, language, kind) = parse_page_attachment_stem(name)?;
    let normalized_media_base = media_base.to_ascii_lowercase();
    if attachment_base == normalized_media_base {
        return Some((language, kind));
    }
    let rest = attachment_base.strip_prefix(&normalized_media_base)?;
    if !rest.starts_with('.') {
        return None;
    }
    let suffix = rest.trim_start_matches('.');
    if suffix.is_empty() {
        return Some((language, kind));
    }

    let mut detected_language = language;
    if detected_language.is_empty() {
        for segment in suffix.rsplit('.') {
            if looks_like_attachment_language(segment) {
                detected_language = segment.to_string();
                break;
            }
        }
    }
    Some((detected_language, kind))
}

fn looks_like_attachment_language(value: &str) -> bool {
    let trimmed = value.trim();
    let size = trimmed.len();
    if !(2..=15).contains(&size) {
        return false;
    }
    trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn attachment_mime_type(kind: &str) -> &'static str {
    match kind {
        "ass" | "ssa" => "text/x-ssa",
        "srt" => "application/x-subrip",
        "vtt" => "text/vtt",
        _ => "application/octet-stream",
    }
}

fn classify_file_kind(lower_name: &str) -> FileKind {
    if has_any_suffix(lower_name, &[".nfo"]) {
        FileKind::Nfo
    } else if has_any_suffix(
        lower_name,
        &[".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v"],
    ) {
        FileKind::Video
    } else if has_any_suffix(
        lower_name,
        &[".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif"],
    ) {
        FileKind::Image
    } else {
        FileKind::Other
    }
}

fn has_any_suffix(value: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| value.ends_with(suffix))
}

fn looks_like_episode_stem(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b's' {
            continue;
        }
        let mut cursor = index + 1;
        let season_digits = consume_ascii_digits(bytes, &mut cursor, 3);
        if season_digits == 0 || cursor >= bytes.len() || bytes[cursor] != b'e' {
            continue;
        }
        cursor += 1;
        if consume_ascii_digits(bytes, &mut cursor, 4) > 0 {
            return true;
        }
    }
    false
}

fn extract_season_number_from_text(text: &str) -> i64 {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return 0;
    }
    let bytes = lower.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index..].starts_with(b"season") {
            let mut cursor = index + "season".len();
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'_' | b'-') {
                cursor += 1;
            }
            if let Some(value) = parse_ascii_int_prefix(bytes, &mut cursor, 3) {
                return value;
            }
        }
        if bytes[index] == b's' && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric()) {
            let mut cursor = index + 1;
            if let Some(value) = parse_ascii_int_prefix(bytes, &mut cursor, 3) {
                if cursor == bytes.len() || !bytes[cursor].is_ascii_alphanumeric() {
                    return value;
                }
            }
        }
    }
    0
}

fn build_sort_index(base_name: &str, meta: &EpisodeMeta) -> i64 {
    if meta.season > 0 && meta.episode > 0 {
        return meta.season * 10000 + meta.episode;
    }
    let lower = base_name.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b's' {
            continue;
        }
        let season_start = index + 1;
        let mut cursor = season_start;
        if consume_ascii_digits(bytes, &mut cursor, 3) == 0 || cursor >= bytes.len() || bytes[cursor] != b'e' {
            continue;
        }
        let season = parse_ascii_int(&bytes[season_start..cursor]).unwrap_or(0);
        let episode_start = cursor + 1;
        cursor = episode_start;
        if consume_ascii_digits(bytes, &mut cursor, 4) == 0 {
            continue;
        }
        let episode = parse_ascii_int(&bytes[episode_start..cursor]).unwrap_or(0);
        if season > 0 && episode > 0 {
            return season * 10000 + episode;
        }
    }
    0
}

fn consume_ascii_digits(bytes: &[u8], cursor: &mut usize, max_len: usize) -> usize {
    let start = *cursor;
    while *cursor < bytes.len() && (*cursor - start) < max_len && bytes[*cursor].is_ascii_digit() {
        *cursor += 1;
    }
    *cursor - start
}

fn parse_ascii_int_prefix(bytes: &[u8], cursor: &mut usize, max_len: usize) -> Option<i64> {
    let start = *cursor;
    if consume_ascii_digits(bytes, cursor, max_len) == 0 {
        return None;
    }
    parse_ascii_int(&bytes[start..*cursor])
}

fn parse_ascii_int(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.parse::<i64>().ok()
}

fn score_cover_candidate(stem: &str, base: &str) -> i64 {
    if stem == format!("{base}-poster") || stem == format!("{base}_poster") {
        return 100;
    }
    if stem == format!("{base}.poster") {
        return 98;
    }
    if stem == format!("{base}-cover") || stem == format!("{base}_cover") {
        return 95;
    }
    if stem == format!("{base}.cover") {
        return 93;
    }
    if stem.contains("poster") {
        return 80;
    }
    if stem.contains("cover") {
        return 70;
    }
    if stem == format!("{base}-thumb") || stem == format!("{base}_thumb") {
        return 60;
    }
    if stem == format!("{base}.thumb") {
        return 55;
    }
    if stem.contains("thumb") {
        return 50;
    }
    if stem == base {
        return 10;
    }
    1
}

fn score_general_cover_candidate(stem: &str) -> i64 {
    match stem {
        "poster" => 1000,
        "folder" => 980,
        "cover" => 960,
        "thumb" => 940,
        "landscape" => 900,
        "backdrop" => 850,
        "fanart" => 800,
        _ if stem.contains("poster") => 700,
        _ if stem.contains("cover") => 650,
        _ if stem.contains("thumb") => 620,
        _ if stem.contains("backdrop") || stem.contains("fanart") => 600,
        _ => 0,
    }
}

fn score_general_artwork_candidate(stem: &str, asset_key: ArtworkKey) -> i64 {
    match asset_key {
        ArtworkKey::Backdrop => match stem {
            "backdrop" => 1100,
            "fanart" => 1080,
            "landscape" => 1040,
            "background" => 980,
            _ if matches_stem_token(stem, "backdrop") => 820,
            _ if matches_stem_token(stem, "fanart") => 780,
            _ if matches_stem_token(stem, "landscape") => 740,
            _ if matches_stem_token(stem, "background") => 700,
            _ => 0,
        },
        ArtworkKey::Clearlogo => match stem {
            "clearlogo" => 1100,
            "logo" => 1000,
            _ if matches_stem_token(stem, "clearlogo") => 920,
            _ if matches_stem_token(stem, "logo") => 780,
            _ => 0,
        },
    }
}

fn score_season_artwork_candidate(stem: &str, token: &str, asset_key: ArtworkKey) -> i64 {
    if token.is_empty() {
        return 0;
    }
    match asset_key {
        ArtworkKey::Backdrop => {
            if stem == format!("{token}-backdrop") || stem == format!("{token}_backdrop") {
                1500
            } else if stem == format!("{token}-fanart") || stem == format!("{token}_fanart") {
                1480
            } else if stem.contains(token) && matches_stem_token(stem, "backdrop") {
                1380
            } else if stem.contains(token) && matches_stem_token(stem, "fanart") {
                1340
            } else if stem.contains(token) && matches_stem_token(stem, "landscape") {
                1280
            } else {
                0
            }
        }
        ArtworkKey::Clearlogo => {
            if stem == format!("{token}-clearlogo") || stem == format!("{token}_clearlogo") {
                1500
            } else if stem == format!("{token}-logo") || stem == format!("{token}_logo") {
                1450
            } else if stem.contains(token) && matches_stem_token(stem, "clearlogo") {
                1380
            } else if stem.contains(token) && matches_stem_token(stem, "logo") {
                1260
            } else {
                0
            }
        }
    }
}

fn score_season_specific_artwork_candidate(stem: &str, token: &str, asset_key: ArtworkKey) -> i64 {
    let score = score_season_artwork_candidate(stem, token, asset_key);
    if score > 0 {
        score + 120
    } else {
        0
    }
}

fn score_season_specific_cover_candidate(stem: &str, token: &str) -> i64 {
    if token.is_empty() {
        return 0;
    }
    if stem == format!("{token}-poster") || stem == format!("{token}_poster") {
        1600
    } else if stem == token {
        1500
    } else if stem.contains(token) && stem.contains("poster") {
        1450
    } else if stem.contains(token) && stem.contains("cover") {
        1350
    } else if stem.contains(token) && stem.contains("thumb") {
        1250
    } else if stem.contains(token) {
        1150
    } else {
        0
    }
}

fn build_season_tokens(season_number: i64) -> Vec<String> {
    if season_number <= 0 {
        return vec![];
    }
    let n = season_number;
    let nn = format!("{n:02}");
    unique_strings(vec![
        format!("season{n}"),
        format!("season{nn}"),
        format!("season_{n}"),
        format!("season_{nn}"),
        format!("season-{n}"),
        format!("season-{nn}"),
        format!("season {n}"),
        format!("season {nn}"),
        format!("s{n}"),
        format!("s{nn}"),
    ])
}

fn matches_stem_token(stem: &str, token: &str) -> bool {
    stem.split(['.', '_', '-', ' '])
        .any(|part| part.eq_ignore_ascii_case(token))
}

fn strip_sidecar_cover_suffix(stem: &str) -> String {
    for suffix in [
        ".poster", "-poster", "_poster", ".cover", "-cover", "_cover", ".thumb", "-thumb",
        "_thumb",
    ] {
        if let Some(base) = stem.strip_suffix(suffix) {
            return base.to_string();
        }
    }
    stem.to_string()
}

fn adjacent_ref(path: &str, levels_up: i64) -> String {
    format!("adjacent://{levels_up}/{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_language_suffix_subtitle_attachment() {
        let parsed = parse_page_attachment_stem("episode01.zh-cn.ass").unwrap();
        assert_eq!(parsed.0, "episode01");
        assert_eq!(parsed.1, "zh-cn");
        assert_eq!(parsed.2, "ass");
    }

    #[test]
    fn parses_plain_subtitle_attachment() {
        let parsed = parse_page_attachment_stem("episode01.srt").unwrap();
        assert_eq!(parsed.0, "episode01");
        assert_eq!(parsed.1, "");
        assert_eq!(parsed.2, "srt");
    }

    #[test]
    fn matches_attachment_with_nonstandard_suffix() {
        let matched = match_page_attachment_to_base(
            "episode01.chs[DandanID_danmu].ass",
            "episode01",
        )
        .unwrap();
        assert_eq!(matched.0, "");
        assert_eq!(matched.1, "ass");
    }

    #[test]
    fn matches_attachment_with_non_ascii_descriptor_suffix() {
        let matched = match_page_attachment_to_base(
            "episode01.chinese(简).srt",
            "episode01",
        )
        .unwrap();
        assert_eq!(matched.0, "");
        assert_eq!(matched.1, "srt");
    }

    #[test]
    fn extracts_language_from_multi_suffix_attachment() {
        let matched = match_page_attachment_to_base(
            "episode01.default.zh-cn.ass",
            "episode01",
        )
        .unwrap();
        assert_eq!(matched.0, "zh-cn");
        assert_eq!(matched.1, "ass");
    }
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

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.error.clear();
        state.result.clear();
    });
}

fn set_error_and_zero(message: String) -> i32 {
    HostBridge::log(0, &message);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.error = message.into_bytes();
        state.result.clear();
    });
    0
}
