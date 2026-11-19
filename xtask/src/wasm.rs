use crate::manifest::Plugin;
use crate::ui;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wasmparser::{ExternalKind, Parser, Payload};

pub const REQUIRED_EXPORTS: &[&str] = &[
    "lanlu_plugin_alloc",
    "lanlu_plugin_free",
    "lanlu_plugin_info",
    "lanlu_plugin_info_len",
    "lanlu_plugin_run",
    "lanlu_plugin_result_len",
    "lanlu_plugin_last_error",
    "lanlu_plugin_last_error_len",
];

pub const ALLOWED_IMPORT_MODULES: &[&str] = &["wasmedge_host", "wasi_snapshot_preview1"];

/// Validate each `<dist>/<plugin>/<plugin>.wasm`. Returns true when all pass.
pub fn run(
    root: &Path,
    plugins: &[&Plugin],
    dist: &Path,
    max_size_override: Option<u64>,
) -> Result<bool> {
    let dist = if dist.is_absolute() {
        dist.to_path_buf()
    } else {
        root.join(dist)
    };
    let mut all_ok = true;
    for plugin in plugins {
        let path = dist
            .join(&plugin.name)
            .join(format!("{}.wasm", plugin.name));
        if !path.is_file() {
            eprintln!(
                "❌ {:<22} missing artifact: {}",
                plugin.name,
                path.display()
            );
            all_ok = false;
            continue;
        }
        let max_size = max_size_override.or(plugin.max_size_bytes);
        match check_one(&path, max_size) {
            Ok(report) => {
                let _ = ui::print_line(format_args!(
                    "✅ {:<22} {} bytes, {} import(s) [{}]{}",
                    plugin.name,
                    report.size,
                    report.imports.len(),
                    summarize_imports(&report.imports),
                    if report.has_initialize {
                        ", _initialize exported (host does not call it)"
                    } else {
                        ""
                    }
                ));
            }
            Err(err) => {
                eprintln!("❌ {:<22} {err:#}", plugin.name);
                all_ok = false;
            }
        }
    }
    Ok(all_ok)
}

struct Report {
    size: u64,
    imports: Vec<(String, String)>,
    has_initialize: bool,
}

fn check_one(path: &PathBuf, max_size: Option<u64>) -> Result<Report> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut exports: Vec<String> = Vec::new();
    let mut imports: Vec<(String, String)> = Vec::new();
    let mut has_memory = false;
    let mut has_initialize = false;

    for payload in Parser::new(0).parse_all(&bytes) {
        match payload.context("parse wasm binary")? {
            Payload::Version { num, .. } => {
                if num != 1 {
                    bail!("unsupported wasm binary version {num}");
                }
            }
            Payload::ImportSection(section) => {
                for group in section {
                    let group = group.context("parse wasm import group")?;
                    for entry in group {
                        let (_, import) = entry.context("parse wasm import")?;
                        imports.push((import.module.to_string(), import.name.to_string()));
                    }
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export.context("parse wasm export")?;
                    let name = export.name.to_string();
                    if name == "memory" && matches!(export.kind, ExternalKind::Memory) {
                        has_memory = true;
                    }
                    if name == "_initialize" {
                        has_initialize = true;
                    }
                    exports.push(name);
                }
            }
            _ => {}
        }
    }

    let missing: Vec<&str> = REQUIRED_EXPORTS
        .iter()
        .copied()
        .filter(|required| !exports.iter().any(|export| export == required))
        .collect();
    let disallowed: Vec<String> = imports
        .iter()
        .filter(|(module, _)| !ALLOWED_IMPORT_MODULES.contains(&module.as_str()))
        .map(|(module, name)| format!("{module}::{name}"))
        .collect();

    let size = bytes.len() as u64;
    let mut problems: Vec<String> = Vec::new();
    if !missing.is_empty() {
        problems.push(format!("missing exports: {}", missing.join(", ")));
    }
    if !has_memory {
        problems.push("missing exported memory".to_string());
    }
    if !disallowed.is_empty() {
        problems.push(format!(
            "disallowed import module(s): {}",
            disallowed.join(", ")
        ));
    }
    if let Some(limit) = max_size {
        if size > limit {
            problems.push(format!("size {size} exceeds max_size_bytes {limit}"));
        }
    }

    if problems.is_empty() {
        Ok(Report {
            size,
            imports,
            has_initialize,
        })
    } else {
        bail!(
            "{} (size={size} bytes, imports=[{}]{})",
            problems.join("; "),
            summarize_imports(&imports),
            if has_initialize {
                ", _initialize exported"
            } else {
                ""
            }
        )
    }
}

fn summarize_imports(imports: &[(String, String)]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (module, _) in imports {
        *counts.entry(module.as_str()).or_insert(0) += 1;
    }
    counts
        .iter()
        .map(|(module, count)| format!("{module}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}
