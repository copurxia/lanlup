use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<Plugin>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub name: String,
    pub dir: String,
    pub package: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
}

pub fn load(root: &Path) -> Result<Manifest> {
    let path = root.join("plugins.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let manifest: Manifest =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    if manifest.schema != 1 {
        bail!(
            "{}: unsupported schema {}, expected 1",
            path.display(),
            manifest.schema
        );
    }
    Ok(manifest)
}

/// Validate that plugins.toml matches the repository layout:
/// every entry points at a real crate whose [package].name matches,
/// and every top-level *-rs crate directory is listed exactly once.
pub fn check(root: &Path, manifest: &Manifest) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let mut names = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    let mut packages = BTreeSet::new();

    for plugin in &manifest.plugins {
        if !names.insert(plugin.name.clone()) {
            errors.push(format!("duplicate plugin name: {}", plugin.name));
        }
        if !dirs.insert(plugin.dir.clone()) {
            errors.push(format!("duplicate plugin dir: {}", plugin.dir));
        }
        if !packages.insert(plugin.package.clone()) {
            errors.push(format!("duplicate package name: {}", plugin.package));
        }

        let dir = root.join(&plugin.dir);
        if !dir.is_dir() {
            errors.push(format!(
                "{}: directory not found: {}",
                plugin.name,
                dir.display()
            ));
            continue;
        }
        let cargo_toml = dir.join("Cargo.toml");
        if !cargo_toml.is_file() {
            errors.push(format!("{}: missing {}", plugin.name, cargo_toml.display()));
            continue;
        }
        match read_cargo_meta(&cargo_toml) {
            Ok((package_name, is_cdylib)) => {
                if package_name != plugin.package {
                    errors.push(format!(
                        "{}: package mismatch (plugins.toml={}, Cargo.toml={})",
                        plugin.name, plugin.package, package_name
                    ));
                }
                if !is_cdylib {
                    eprintln!(
                        "warning: {} does not declare [lib] crate-type = [\"cdylib\"]",
                        plugin.name
                    );
                }
            }
            Err(err) => errors.push(format!("{}: {err:#}", plugin.name)),
        }
    }

    let on_disk = crate_dirs(root);
    for name in on_disk.difference(&dirs) {
        errors.push(format!(
            "crate directory not listed in plugins.toml: {name}"
        ));
    }
    for name in dirs.difference(&on_disk) {
        errors.push(format!("plugins.toml dir has no crate directory: {name}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        for error in &errors {
            eprintln!("  - {error}");
        }
        bail!("plugins.toml check failed with {} error(s)", errors.len())
    }
}

fn read_cargo_meta(path: &Path) -> Result<(String, bool)> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let package_name = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(|name| name.as_str())
        .map(str::to_owned)
        .with_context(|| format!("missing [package].name in {}", path.display()))?;
    let is_cdylib = value
        .get("lib")
        .and_then(|lib| lib.get("crate-type"))
        .and_then(|crate_type| crate_type.as_array())
        .map(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("cdylib")))
        .unwrap_or(false);
    Ok((package_name, is_cdylib))
}

fn crate_dirs(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.ends_with("-rs") {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Select plugins for a build/check command.
pub fn select<'a>(
    manifest: &'a Manifest,
    root: &Path,
    names: &[String],
    all: bool,
    changed: bool,
    base: &str,
) -> Result<Vec<&'a Plugin>> {
    if !names.is_empty() {
        let mut selected = Vec::with_capacity(names.len());
        for name in names {
            let plugin = manifest
                .plugins
                .iter()
                .find(|plugin| &plugin.name == name)
                .with_context(|| format!("unknown plugin: {name} (see `xtask list`)"))?;
            selected.push(plugin);
        }
        return Ok(selected);
    }
    if all {
        return Ok(manifest.plugins.iter().collect());
    }
    if changed {
        let affected = affected(root, manifest, base)?;
        return Ok(manifest
            .plugins
            .iter()
            .filter(|plugin| affected.contains(&plugin.name))
            .collect());
    }
    bail!("no selection: pass --plugin <name> (repeatable), --all, or --changed")
}

/// Paths under these prefixes invalidate every plugin.
const SHARED_PREFIXES: &[&str] = &[
    "plugins.toml",
    "xtask/",
    "ci/",
    "contracts/",
    ".github/workflows/",
    ".gitea/workflows/",
    "scripts/",
];

pub fn affected(root: &Path, manifest: &Manifest, base: &str) -> Result<BTreeSet<String>> {
    let range = format!("{base}...HEAD");
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", &range])
        .current_dir(root)
        .output()
        .with_context(|| format!("run git diff {range}"))?;
    if !output.status.success() {
        bail!(
            "git diff {range} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut selected = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if SHARED_PREFIXES
            .iter()
            .any(|prefix| line == *prefix || line.starts_with(prefix))
        {
            return Ok(manifest.plugins.iter().map(|p| p.name.clone()).collect());
        }
        for plugin in &manifest.plugins {
            if line == plugin.dir || line.starts_with(&format!("{}/", plugin.dir)) {
                selected.insert(plugin.name.clone());
            }
        }
    }
    Ok(selected)
}
