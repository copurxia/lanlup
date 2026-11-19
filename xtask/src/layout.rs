use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Locate the repository root by walking up until plugins.toml is found.
pub fn repo_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().context("cannot read current directory")?;
    loop {
        if dir.join("plugins.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!("could not locate repository root (plugins.toml not found in any parent)");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 40 independent crates, each with its own Cargo.lock/target.
    Legacy,
    /// Root virtual workspace with a single Cargo.lock/target.
    Workspace,
}

/// Detect the layout. Only used for reporting/assertions; commands are
/// layout-agnostic because they always run cargo with `current_dir(member)`.
pub fn detect(root: &Path) -> Layout {
    let root_manifest = root.join("Cargo.toml");
    if let Ok(text) = std::fs::read_to_string(&root_manifest) {
        if let Ok(value) = toml::from_str::<toml::Value>(&text) {
            if value.get("workspace").is_some() {
                return Layout::Workspace;
            }
        }
    }
    Layout::Legacy
}
