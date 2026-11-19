use crate::manifest::Plugin;
use crate::ui;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Build each selected plugin and copy the wasm artifact to
/// `dist/<plugin>/<plugin>.wasm`.
///
/// Cargo always runs with `current_dir(member)` so crate-level
/// `.cargo/config.toml` (rustflags for nfo-rs / ehdb-rs) is honoured in both
/// the legacy 40-crate layout and a future root workspace.
pub fn run(root: &Path, plugins: &[&Plugin]) -> Result<()> {
    if plugins.is_empty() {
        println!("no plugins selected; nothing to build");
        return Ok(());
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut failed = Vec::new();

    for plugin in plugins {
        match build_one(root, plugin, &cargo) {
            Ok((source, dest)) => {
                let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                let dest_rel = dest.strip_prefix(root).unwrap_or(&dest);
                let _ = ui::print_line(format_args!(
                    "✅ {:<22} {} -> {} ({} bytes)",
                    plugin.name,
                    source.display(),
                    dest_rel.display(),
                    size
                ));
            }
            Err(err) => {
                eprintln!("❌ {:<22} {err:#}", plugin.name);
                failed.push(plugin.name.clone());
            }
        }
    }

    if !failed.is_empty() {
        bail!(
            "{} plugin build(s) failed: {}",
            failed.len(),
            failed.join(", ")
        );
    }
    Ok(())
}

fn build_one(root: &Path, plugin: &Plugin, cargo: &str) -> Result<(PathBuf, PathBuf)> {
    let member = root.join(&plugin.dir);
    if !member.join("Cargo.toml").is_file() {
        bail!("missing Cargo.toml at {}", member.display());
    }

    // Metadata is layout-agnostic: target_directory is member/target in the
    // legacy layout and <root>/target inside a workspace. The lib target name
    // also covers any future `[lib] name = ...` override.
    let meta_output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .current_dir(&member)
        .output()
        .with_context(|| format!("run cargo metadata in {}", member.display()))?;
    if !meta_output.status.success() {
        bail!(
            "cargo metadata failed in {}: {}",
            member.display(),
            String::from_utf8_lossy(&meta_output.stderr).trim()
        );
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&meta_output.stdout).context("parse cargo metadata JSON")?;
    let target_directory = metadata
        .get("target_directory")
        .and_then(|value| value.as_str())
        .context("cargo metadata: missing target_directory")?;
    let packages = metadata
        .get("packages")
        .and_then(|value| value.as_array())
        .context("cargo metadata: missing packages")?;
    let package = packages
        .iter()
        .find(|package| {
            package.get("name").and_then(|value| value.as_str()) == Some(plugin.package.as_str())
        })
        .with_context(|| format!("cargo metadata: package {} not found", plugin.package))?;
    let targets = package
        .get("targets")
        .and_then(|value| value.as_array())
        .context("cargo metadata: missing targets")?;
    let lib_target = targets
        .iter()
        .find(|target| {
            target
                .get("kind")
                .and_then(|value| value.as_array())
                .map(|kinds| {
                    kinds
                        .iter()
                        .any(|kind| matches!(kind.as_str(), Some("cdylib") | Some("lib")))
                })
                .unwrap_or(false)
        })
        .with_context(|| format!("{}: no lib/cdylib target in Cargo.toml", plugin.name))?;
    let lib_name = lib_target
        .get("name")
        .and_then(|value| value.as_str())
        .context("cargo metadata: missing lib target name")?;

    let status = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-wasip1",
        ])
        .current_dir(&member)
        .status()
        .with_context(|| format!("run cargo build in {}", member.display()))?;
    if !status.success() {
        bail!(
            "cargo build failed for {} (target wasm32-wasip1)",
            plugin.name
        );
    }

    let wasm = Path::new(target_directory)
        .join("wasm32-wasip1")
        .join("release")
        .join(format!("{lib_name}.wasm"));
    if !wasm.is_file() {
        let listing = wasm
            .parent()
            .and_then(|dir| std::fs::read_dir(dir).ok())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "<unreadable>".to_string());
        bail!(
            "expected artifact not found: {} (directory contains: {})",
            wasm.display(),
            listing
        );
    }

    let dest_dir = root.join("dist").join(&plugin.name);
    std::fs::create_dir_all(&dest_dir).with_context(|| format!("create {}", dest_dir.display()))?;
    let dest = dest_dir.join(format!("{}.wasm", plugin.name));
    std::fs::copy(&wasm, &dest)
        .with_context(|| format!("copy {} -> {}", wasm.display(), dest.display()))?;
    Ok((wasm, dest))
}
