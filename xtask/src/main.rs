mod build;
mod doctor;
mod env;
mod layout;
mod manifest;
mod ui;
mod wasm;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "xtask", about = "lanlup build and verification tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report toolchain / environment status (exit 2 if required tools are missing)
    Doctor,
    /// List plugins from plugins.toml
    List {
        /// Validate plugins.toml against the repository layout
        #[arg(long)]
        check: bool,
    },
    /// Print plugins affected by changes since a git revision
    Affected {
        /// Git revision to diff against (merge-base triple-dot)
        #[arg(long, default_value = "origin/master")]
        base: String,
    },
    /// Build plugin wasm artifacts into dist/<plugin>/<plugin>.wasm
    Build {
        /// Plugin name from plugins.toml (repeatable)
        #[arg(long, value_name = "NAME")]
        plugin: Vec<String>,
        /// Build every plugin
        #[arg(long, conflicts_with_all = ["plugin", "changed"])]
        all: bool,
        /// Build only plugins affected since --base
        #[arg(long, conflicts_with_all = ["plugin", "all"])]
        changed: bool,
        /// Git revision used by --changed
        #[arg(long, default_value = "origin/master")]
        base: String,
    },
    /// Statically validate built wasm artifacts (exports, imports, memory, size)
    CheckWasm {
        /// Plugin name from plugins.toml (repeatable)
        #[arg(long, value_name = "NAME")]
        plugin: Vec<String>,
        /// Check every plugin
        #[arg(long, conflicts_with = "plugin")]
        all: bool,
        /// Directory containing <plugin>/<plugin>.wasm
        #[arg(long, default_value = "dist")]
        dist: PathBuf,
        /// Override max wasm size in bytes for all selected plugins
        #[arg(long, value_name = "BYTES")]
        max_size: Option<u64>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let root = layout::repo_root()?;
    match cli.command {
        Command::Doctor => doctor::run(),
        Command::List { check } => {
            let manifest = manifest::load(&root)?;
            if check {
                manifest::check(&root, &manifest)?;
                ui::print_line(format_args!(
                    "plugins.toml OK: {} plugin(s), layout={:?}",
                    manifest.plugins.len(),
                    layout::detect(&root)
                ))?;
            } else if ui::print_line(format_args!(
                "{:<22} {:<22} {:<22} {}",
                "NAME", "DIR", "PACKAGE", "KIND"
            ))? {
                for plugin in &manifest.plugins {
                    let printed = ui::print_line(format_args!(
                        "{:<22} {:<22} {:<22} {}",
                        plugin.name,
                        plugin.dir,
                        plugin.package,
                        plugin.kind.as_deref().unwrap_or("-"),
                    ))?;
                    if !printed {
                        break;
                    }
                }
                ui::print_line(format_args!(
                    "\n{} plugin(s), layout={:?}",
                    manifest.plugins.len(),
                    layout::detect(&root)
                ))?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Affected { base } => {
            let manifest = manifest::load(&root)?;
            let affected = manifest::affected(&root, &manifest, &base)?;
            for name in &affected {
                if !ui::print_line(format_args!("{name}"))? {
                    break;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Build {
            plugin,
            all,
            changed,
            base,
        } => {
            let manifest = manifest::load(&root)?;
            let selected = manifest::select(&manifest, &root, &plugin, all, changed, &base)?;
            build::run(&root, &selected)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::CheckWasm {
            plugin,
            all,
            dist,
            max_size,
        } => {
            let manifest = manifest::load(&root)?;
            // check-wasm defaults to every plugin when neither --plugin nor --all is given,
            // so a bare `xtask check-wasm` validates the whole dist tree.
            let selected = if plugin.is_empty() && !all {
                manifest.plugins.iter().collect()
            } else {
                manifest::select(&manifest, &root, &plugin, all, false, "origin/master")?
            };
            let ok = wasm::run(&root, &selected, &dist, max_size)?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}
