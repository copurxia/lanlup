use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate a wasi-sdk installation. Search order:
/// `WASI_SDK_PATH`, `/opt/wasi-sdk-34.0`, `/opt/wasi-sdk`, `$HOME/wasi-sdk-34.0`.
pub fn find_wasi_sdk() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("WASI_SDK_PATH") {
        if !path.trim().is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    candidates.push(PathBuf::from("/opt/wasi-sdk-34.0"));
    candidates.push(PathBuf::from("/opt/wasi-sdk"));
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join("wasi-sdk-34.0"));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.join("bin/clang").is_file())
}

/// Apply the same wasi-sdk environment that CI sets for wasm32-wasip1 builds
/// (`_build-wasip1.yml`): ring reads `WASI_SDK_PATH`, cc-rs reads the
/// `CC_<target>` / `AR_<target>` variables. User-provided values win.
pub fn apply_wasi_sdk_env(command: &mut Command, sdk: &Path) {
    if std::env::var_os("WASI_SDK_PATH").is_none() {
        command.env("WASI_SDK_PATH", sdk);
    }
    if std::env::var_os("CC_wasm32_wasip1").is_none() {
        command.env("CC_wasm32_wasip1", sdk.join("bin/clang"));
    }
    if std::env::var_os("AR_wasm32_wasip1").is_none() {
        command.env("AR_wasm32_wasip1", sdk.join("bin/llvm-ar"));
    }
}
