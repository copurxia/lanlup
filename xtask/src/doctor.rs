use crate::env;
use anyhow::Result;
use std::path::Path;
use std::process::{Command, ExitCode};

/// Report toolchain and environment status.
/// Exit code: 0 when cargo/rustc/wasm32-wasip1 are usable, 2 otherwise.
pub fn run() -> Result<ExitCode> {
    println!("xtask doctor");
    println!("------------");

    let mut critical_ok = true;

    critical_ok &= report_version("cargo", &["--version"]);
    critical_ok &= report_version("rustc", &["--version"]);

    let target_ok = has_wasm_target();
    report(
        "wasm32-wasip1 target",
        target_ok,
        Some("rustup target add wasm32-wasip1"),
    );
    critical_ok &= target_ok;

    let node = command_first_line("node", &["--version"]);
    report(
        "node (release manifest only)",
        node.is_some(),
        Some("install Node.js 20+ (used by release aggregate / scripts)"),
    );
    if let Some(version) = &node {
        println!("      version: {version}");
    }

    let wasi_sdk = env::find_wasi_sdk();
    report(
        "wasi-sdk (ring-based crates only)",
        wasi_sdk.is_some(),
        Some("download wasi-sdk-34, extract to /opt/wasi-sdk-34.0 and/or set WASI_SDK_PATH"),
    );
    if let Some(path) = &wasi_sdk {
        println!("      path: {}", path.display());
    }

    println!();
    if critical_ok {
        println!("doctor: core toolchain OK");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("doctor: required tooling missing (exit 2)");
        Ok(ExitCode::from(2))
    }
}

fn report_version(command: &str, args: &[&str]) -> bool {
    match command_first_line(command, args) {
        Some(version) => {
            println!("[ok]      {command}: {version}");
            true
        }
        None => {
            println!("[missing] {command}");
            false
        }
    }
}

fn report(label: &str, ok: bool, hint: Option<&str>) {
    if ok {
        println!("[ok]      {label}");
    } else {
        println!("[missing] {label}");
        if let Some(hint) = hint {
            println!("          hint: {hint}");
        }
    }
}

fn command_first_line(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn has_wasm_target() -> bool {
    if let Ok(output) = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == "wasm32-wasip1")
        {
            return true;
        }
    }
    // Fallback for toolchains installed without rustup.
    if let Ok(output) = Command::new("rustc").args(["--print", "sysroot"]).output() {
        if output.status.success() {
            let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Path::new(&sysroot)
                .join("lib/rustlib/wasm32-wasip1")
                .is_dir();
        }
    }
    false
}
