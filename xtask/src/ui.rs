use anyhow::Result;
use std::io::Write;

/// Write one line to stdout, tolerating a closed pipe (`xtask list | head`).
/// Returns `Ok(false)` when the reader went away so callers can stop early.
pub fn print_line(args: std::fmt::Arguments<'_>) -> Result<bool> {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_fmt(format_args!("{args}\n")) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err.into()),
    }
}
