use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Append a CSV line. Creates parent dirs if needed.
/// Best-effort: prints an error to stderr if something goes wrong.
pub fn append_csv(path: &str, line: &str) {
    if let Some(parent) = Path::new(path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("[logutil] mkdir {} failed: {e}", parent.display());
        }
    }
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("[logutil] write {} failed: {e}", path);
            }
        }
        Err(e) => eprintln!("[logutil] open {} failed: {e}", path),
    }
}
