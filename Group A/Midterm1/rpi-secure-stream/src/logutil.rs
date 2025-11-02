use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Append a CSV line safely (auto-creates directory)
pub fn append_csv(path: &str, line: &str) {
    if let Some(parent) = Path::new(path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("[logutil] mkdir failed: {e}");
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        if let Err(e) = writeln!(f, "{line}") {
            eprintln!("[logutil] write failed: {e}");
        }
    }
}
