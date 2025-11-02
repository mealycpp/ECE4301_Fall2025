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

pub fn append_csv_with_header(path: &str, header: &str, line: &str) {
    use std::fs::{self, OpenOptions};
    use std::io::{Write, Read};
    use std::path::Path;

    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut need_header = true;
    if let Ok(mut f) = OpenOptions::new().read(true).open(path) {
        let mut buf = String::new();
        if f.read_to_string(&mut buf).is_ok() && buf.contains(header) { need_header = false; }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        if need_header {
            let _ = writeln!(f, "{header}");
        }
        let _ = writeln!(f, "{line}");
    }
}
