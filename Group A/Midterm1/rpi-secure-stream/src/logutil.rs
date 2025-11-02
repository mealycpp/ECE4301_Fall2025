use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn append_csv(path: &str, line: &str) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        if let Err(e) = writeln!(f, "{line}") {
            eprintln!("[logutil] write {path} failed: {e}");
        } else {
            //eprintln!("[logutil] wrote line to {path}");
        }
    } else {
        eprintln!("[logutil] open {path} failed");
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
