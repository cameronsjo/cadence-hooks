//! No bare `println!`/`print!` in shipped source (cadence-hooks#980).
//!
//! On Windows a write to a closed stdout pipe surfaces as
//! `ErrorKind::BrokenPipe`, and `println!` turns that into a panic that the
//! panic hook then records as a false `"reason":"panic"` failopen row. Every
//! stdout write therefore goes through `cadence_hooks_core::stdout`
//! (`out!`/`outln!`), which owns the `BrokenPipe` decision. This test keeps the
//! list closed: a new bare `println!`/`print!` in non-test source fails here.
//!
//! Scope: `src/**` and `crates/*/src/**`. Skipped: comment lines, and
//! everything from the first `#[cfg(test)]` module to end of file (test
//! modules sit at the bottom of each file in this workspace). `tests/` is not
//! scanned. `eprintln!`/`eprint!` are stderr and out of scope.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `line` contains a bare `print!`/`println!` (not `eprint*`, not a
/// longer identifier ending in `print`, e.g. `sprint!`).
fn has_bare_print(line: &str) -> bool {
    for needle in ["println!", "print!"] {
        let mut from = 0;
        while let Some(i) = line[from..].find(needle) {
            let at = from + i;
            let prev = line[..at].chars().next_back();
            if !prev.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                return true;
            }
            from = at + needle.len();
        }
    }
    false
}

/// `path:line` of each bare print in `source`'s non-test region.
fn offenders(label: &str, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let cut = (0..lines.len())
        .find(|&i| {
            lines[i].trim() == "#[cfg(test)]"
                && lines
                    .get(i + 1)
                    .is_some_and(|n| n.trim_start().starts_with("mod "))
        })
        .unwrap_or(lines.len());
    lines[..cut]
        .iter()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//") && has_bare_print(l))
        .map(|(i, l)| format!("{label}:{}: {}", i + 1, l.trim()))
        .collect()
}

#[test]
fn detector_flags_bare_prints_and_spares_the_rest() {
    for (src, want) in [
        ("    println!(\"x\");", 1),
        ("print!(\"x\");", 1),
        ("x; println!()", 1),
        ("eprintln!(\"x\");", 0),
        ("eprint!(\"x\");", 0),
        ("// println!(\"x\")", 0),
        ("/// print!(\"x\")", 0),
        ("outln!(\"x\");", 0),
        ("#[cfg(test)]\nmod tests {\n println!(\"x\");\n}", 0),
        ("fn a() { println!(\"x\"); }\n#[cfg(test)]\nmod tests {}", 1),
    ] {
        assert_eq!(offenders("t.rs", src).len(), want, "{src}");
    }
}

#[test]
fn no_bare_println_in_shipped_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    if let Ok(crates) = fs::read_dir(root.join("crates")) {
        for c in crates.flatten() {
            rust_files(&c.path().join("src"), &mut files);
        }
    }
    assert!(
        files.len() > 20,
        "scanned suspiciously few files: {}",
        files.len()
    );
    let mut bad = Vec::new();
    for f in &files {
        let Ok(src) = fs::read_to_string(f) else {
            continue;
        };
        let label = f.strip_prefix(root).unwrap_or(f).display().to_string();
        bad.extend(offenders(&label, &src));
    }
    assert!(
        bad.is_empty(),
        "bare println!/print! in shipped source; use cadence_hooks_core::outln!/out! \
         (BrokenPipe-aware, cadence-hooks#980):\n{}",
        bad.join("\n")
    );
}
