//! Extraction of `gh`/`git` body and title flag values from a command segment.
//!
//! Shared by every guard that has to look at what a posting command is about to
//! send: the redaction scanner reads bodies for blocklist hits, the body-budget
//! guard measures their size. Both need the same answer to "what text does this
//! command post?", and a second copy of this flag table would drift from the
//! first the moment `gh` grows a spelling.
//!
//! Callers must gate the segment themselves — a file-body flag is *read* here,
//! so handing this a non-posting segment performs I/O the guard has no business
//! doing (cadence-hooks#424).

use crate::shell::tokenize;
use std::path::Path;

/// Why a `--body-file` read yielded no text.
///
/// Reading is capped and regular-file-only, so "no text" has three distinct
/// causes and a caller that only nudges on oversize needs to tell them apart.
/// Re-exported from [`crate::paths`] so the cap discipline and the error
/// vocabulary stay one thing.
pub use crate::paths::CappedReadError as BodyFileError;

/// Flags whose value is a separate token that must never be read as another
/// flag. Skipping their value keeps a body like `--body --title` from
/// donating a title.
const VALUE_FLAGS: &[&str] = &[
    "--body",
    "-b",
    "-m",
    "--message",
    "--body-file",
    "-F",
    "--title",
    "-t",
];

/// Extract body text from the flag values of ONE gate-passing segment. Callers
/// must apply their own posting gate to the segment first — a file-body flag
/// is read here, so handing this a non-posting segment performs I/O the guard
/// has no business doing (#424).
///
/// Literal-body flags (`--body`/`-b`/`-m`/`--message`, plus their `=`-joined and
/// glued-short forms) contribute their value verbatim. File-body flags
/// (`--body-file`/`-F`) contribute the file's contents read from disk; an
/// unreadable path is silently skipped (fail-open). `tokenize` keeps a quoted
/// value as one token, so a heredoc inside `"$(cat <<EOF … EOF)"` rides into the
/// value intact. `--title`/`-t` is deliberately out of scope here (bodies only);
/// [`extract_title`] handles it separately.
pub fn extract_bodies(segment: &str, base_dir: &str) -> Vec<String> {
    let tokens = tokenize(segment);
    let mut bodies = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        // Separate-token literal body flags.
        if matches!(tok, "--body" | "-b" | "-m" | "--message")
            && let Some(v) = tokens.get(i + 1)
        {
            bodies.push(v.clone());
            i += 2;
            continue;
        }
        // Separate-token file-body flags (value is a path → read it). The flag
        // consumes two tokens whether or not the file reads, so the i-advance
        // stays outside the read-success branch.
        if matches!(tok, "--body-file" | "-F")
            && let Some(p) = tokens.get(i + 1)
        {
            if let Ok(content) = read_body_file(p, base_dir) {
                bodies.push(content);
            }
            i += 2;
            continue;
        }
        // `=`-joined long forms.
        if let Some(v) = tok
            .strip_prefix("--body=")
            .or_else(|| tok.strip_prefix("--message="))
        {
            bodies.push(v.to_string());
            i += 1;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--body-file=") {
            if let Ok(content) = read_body_file(p, base_dir) {
                bodies.push(content);
            }
            i += 1;
            continue;
        }
        // Glued short forms: `-mMSG`, `-bBODY` (literal), `-FPATH` (file).
        if !tok.starts_with("--") && tok.len() > 2 {
            if let Some(v) = tok.strip_prefix("-m").or_else(|| tok.strip_prefix("-b")) {
                bodies.push(v.to_string());
                i += 1;
                continue;
            }
            if let Some(p) = tok.strip_prefix("-F") {
                if let Ok(content) = read_body_file(p, base_dir) {
                    bodies.push(content);
                }
                i += 1;
                continue;
            }
        }
        i += 1;
    }
    bodies
}

/// Extract the title from ONE segment: `--title <v>`, `--title=<v>`, `-t <v>`,
/// or glued `-t<v>`. First occurrence wins, matching `gh`, which takes the
/// first of a repeated flag.
///
/// Pure — no I/O, because no title flag names a file.
///
/// A `--title` sitting inside a quoted body value cannot donate a title:
/// [`tokenize`] keeps a quoted string as ONE token, so `--body "use --title
/// later"` yields a token whose text is `use --title later` and never a bare
/// `--title`. The [`VALUE_FLAGS`] skip covers the remaining shape, an unquoted
/// flag-looking word passed as another flag's value (`--body --title`).
pub fn extract_title(segment: &str) -> Option<String> {
    let tokens = tokenize(segment);
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if matches!(tok, "--title" | "-t") {
            return tokens.get(i + 1).cloned();
        }
        if let Some(v) = tok.strip_prefix("--title=") {
            return Some(v.to_string());
        }
        // Glued short form `-tTITLE`. `--title` is excluded by the `--` guard;
        // a bare `-t` is excluded by the length guard.
        if !tok.starts_with("--")
            && tok.len() > 2
            && let Some(v) = tok.strip_prefix("-t")
        {
            return Some(v.to_string());
        }
        // Another flag's value is data, not a flag.
        if VALUE_FLAGS.contains(&tok) {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

/// Read a `--body-file` value from disk, resolving a relative path against
/// `base_dir`. Errors carry why (see [`BodyFileError`]) so a caller can tell an
/// oversized body from a missing one; a fail-open caller maps every error to
/// skip with `.ok()`.
///
/// #194: shares the #157 unbounded-read DoS shape — a symlink to an endless
/// special file (`/dev/zero`, a FIFO) or a multi-GB file could hang or OOM the
/// hook — so this routes through the same bounded, regular-file-only reader.
pub fn read_body_file(path: &str, base_dir: &str) -> Result<String, BodyFileError> {
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(base_dir).join(p)
    };
    crate::paths::read_untrusted_config_detailed(&full)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_title: the four spellings, plus the two ways it must not fire

    #[test]
    fn extract_title_forms() {
        let cases: &[(&str, Option<&str>)] = &[
            // The four accepted spellings.
            ("gh pr create --title Real", Some("Real")),
            ("gh pr create --title=Real", Some("Real")),
            ("gh pr create -t Real", Some("Real")),
            ("gh pr create -tReal", Some("Real")),
            // No title flag at all.
            ("gh pr create --body hello", None),
            // A `--title` inside a quoted body value is one token, not a flag.
            (
                "gh pr create --body \"use --title later\" --title Real",
                Some("Real"),
            ),
            ("gh pr create --body \"--title fake\"", None),
            // First occurrence wins.
            ("gh pr create --title First --title Second", Some("First")),
            // An unquoted flag-looking word is still another flag's value.
            ("gh pr create --body --title", None),
            // A bare trailing flag has no value.
            ("gh pr create --title", None),
            // Quoted multi-word titles survive intact.
            (
                "gh pr create --title \"a real title\"",
                Some("a real title"),
            ),
        ];
        for (cmd, want) in cases {
            assert_eq!(
                extract_title(cmd).as_deref(),
                *want,
                "extract_title({cmd:?})"
            );
        }
    }

    // --- read_body_file: each error variant is distinguishable

    #[test]
    fn read_body_file_reads_a_normal_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "hello").unwrap();
        assert_eq!(
            read_body_file(path.to_str().unwrap(), "."),
            Ok("hello".to_string())
        );
    }

    #[test]
    fn read_body_file_resolves_a_relative_path_against_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("body.md"), "hello").unwrap();
        assert_eq!(
            read_body_file("body.md", dir.path().to_str().unwrap()),
            Ok("hello".to_string())
        );
    }

    #[test]
    fn read_body_file_missing_path_is_unreadable() {
        assert_eq!(
            read_body_file("/nonexistent/path/body.md", "."),
            Err(BodyFileError::Unreadable)
        );
    }

    #[test]
    fn read_body_file_one_byte_over_the_cap_is_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.md");
        std::fs::write(
            &path,
            vec![b'x'; (crate::paths::MAX_UNTRUSTED_CONFIG_BYTES as usize) + 1],
        )
        .unwrap();
        assert_eq!(
            read_body_file(path.to_str().unwrap(), "."),
            Err(BodyFileError::OverCap)
        );
    }

    #[test]
    fn read_body_file_exactly_at_the_cap_still_reads() {
        // The discriminating control for the test above: one byte less must
        // read, or `OverCap` could be coming from anything.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("atcap.md");
        let want = vec![b'x'; crate::paths::MAX_UNTRUSTED_CONFIG_BYTES as usize];
        std::fs::write(&path, &want).unwrap();
        assert_eq!(
            read_body_file(path.to_str().unwrap(), ".").map(|s| s.len()),
            Ok(want.len())
        );
    }

    #[test]
    fn read_body_file_invalid_utf8_is_not_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bytes.md");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert_eq!(
            read_body_file(path.to_str().unwrap(), "."),
            Err(BodyFileError::NotUtf8)
        );
    }

    // --- extract_bodies: the move preserved behavior

    #[test]
    fn extract_bodies_covers_every_literal_spelling() {
        for cmd in [
            "gh pr create --body hi",
            "gh pr create --body=hi",
            "gh pr comment 1 -b hi",
            "git commit -m hi",
            "git commit --message hi",
            "git commit --message=hi",
            "git commit -mhi",
            "gh pr comment 1 -bhi",
        ] {
            assert_eq!(extract_bodies(cmd, "."), vec!["hi".to_string()], "{cmd:?}");
        }
    }

    #[test]
    fn extract_bodies_reads_file_flags_and_skips_an_unreadable_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "from disk").unwrap();
        let p = path.to_str().unwrap();
        for cmd in [
            format!("gh pr create --body-file {p}"),
            format!("gh pr create --body-file={p}"),
            format!("git commit -F {p}"),
            format!("git commit -F{p}"),
        ] {
            assert_eq!(
                extract_bodies(&cmd, "."),
                vec!["from disk".to_string()],
                "{cmd:?}"
            );
        }
        assert!(
            extract_bodies("gh pr create --body-file /nonexistent/body.md", ".").is_empty(),
            "an unreadable body file contributes nothing"
        );
    }

    #[test]
    fn extract_bodies_collects_every_body_in_order() {
        assert_eq!(
            extract_bodies("git commit -m one -m two", "."),
            vec!["one".to_string(), "two".to_string()]
        );
    }
}
