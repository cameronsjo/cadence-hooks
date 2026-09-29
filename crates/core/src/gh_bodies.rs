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
    extract_bodies_sourced(segment, base_dir)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

/// Where one extracted body came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySource {
    /// A command-line word, as [`tokenize`] returns it: quotes removed, but an
    /// unquoted backslash still in place (`zorbl\axcorp`), where the shell
    /// removes it before the program ever sees the value.
    Word,
    /// A file's contents, read from disk: the bytes are posted as they are, so
    /// no shell quote removal applies to them.
    File,
}

/// [`extract_bodies`], with each body tagged by where it came from. A caller
/// that must read a literal value the way the shell passes it (a backslash
/// removed) needs to know which bodies are words, since doing the same to a
/// file's contents would scan text nobody posts.
pub fn extract_bodies_sourced(segment: &str, base_dir: &str) -> Vec<(String, BodySource)> {
    let tokens = tokenize(segment);
    let mut bodies = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        // Separate-token literal body flags.
        if matches!(tok, "--body" | "-b" | "-m" | "--message")
            && let Some(v) = tokens.get(i + 1)
        {
            bodies.push((v.clone(), BodySource::Word));
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
                bodies.push((content, BodySource::File));
            }
            i += 2;
            continue;
        }
        // `=`-joined long forms.
        if let Some(v) = tok
            .strip_prefix("--body=")
            .or_else(|| tok.strip_prefix("--message="))
        {
            bodies.push((v.to_string(), BodySource::Word));
            i += 1;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--body-file=") {
            if let Ok(content) = read_body_file(p, base_dir) {
                bodies.push((content, BodySource::File));
            }
            i += 1;
            continue;
        }
        // Glued short forms: `-mMSG`, `-bBODY` (literal), `-FPATH` (file).
        if !tok.starts_with("--") && tok.len() > 2 {
            if let Some(v) = tok.strip_prefix("-m").or_else(|| tok.strip_prefix("-b")) {
                bodies.push((v.to_string(), BodySource::Word));
                i += 1;
                continue;
            }
            if let Some(p) = tok.strip_prefix("-F") {
                if let Ok(content) = read_body_file(p, base_dir) {
                    bodies.push((content, BodySource::File));
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
/// or glued `-t<v>`. The LAST occurrence wins, matching `gh`: it parses flags
/// with pflag/Cobra, where a repeated string flag keeps the last value. Taking
/// the first made the 72-character cap evadable (`--title short --title <long>`
/// passed) and could report a title `gh` never posts — the same last-wins rule
/// `last_body_flag` already applies to `--body`.
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
    let mut found: Option<String> = None;
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if matches!(tok, "--title" | "-t") {
            if let Some(v) = tokens.get(i + 1) {
                found = Some(v.clone());
                i += 2;
                continue;
            }
            // A bare trailing flag has no value; leave the previous one.
            break;
        }
        if let Some(v) = tok.strip_prefix("--title=") {
            found = Some(v.to_string());
            i += 1;
            continue;
        }
        // Glued short form `-tTITLE`. `--title` is excluded by the `--` guard;
        // a bare `-t` is excluded by the length guard.
        if !tok.starts_with("--")
            && tok.len() > 2
            && let Some(v) = tok.strip_prefix("-t")
        {
            found = Some(v.to_string());
            i += 1;
            continue;
        }
        // Another flag's value is data, not a flag.
        if VALUE_FLAGS.contains(&tok) {
            i += 2;
            continue;
        }
        i += 1;
    }
    found
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

/// Every value of one flag in ONE segment's tokens, in argument order: the
/// separate (`--desc x`, `-d x`), `=`-joined long (`--desc=x`) and glued short
/// (`-dx`) spellings. ALL occurrences, not the last — a scanner reading more
/// than `gh` posts errs toward seeing, which is the direction a leak guard
/// wants. Pure.
pub fn flag_values(tokens: &[String], long: &str, short: Option<char>) -> Vec<String> {
    let short = short.map(|c| format!("-{c}"));
    let joined = format!("{long}=");
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "--" {
            break;
        }
        if tok == long || short.as_deref() == Some(tok) {
            if let Some(v) = tokens.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
            continue;
        }
        if let Some(v) = tok.strip_prefix(joined.as_str()) {
            out.push(v.to_string());
        } else if let Some(s) = short.as_deref()
            && !tok.starts_with("--")
            && tok.len() > 2
            && let Some(v) = tok.strip_prefix(s)
        {
            out.push(v.to_string());
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// `gh api` request bodies (cadence-hooks#930)
// ---------------------------------------------------------------------------

/// Where a `gh api` request's `body` (or `title`) field comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiField {
    /// `-f body=TEXT`, or `-F body=TEXT` without an `@`: the text itself.
    Literal(String),
    /// `-F body=@PATH`: gh reads the field's value from the file.
    File(String),
    /// `-F body=@-`, or `--input -`: gh reads standard input, which the hook
    /// cannot see.
    Stdin,
}

/// The parts of ONE `gh api` invocation a body reader needs. Pure: no file is
/// opened building it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiRequest {
    /// The endpoint positional, as written (`repos/o/r/issues`, `/repos/…`).
    pub endpoint: String,
    /// The LAST `-X`/`--method` value, uppercased; `None` when absent.
    pub method: Option<String>,
    /// Whether any `-f`/`-F` field was passed.
    pub has_fields: bool,
    /// The LAST `body` field — gh keeps the last value for a repeated key.
    pub body: Option<ApiField>,
    /// The LAST `title` field.
    pub title: Option<ApiField>,
    /// EVERY `-f`/`-F` field in argument order, keys included — `name`,
    /// `description`, `message`, nested `labels[]`, graphql `query` and its
    /// variables. A scanner reads all of them; [`Self::body`] and
    /// [`Self::title`] are the last-wins views a size budget needs.
    pub fields: Vec<(String, ApiField)>,
    /// The `--input` source, when given. gh sends that file as the request
    /// body and turns every field into a query parameter instead.
    pub input: Option<ApiField>,
}

impl ApiRequest {
    /// The method gh will send: the explicit one, else POST once any field or
    /// `--input` is present, else GET (gh's own implicit rule).
    pub fn effective_method(&self) -> String {
        match &self.method {
            Some(m) => m.clone(),
            None if self.has_fields || self.input.is_some() => "POST".to_string(),
            None => "GET".to_string(),
        }
    }

    /// Does this request carry a payload? A literal `GET` or `HEAD` sends its
    /// fields as a query string, so it posts nothing. Any other method —
    /// including one the hook cannot read literally (`-X "$M"`) — is taken to
    /// post, which is the see-more direction for a reader.
    pub fn sends_payload(&self) -> bool {
        !matches!(self.effective_method().as_str(), "GET" | "HEAD")
    }

    /// The endpoint with any scheme/host, `api/v3/` prefix, leading slash and
    /// query string removed: `https://ghe.x/api/v3/repos/o/r/issues?a=b` →
    /// `repos/o/r/issues`.
    pub fn endpoint_path(&self) -> &str {
        let mut e = self.endpoint.as_str();
        if let Some(rest) = e
            .strip_prefix("https://")
            .or_else(|| e.strip_prefix("http://"))
        {
            e = rest.split_once('/').map_or("", |(_, path)| path);
        }
        e = e.trim_start_matches('/');
        e = e.strip_prefix("api/v3/").unwrap_or(e);
        e.split(['?', '#']).next().unwrap_or(e)
    }
}

/// `gh api` flags whose value is the following token (or `=`-joined, or glued
/// to the short form).
const API_VALUE_FLAGS: &[(&str, Option<char>)] = &[
    ("--method", Some('X')),
    ("--field", Some('F')),
    ("--raw-field", Some('f')),
    ("--header", Some('H')),
    ("--jq", Some('q')),
    ("--template", Some('t')),
    ("--preview", Some('p')),
    ("--input", None),
    ("--hostname", None),
    ("--cache", None),
];

/// Parse a `key=value` field into (key, source). `typed` is `-F`/`--field`,
/// where a value starting with `@` names a file (`@-` is stdin); `-f` values
/// are always literal.
fn api_field(raw: &str, typed: bool) -> Option<(&str, ApiField)> {
    let (key, value) = raw.split_once('=')?;
    let field = match value.strip_prefix('@') {
        Some("-") if typed => ApiField::Stdin,
        Some(path) if typed => ApiField::File(path.to_string()),
        _ => ApiField::Literal(value.to_string()),
    };
    Some((key, field))
}

/// Read a `gh api` invocation. `argv` is the command's argv with `gh` at index
/// 0 (transparent prefixes already peeled); `None` when the command word is not
/// `gh` or the first non-flag word after it is not `api`.
///
/// Every flag spelling pflag accepts is read — separate (`-f body=x`),
/// `=`-joined long (`--raw-field=body=x`) and glued short (`-fbody=x`,
/// `-XPATCH`). Repeated keys keep the last value, as gh does.
pub fn parse_gh_api(argv: &[String]) -> Option<ApiRequest> {
    if crate::shell::command_word(argv.first()?).as_ref() != "gh" {
        return None;
    }
    let mut i = 1;
    while i < argv.len() && argv[i].starts_with('-') {
        i += 1;
    }
    // The shell drops an unquoted word's backslashes, so `a\pi` runs `api`.
    if argv
        .get(i)
        .map(|w| crate::shell::unescape_word(w))
        .as_deref()
        != Some("api")
    {
        return None;
    }
    i += 1;
    let mut req = ApiRequest::default();
    let mut endpoint: Option<String> = None;
    while i < argv.len() {
        let tok = argv[i].as_str();
        // Resolve (long name, value, tokens consumed) for a value flag.
        let mut hit: Option<(&str, &str, usize)> = None;
        if tok == "--" {
            if endpoint.is_none() {
                endpoint = argv.get(i + 1).cloned();
            }
            break;
        }
        for (long, short) in API_VALUE_FLAGS {
            let short_s = short.map(|c| format!("-{c}"));
            if tok == *long || short_s.as_deref() == Some(tok) {
                if let Some(v) = argv.get(i + 1) {
                    hit = Some((long, v.as_str(), 2));
                } else {
                    hit = Some((long, "", 1));
                }
                break;
            }
            if let Some(v) = tok
                .strip_prefix(long)
                .and_then(|rest| rest.strip_prefix('='))
            {
                hit = Some((long, v, 1));
                break;
            }
            if let Some(s) = short_s.as_deref()
                && !tok.starts_with("--")
                && tok.len() > 2
                && let Some(v) = tok.strip_prefix(s)
            {
                hit = Some((long, v, 1));
                break;
            }
        }
        match hit {
            Some((long, value, used)) => {
                match long {
                    "--method" => req.method = Some(value.to_ascii_uppercase()),
                    "--field" | "--raw-field" => {
                        req.has_fields = true;
                        if let Some((key, field)) = api_field(value, long == "--field") {
                            match key {
                                "body" => req.body = Some(field.clone()),
                                "title" => req.title = Some(field.clone()),
                                _ => {}
                            }
                            req.fields.push((key.to_string(), field));
                        }
                    }
                    "--input" => {
                        req.input = Some(if value == "-" {
                            ApiField::Stdin
                        } else {
                            ApiField::File(value.to_string())
                        });
                    }
                    _ => {}
                }
                i += used;
            }
            None => {
                if !tok.starts_with('-') && endpoint.is_none() {
                    endpoint = Some(tok.to_string());
                }
                i += 1;
            }
        }
    }
    req.endpoint = endpoint.unwrap_or_default();
    Some(req)
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
            // LAST occurrence wins, as pflag does.
            ("gh pr create --title First --title Second", Some("Second")),
            ("gh pr create --title First --title=Second", Some("Second")),
            ("gh pr create -t First -tSecond", Some("Second")),
            // A trailing bare `--title` has no value and does not erase the
            // one already found.
            ("gh pr create --title Real --title", Some("Real")),
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

    #[test]
    fn extract_title_takes_the_last_repeat_so_the_cap_cannot_be_evaded() {
        // The reviewer's probe: a short title first, the real one second. With
        // first-wins the long title was never seen and the 72-char cap was
        // evadable by adding a decoy.
        let long = "t".repeat(84);
        let cmd = format!("gh pr create --title short --title \"{long}\" --body hi");
        assert_eq!(extract_title(&cmd).as_deref(), Some(long.as_str()));
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

    #[cfg(unix)]
    #[test]
    fn read_body_file_a_fifo_is_not_regular_not_unreadable() {
        // cadence-hooks#930 security review, Important 2: a FIFO and a
        // `/dev/fd/N` process substitution both feed `gh` fine, so a caller has
        // to tell them from a missing path. The `stat` check runs before any
        // open, so nothing here can block on the empty FIFO.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe.md");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo should run");
        assert!(status.success(), "mkfifo failed");
        assert_eq!(
            read_body_file(path.to_str().unwrap(), "."),
            Err(BodyFileError::NotRegular)
        );
    }

    #[test]
    fn read_body_file_a_directory_is_not_regular() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_body_file(dir.path().to_str().unwrap(), "."),
            Err(BodyFileError::NotRegular)
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

    #[test]
    fn extract_bodies_sourced_tags_words_and_files() {
        // A word keeps its unquoted backslash (the caller decides how to read
        // it); a file's contents are tagged so no caller unescapes them.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.md"), "file \\text").unwrap();
        let base = dir.path().to_str().unwrap();
        let cases: &[(&str, Vec<(&str, BodySource)>)] = &[
            (
                r"gh pr comment 3 --body a\b",
                vec![(r"a\b", BodySource::Word)],
            ),
            (
                r"gh pr comment 3 --body=a\b",
                vec![(r"a\b", BodySource::Word)],
            ),
            (r"git commit -ma\b", vec![(r"a\b", BodySource::Word)]),
            (
                "gh pr comment 3 --body-file b.md",
                vec![(r"file \text", BodySource::File)],
            ),
            (
                "git commit -Fb.md -m x",
                vec![(r"file \text", BodySource::File), ("x", BodySource::Word)],
            ),
        ];
        for (cmd, want) in cases {
            let got = extract_bodies_sourced(cmd, base);
            let want: Vec<(String, BodySource)> =
                want.iter().map(|(t, s)| (t.to_string(), *s)).collect();
            assert_eq!(got, want, "{cmd}");
        }
    }

    // ---- parse_gh_api (cadence-hooks#930) ----

    fn argv(s: &str) -> Vec<String> {
        tokenize(s)
    }

    #[test]
    fn parse_gh_api_reads_every_field_spelling() {
        use ApiField::*;
        let cases: &[(&str, Option<ApiField>)] = &[
            (
                "gh api repos/o/r/issues -f body=hi",
                Some(Literal("hi".into())),
            ),
            (
                "gh api repos/o/r/issues -fbody=hi",
                Some(Literal("hi".into())),
            ),
            (
                "gh api repos/o/r/issues --raw-field body=hi",
                Some(Literal("hi".into())),
            ),
            (
                "gh api repos/o/r/issues --raw-field=body=hi",
                Some(Literal("hi".into())),
            ),
            (
                "gh api repos/o/r/issues -F body=hi",
                Some(Literal("hi".into())),
            ),
            (
                "gh api repos/o/r/issues --field=body=@b.md",
                Some(File("b.md".into())),
            ),
            (
                "gh api repos/o/r/issues -Fbody=@b.md",
                Some(File("b.md".into())),
            ),
            ("gh api repos/o/r/issues -F body=@-", Some(Stdin)),
            // A raw field never reads a file: `@` is literal text.
            (
                "gh api repos/o/r/issues -f body=@b.md",
                Some(Literal("@b.md".into())),
            ),
            // gh keeps the last value for a repeated key.
            (
                "gh api repos/o/r/issues -f body=a -f body=b",
                Some(Literal("b".into())),
            ),
            // Another key is not the body; a flag's VALUE is not a field.
            ("gh api repos/o/r/issues -f labels=x", None),
            ("gh api repos/o/r/issues -H body=x", None),
        ];
        for (cmd, want) in cases {
            let req = parse_gh_api(&argv(cmd)).expect(cmd);
            assert_eq!(&req.body, want, "{cmd}");
            assert_eq!(req.endpoint, "repos/o/r/issues", "{cmd}");
        }
    }

    #[test]
    fn parse_gh_api_method_input_and_non_api() {
        let req = parse_gh_api(&argv("gh api -XPATCH /repos/o/r/pulls/1 --input p.json")).unwrap();
        assert_eq!(req.method.as_deref(), Some("PATCH"));
        assert_eq!(req.input, Some(ApiField::File("p.json".into())));
        assert_eq!(req.endpoint_path(), "repos/o/r/pulls/1");
        assert!(req.sends_payload());

        let implicit = parse_gh_api(&argv("gh api repos/o/r/issues -f body=x")).unwrap();
        assert_eq!(implicit.effective_method(), "POST");
        let get = parse_gh_api(&argv("gh api -X get repos/o/r/issues -f body=x")).unwrap();
        assert!(!get.sends_payload(), "a GET sends fields as a query string");
        let bare = parse_gh_api(&argv("gh api repos/o/r/issues")).unwrap();
        assert!(!bare.sends_payload());

        let url = parse_gh_api(&argv(
            "gh api https://ghe.example/api/v3/repos/o/r/issues?x=1 -f body=x",
        ))
        .unwrap();
        assert_eq!(url.endpoint_path(), "repos/o/r/issues");

        for not_api in ["gh pr create --body x", "gh repo view api", "echo api"] {
            assert_eq!(parse_gh_api(&argv(not_api)), None, "{not_api}");
        }
    }

    #[test]
    fn parse_gh_api_keeps_every_field_in_order() {
        use ApiField::*;
        let req = parse_gh_api(&argv(
            "gh a\\pi repos/o/r/labels -f name=n --field=description=@d.md -Fcolor=@- -H x=y",
        ))
        .expect("an escaped `api` is `api`");
        assert_eq!(
            req.fields,
            vec![
                ("name".to_string(), Literal("n".into())),
                ("description".to_string(), File("d.md".into())),
                ("color".to_string(), Stdin),
            ]
        );
    }

    #[test]
    fn flag_values_reads_every_spelling_and_occurrence() {
        let cases: &[(&str, &[&str])] = &[
            ("gh gist create -d a f", &["a"]),
            ("gh gist create -da f", &["a"]),
            ("gh gist create --desc a f", &["a"]),
            ("gh gist create --desc=a f", &["a"]),
            ("gh gist create -d a --desc b", &["a", "b"]),
            ("gh gist create --descx a", &[]),
            ("gh gist create -- --desc a", &[]),
            ("gh gist create -d", &[]),
        ];
        for (cmd, want) in cases {
            assert_eq!(flag_values(&argv(cmd), "--desc", Some('d')), *want, "{cmd}");
        }
    }
}
