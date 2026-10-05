//! Mask secret values in Bash output before they reach the model and the
//! transcript (cameronsjo/cadence-hooks#776). PostToolUse, `Bash` only.
//!
//! **The incidents.** Legitimate commands printed live secrets as collateral:
//! `sops -d … | grep -A3 unifi` (the operator wanted to know a key existed),
//! and `docker inspect <c> --format '{{range .Config.Env}}{{println .}}{{end}}'
//! | grep -i HOMEPAGE` (one non-secret config value was wanted; a secret one
//! rode along). Once a value is in the transcript it is in the JSONL on disk
//! and every compaction summary.
//!
//! **Mechanism.** The hook returns `hookSpecificOutput.updatedToolOutput` with
//! the **full** Bash output object `{stdout, stderr, interrupted, isImage}`.
//! Probed on Claude Code 2.1.285 with a made-up canary: the replacement reaches
//! both the model-facing `tool_result` and the persisted `toolUseResult` in the
//! session JSONL, and the raw output is written nowhere in the session. A
//! wrong shape (or `updatedMCPToolOutput`) is silently ignored and the raw
//! output is used, so the shape here must stay exactly that object.
//!
//! **Policy: name strength decides, not value shape.** A miss leaks a secret
//! that cannot be recalled, so a STRONG name (`password`, `passwd`, `pwd`,
//! `passphrase`, `secret`, `token`, `apikey`/`api_key`, `access_key`,
//! `secret_key`, `private_key`, `credential(s)`, `auth_token`, `cookie`, and the
//! `Authorization`/`Proxy-Authorization`/`X-Api-Key`/`X-Auth-Token` headers)
//! masks ANY value in every form — colon, `=`, quoted, JSON, table row,
//! `.netrc` — except booleans/null, obvious placeholders (`***`, `<redacted>`,
//! `[REDACTED]`, `(sensitive value)`, `gho_****`, `Bearer <token>`) and
//! `$VAR`/`${VAR}` references. The unquoted colon form additionally spares a
//! short closed set of prose words (`password: required`, `token: expired`)
//! and type annotations (`password: String,`, `token: Option<String>`). A WEAK
//! name (`…_key`, `auth`, `db_pass`) needs a credential-shaped value in the
//! prose-shaped forms ([`secret_like`]). A bare `PASS`/`FAIL` is a test
//! runner's status word, and `Token expired` (a name, a space, a word, at the
//! start of a line outside a `.netrc`/vault table) is prose, not a pair. A
//! corpus test holds everyday output (test runners, builds, git over code,
//! listings, error prose) at zero masks.
//!
//! **Views.** Every detector runs on the output with ANSI CSI sequences
//! removed (`grep --color`, coloured logs), and again on windows around each
//! backslash (bounded by the line and 4 KiB either side) with JSON/C escapes
//! decoded (`\n`, `\t`, `\r`, `\"`, `\\`, `\/`), so a key or token inside a
//! JSON string (`kubectl logs`, JSONL, `gh api` bodies, escaped nested JSON) is
//! seen as if printed raw — without re-scanning a whole 5 MB output because
//! one byte of it was a backslash. Each span maps back to the original bytes
//! and ends after the original char its last byte came from, so a colour reset
//! right after a masked value is kept.
//!
//! **What is masked**, each value replaced in place and every other byte kept:
//! 1. **Credential tokens**, by grammar — the shared `credential_scan`
//!    grammar ([`credential_scan::direct_spans`]), with its left-boundary gate
//!    relaxed and JWTs added (see that function).
//! 2. **Private keys**: from any `-----BEGIN … PRIVATE KEY-----` (PEM, OpenSSH,
//!    PGP `PRIVATE KEY BLOCK`) to the next matching `-----END …-----`, or to
//!    the end of the stream when there is none — armor headers, blank lines and
//!    colour codes included. An END with no BEGIN before it in the same stream
//!    (a key split across stdout and stderr, or cut off at the top) masks from
//!    the stream start to that END. stdout and stderr are handled separately.
//! 3. **URL credentials**: the password in any `scheme://user:pass@host`.
//! 4. **Secret-named values** — name-keyed. The value is masked when the NAME
//!    is secret-shaped ([`is_secret_name`], matched by `_`/`-`/`.`/camelCase
//!    segment — not `secret_patterns::is_secret_shaped_var_name`, whose bare
//!    substring match is cheap for a nudge and wrong for a mutation). Forms:
//!    `NAME=value` and `name: value`/`name:value` at a line start (masked to
//!    end of line) or mid-line (to the next whitespace or closing quote), YAML
//!    block scalars (`password: |`), `"name": "value"`/number (JSON, pretty or
//!    minified), `"NAME=value"` in a JSON string (`docker inspect` env arrays),
//!    k8s/ECS `name: X` + `value: V` pairs, `--password=V`/`--token V` flags,
//!    `name    value` table rows (vault `kv get`) and `.netrc` `password V`.
//!    Cookie values are masked whatever the cookie is called (`theme=dark`
//!    included): a session cookie is a credential, and readability loses to
//!    that.
//!
//! **Deliberately left alone:** names whose last segment is metadata
//! (`KEY_ID`, `secretName`, `PASSWORD_FILE`), a bare `key` (key/value
//! listings), `key` qualified as a non-secret (`primary_key`, `public_key`),
//! token counters (`max_tokens`); a bare unnamed value (`security
//! find-generic-password -w`, `kubectl … -o jsonpath`), which is what the
//! PreToolUse `guard-secret-dump` Ask backstop exists for; split token forms.
//!
//! **Output contract.** `updatedToolOutput` is emitted only when something was
//! actually masked — never an identity rewrite, which would race a sibling
//! hook's real rewrite last-write-wins. Image output is never touched. Any
//! doubt about a span (a non-char-boundary offset) abandons the rewrite: the
//! failure mode is "no change", never corrupted output. Every pass is linear in
//! the output size (every 5 MB adversarial shape measured at 0.37 s CPU or
//! less in a release build).
//!
//! **Escape:** `CADENCE_ALLOW_SECRET_OUTPUT` (truthy) passes output through
//! unmasked and records a bypass row, like `CADENCE_ALLOW_SOPS_DECRYPT`. The
//! issue's `dismiss-*` snooze is intentionally not built: a snooze the session
//! itself can arm from Bash would let the model unmask the very values this
//! exists to keep from it; an env switch has to be set by the operator before
//! the session starts.
//!
//! **Residuals — what this hook cannot close:**
//! - **Other tools are not covered.** Output read back through `BashOutput`, a
//!   background task's `Monitor`, or `Read` of a file the command wrote never
//!   passes through this Bash-matcher hook and is not masked.
//! - OpenTelemetry tool spans and analytics events capture the original
//!   output *before* hooks run (Claude Code hooks docs).
//! - A hook failure or timeout leaves the raw output in place (fail open).
//! - The hook itself receives the raw output on stdin (by design).
//! - The compaction path was not probed; the JSONL and model-facing
//!   `tool_result` were. Very large rewrites, and a rewrite carried beside a
//!   `decision: "block"` from a grouped sibling, are unprobed.
//! - A payload Claude Code cannot deliver as valid JSON (a lone surrogate)
//!   fails the parse, and the raw output stands.
//! - A token printed in an encoded form (base64 of a `ghp_…`), and names
//!   spelled with non-ASCII letters (`PASSWÖRD=…`), are not recognized.
//! - Anything the model reconstructs from the command text itself.

use crate::credential_scan::{self, PEM_END_RE, PEM_KIND};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput, ToolResponse};
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

/// The returnable escape: set truthy to see raw output deliberately.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_SECRET_OUTPUT";

/// Replacement for a value masked because of its name.
const NAMED_MARK: &str = "[redacted: secret-named value]";

/// Label for a masked private key.
const KEY_LABEL: &str = "private key";

/// Label for a masked URL password.
const URL_LABEL: &str = "URL password";

/// Longest name the name-keyed rules consider.
const MAX_NAME: usize = 128;

/// How far either side of a backslash the decoded-escape pass looks (bounded
/// by the line). Keeps that second pass proportional to the escaped regions,
/// not to the whole output.
const ESCAPE_WINDOW: usize = 4096;

/// Masks secret values in Bash output via `updatedToolOutput`.
pub struct RedactSecretOutput;

impl Check for RedactSecretOutput {
    fn name(&self) -> &str {
        "redact-secret-output"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if input.tool_name() != Some("Bash") {
            return CheckResult::allow();
        }
        let Some(response) = input.tool_response.as_ref() else {
            return CheckResult::allow();
        };
        let escape = is_truthy(std::env::var(ESCAPE_ENV).ok().as_deref());
        decide(response, escape)
    }
}

/// Pure core of [`RedactSecretOutput::run`]: the rewrite for `response`, or a
/// plain allow when nothing was masked. `escape` is the resolved env switch.
pub fn decide(response: &ToolResponse, escape: bool) -> CheckResult {
    if response.is_image == Some(true) {
        return CheckResult::allow();
    }
    let stdout = response.stdout.as_deref().unwrap_or("");
    let stderr = response.stderr.as_deref().unwrap_or("");
    let new_stdout = redact(stdout);
    let new_stderr = redact(stderr);
    if new_stdout.is_none() && new_stderr.is_none() {
        return CheckResult::allow();
    }
    if escape {
        return CheckResult::allow_bypassed(BypassProvenance::env_switch(ESCAPE_ENV));
    }
    CheckResult::rewrite_output(serde_json::json!({
        "stdout": new_stdout.as_deref().unwrap_or(stdout),
        "stderr": new_stderr.as_deref().unwrap_or(stderr),
        "interrupted": response.interrupted.unwrap_or(false),
        "isImage": false,
    }))
}

/// What a span is masked as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    Named,
    Kind(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    label: Label,
}

fn named(start: usize, end: usize) -> Span {
    Span {
        start,
        end,
        label: Label::Named,
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// A transformed copy of (part of) the output and, per byte of the copy, the
/// original byte it came from. `map: None` is the identity (the common case:
/// no colour codes), so no 8-bytes-per-byte map is built for plain output.
struct View<'a> {
    text: Cow<'a, str>,
    map: Option<Vec<usize>>,
}

impl View<'_> {
    /// Original offset of view byte `i`.
    fn orig(&self, i: usize) -> Option<usize> {
        match &self.map {
            None => Some(i),
            Some(map) => map.get(i).copied(),
        }
    }
}

/// The output with ANSI CSI sequences (`ESC [ params final`) removed.
fn strip_ansi(src: &str) -> View<'_> {
    if !src.contains('\x1b') {
        return View {
            text: Cow::Borrowed(src),
            map: None,
        };
    }
    let bytes = src.as_bytes();
    let mut text = String::with_capacity(src.len());
    let mut map = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < bytes.len() && (0x30..=0x3f).contains(&bytes[j]) {
                j += 1;
            }
            while j < bytes.len() && (0x20..=0x2f).contains(&bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && (0x40..=0x7e).contains(&bytes[j]) {
                i = j + 1;
                continue;
            }
        }
        // Only ASCII bytes are ever skipped, so `i` is a char boundary.
        let Some(c) = src.get(i..).and_then(|rest| rest.chars().next()) else {
            break;
        };
        text.push(c);
        map.extend(std::iter::repeat_n(i, c.len_utf8()));
        i += c.len_utf8();
    }
    View {
        text: Cow::Owned(text),
        map: Some(map),
    }
}

/// `view.text[start..end]` with JSON/C escapes (`\n \r \t \" \\ \/`) decoded,
/// mapped to original offsets.
fn unescape_window(view: &View<'_>, start: usize, end: usize, orig_len: usize) -> View<'static> {
    let slice = &view.text[start..end];
    let mut text = String::with_capacity(slice.len());
    let mut map = Vec::with_capacity(slice.len());
    let mut chars = slice.char_indices().peekable();
    while let Some((k, c)) = chars.next() {
        let origin = view.orig(start + k).unwrap_or(orig_len);
        if c == '\\'
            && let Some(&(_, next)) = chars.peek()
        {
            let decoded = match next {
                'n' => Some('\n'),
                'r' => Some('\r'),
                't' => Some('\t'),
                '"' => Some('"'),
                '\\' => Some('\\'),
                '/' => Some('/'),
                _ => None,
            };
            if let Some(d) = decoded {
                chars.next();
                text.push(d);
                map.push(origin);
                continue;
            }
        }
        text.push(c);
        map.extend(std::iter::repeat_n(origin, c.len_utf8()));
    }
    View {
        text: Cow::Owned(text),
        map: Some(map),
    }
}

/// The regions of `text` around backslashes, each bounded by its line and
/// [`ESCAPE_WINDOW`], merged, on char boundaries.
fn escape_windows(text: &str, mut settled: impl FnMut(usize) -> bool) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (p, _) in text.match_indices('\\') {
        if out.last().is_some_and(|&(_, e)| p < e) || settled(p) {
            continue;
        }
        // Only an escape the decoded pass changes earns a window: a `\` before
        // a newline (line continuation) or any other char decodes to itself,
        // and re-scanning identical text finds nothing new.
        if !matches!(
            text.as_bytes().get(p + 1),
            Some(b'n' | b'r' | b't' | b'"' | b'\\' | b'/')
        ) {
            continue;
        }
        let mut lo = p.saturating_sub(ESCAPE_WINDOW);
        while !text.is_char_boundary(lo) {
            lo -= 1;
        }
        let mut hi = (p + ESCAPE_WINDOW).min(text.len());
        while !text.is_char_boundary(hi) {
            hi += 1;
        }
        let start = text[lo..p].rfind('\n').map_or(lo, |i| lo + i + 1);
        let end = text[p..hi].find('\n').map_or(hi, |i| p + i);
        // Adjacent lines merge (`start` is one past the previous `\n`), so a
        // run of escaped lines is one window, not a window per line.
        match out.last_mut() {
            Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// `text` with every secret value masked, or `None` when nothing was masked
/// (or a span could not be applied safely — fail open to "no change").
pub fn redact(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let mut spans = Vec::new();
    let mut names = Names::default();
    let plain = strip_ansi(text);
    collect_mapped(text, &plain, &mut names, &mut spans);
    let plain_masks = merge(std::mem::take(&mut spans));
    // An escape inside a plain-pass mask adds nothing when decoded: the text
    // it could expose is masked already, and any pair beyond the mask that
    // only decoding reveals has escapes of its own outside it, which still
    // open a window (a window spans the whole line). Skipping these keeps
    // dense escaped output (`"PASSWORD=x\n"…`, `\"PASSWORD=x\"…`) to one pass.
    let mut cursor = 0usize;
    let settled = |p: usize| {
        let Some(o) = plain.orig(p) else {
            return false;
        };
        while cursor < plain_masks.len() && plain_masks[cursor].end <= o {
            cursor += 1;
        }
        plain_masks.get(cursor).is_some_and(|m| m.start <= o)
    };
    let windows = escape_windows(&plain.text, settled);
    spans = plain_masks;
    for (start, end) in windows {
        let window = unescape_window(&plain, start, end, text.len());
        collect_mapped(text, &window, &mut names, &mut spans);
    }
    if spans.is_empty() {
        return None;
    }
    let merged = merge(spans);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for span in &merged {
        out.push_str(text.get(cursor..span.start)?);
        text.get(span.start..span.end)?;
        match span.label {
            Label::Named => out.push_str(NAMED_MARK),
            Label::Kind(kind) => {
                out.push_str("[redacted: ");
                out.push_str(kind);
                out.push(']');
            }
        }
        cursor = span.end;
    }
    out.push_str(text.get(cursor..)?);
    (out != text).then_some(out)
}

/// Sort and merge overlapping spans; a token kind wins the label.
fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_unstable_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = merged.last_mut()
            && span.start < last.end
        {
            last.end = last.end.max(span.end);
            if let Label::Kind(_) = span.label {
                last.label = span.label;
            }
            continue;
        }
        merged.push(span);
    }
    merged
}

/// Run every detector over `view` and map its spans back to `original`.
///
/// A span's end maps to just past the original char its last byte came from
/// (a two-byte escape counts whole), so a colour reset right after a masked
/// value is kept, not swallowed.
fn collect_mapped(original: &str, view: &View<'_>, names: &mut Names, spans: &mut Vec<Span>) {
    let mut local = Vec::new();
    let t: &str = &view.text;
    token_spans(t, &mut local);
    url_spans(t, &mut local);
    json_pair_spans(t, names, &mut local);
    name_value_json_spans(t, names, &mut local);
    env_string_spans(t, names, &mut local);
    inline_spans(t, names, &mut local);
    quoted_key_spans(t, names, &mut local);
    argv_flag_spans(t, &mut local);
    npmrc_spans(t, &mut local);
    line_spans(t, names, &mut local);
    for s in local {
        if s.start >= s.end {
            continue;
        }
        let (start, end) = match &view.map {
            None => (s.start, s.end),
            Some(map) => {
                let (Some(&start), Some(&last)) = (map.get(s.start), map.get(s.end - 1)) else {
                    continue;
                };
                (start, char_end(original, last))
            }
        };
        if start >= end {
            continue;
        }
        // Coalesce with the previous span when they touch: detectors emit in
        // ascending order, so this keeps the vector (and its sort) small on
        // dense output.
        if let Some(last) = spans.last_mut()
            && last.label == s.label
            && start >= last.start
            && start <= last.end
        {
            last.end = last.end.max(end);
            continue;
        }
        spans.push(Span {
            start,
            end,
            label: s.label,
        });
    }
}

/// End of the original char (or two-byte `\x` escape) starting at `at`.
fn char_end(original: &str, at: usize) -> usize {
    let Some(rest) = original.get(at..) else {
        return original.len();
    };
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return at;
    };
    let mut end = at + first.len_utf8();
    if first == '\\'
        && let Some(next) = chars.next()
    {
        end += next.len_utf8();
    }
    end
}

// ---------------------------------------------------------------------------
// Credential tokens and private keys
// ---------------------------------------------------------------------------

fn token_spans(text: &str, spans: &mut Vec<Span>) {
    let mut hits = credential_scan::direct_spans(text);
    hits.sort_by_key(|h| h.start);
    let ends: Vec<(usize, usize)> = PEM_END_RE
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect();
    let first_begin = hits
        .iter()
        .find(|h| h.kind == PEM_KIND)
        .map_or(text.len(), |h| h.start);
    // An END with no BEGIN before it: the tail of a key whose start is in the
    // other stream or was cut off. Mask from the stream start.
    if let Some(&(_, end)) = ends.iter().take_while(|(s, _)| *s < first_begin).last() {
        spans.push(Span {
            start: 0,
            end,
            label: Label::Kind(KEY_LABEL),
        });
    }
    // Each BEGIN masks to the next END (or the end of the stream); a BEGIN
    // already inside a masked key is skipped, so this stays linear.
    let mut covered = 0;
    let mut k = 0;
    for hit in hits {
        if hit.kind != PEM_KIND {
            spans.push(Span {
                start: hit.start,
                end: hit.end,
                label: Label::Kind(hit.kind),
            });
            continue;
        }
        if hit.start < covered {
            continue;
        }
        while k < ends.len() && ends[k].0 < hit.end {
            k += 1;
        }
        let end = ends.get(k).map_or(text.len(), |e| e.1);
        covered = end;
        spans.push(Span {
            start: hit.start,
            end,
            label: Label::Kind(KEY_LABEL),
        });
    }
}

/// `scheme://user:password@host` — the password, whatever the name around it.
static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/?#@:'"]*:([^\s/?#@'"]+)@"#)
        .expect("url userinfo regex is valid")
});

fn url_spans(text: &str, spans: &mut Vec<Span>) {
    if !text.contains("://") {
        return;
    }
    for caps in URL_USERINFO.captures_iter(text) {
        if let Some(pw) = caps.get(1) {
            spans.push(Span {
                start: pw.start(),
                end: pw.end(),
                label: Label::Kind(URL_LABEL),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// How sure a name is to hold a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// `password`, `secret`, `token`, `api_key`, `Authorization`, … — every
    /// value is masked except booleans, placeholders and `$VAR` references.
    Strong,
    /// `…_key`, `auth`, `db_pass` — ambiguous; in the prose-shaped forms
    /// (unquoted `name: value`, tables) the value must also look like a
    /// credential ([`secret_like`]).
    Weak,
    /// A strong name whose last segment is metadata (`SECRET_TOKEN_URL`,
    /// `API_KEY_ENV`, `adminPasswordKey`, `existingSecret`): masked unless the
    /// value itself looks like metadata ([`metadata_value`]) — a URL, path,
    /// number, reference, plain word or lowercase k8s-style name.
    Meta,
    /// A glued `…pass` word whose stem also names a counter or a timestamp
    /// (`lastpass`, `hashpass`, `endpass`): masked as [`Strength::Strong`] is,
    /// except a value that is only digits (`lastpass=1696500000`,
    /// `HASHPASS: 12`), which counts something.
    Counter,
}

/// Per-call memo of [`name_strength`], so a long run of the same name is
/// classified once.
#[derive(Default)]
struct Names {
    memo: HashMap<String, Option<Strength>>,
    /// The last name looked up (buffer reused): real and adversarial runs
    /// repeat one name.
    last: String,
    last_strength: Option<Strength>,
}

/// Memo entries kept per call; past this, distinct names are classified
/// without being stored, so a flood of distinct names cannot grow the map.
const MEMO_CAP: usize = 1024;

impl Names {
    fn get(&mut self, name: &str) -> Option<Strength> {
        if !self.last.is_empty() && self.last == name {
            return self.last_strength;
        }
        let s = if name.len() > MAX_NAME || !might_be_secret(name) {
            None
        } else if let Some(&s) = self.memo.get(name) {
            s
        } else {
            let s = name_strength(name);
            if self.memo.len() < MEMO_CAP {
                self.memo.insert(name.to_string(), s);
            }
            s
        };
        self.last.clear();
        self.last.push_str(name);
        self.last_strength = s;
        s
    }
}

/// Cheap prefilter for [`name_strength`]: every segment it accepts contains
/// one of these (case-insensitively), so most names skip the segment split.
fn might_be_secret(name: &str) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"secret", b"token", b"pass", b"pw", b"cred", b"key", b"auth", b"cookie", b"docker", b"dsn",
    ];
    let bytes = name.as_bytes();
    NEEDLES
        .iter()
        .any(|n| bytes.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n)))
}

/// Does this NAME hold a secret value? See [`name_strength`].
pub fn is_secret_name(name: &str) -> bool {
    name_strength(name).is_some()
}

/// Classify a NAME by `_`/`-`/`.`/camelCase segment. `None` when it is not a
/// secret name — including when its last segment is metadata (`TOKEN_URL`,
/// `KEY_ID`, `SSH_AUTH_SOCK`, `PASSWORD_FILE`); URL userinfo is masked by its
/// own rule, so a `_URL` exemption never exposes a password.
pub fn name_strength(name: &str) -> Option<Strength> {
    // Test runners' status words, and the shell's working-directory vars.
    if matches!(name, "PASS" | "FAIL" | "OK" | "PWD" | "OLDPWD") {
        return None;
    }
    // AWS's request idempotency field, in the API's own PascalCase spelling
    // only: Vault's `client_token` is a real token and stays strong.
    if name == "ClientToken" {
        return None;
    }
    if name.len() > MAX_NAME {
        return None;
    }
    // Lowercase into a stack buffer and slice segments out of it: no heap
    // allocation per name (a flood of distinct names is the perf worst case).
    let mut buf = [0u8; MAX_NAME];
    let lower = &mut buf[..name.len()];
    lower.copy_from_slice(name.as_bytes());
    lower.make_ascii_lowercase();
    let lower = std::str::from_utf8(lower).ok()?;
    let mut ranges = [(0usize, 0usize); MAX_SEGMENTS];
    let count = segment_ranges(name.as_bytes(), &mut ranges);
    let mut seg_buf = [""; MAX_SEGMENTS];
    let mut n = 0;
    for &(a, b) in &ranges[..count] {
        let seg = &lower[a..b];
        // Numeric segments (`API_KEY_2`) neither qualify nor terminate a name.
        if !seg.bytes().all(|c| c.is_ascii_digit()) {
            seg_buf[n] = seg;
            n += 1;
        }
    }
    let segs = &seg_buf[..n];
    let (&last, body) = segs.split_last()?;
    // A metadata last segment describes the secret rather than holding it —
    // unless the rest of the name is strong, where the VALUE decides (Meta).
    // `…PasswordKey`/`…TokenKey` and `existingSecret` are references too.
    let meta_suffix = METADATA_SUFFIXES.contains(&last)
        || (last == "key"
            && body
                .last()
                .is_some_and(|p| matches!(*p, "password" | "token")))
        || (matches!(last, "secret" | "secrets") && body.last() == Some(&"existing"));
    if meta_suffix {
        return matches!(classify(body), Some(Strength::Strong | Strength::Counter))
            .then_some(Strength::Meta);
    }
    classify(segs)
}

fn classify(segs: &[&str]) -> Option<Strength> {
    // Whole-name directives that are not English words (redis, slapd).
    if let [only] = segs
        && matches!(
            *only,
            "requirepass" | "masterauth" | "rootpw" | "pass" | "pw"
        )
    {
        return Some(Strength::Strong);
    }
    let mut weak = false;
    for (i, seg) in segs.iter().enumerate() {
        let prev = i.checked_sub(1).map(|p| segs[p]);
        match *seg {
            "token" => {
                // `NextToken`, `next_page_token`, `IdempotencyToken`: the
                // camelCase and separated spellings of the pagination and
                // idempotency handles. Other glued exemptions (`keytoken`,
                // `synctoken`) stay glued-only, so `KEY_TOKEN` is strong.
                if prev.is_none_or(|p| {
                    !TOKEN_COUNT_QUALIFIERS.contains(&p) && !HANDLE_TOKEN_QUALIFIERS.contains(&p)
                }) {
                    return Some(Strength::Strong);
                }
            }
            "key" | "keys" => match prev {
                Some("api" | "access" | "secret" | "private" | "master" | "signing") => {
                    return Some(Strength::Strong);
                }
                Some(p) if !NON_SECRET_KEY_QUALIFIERS.contains(&p) => weak = true,
                _ => {}
            },
            "auth" => weak = true,
            "pass" => weak |= prev.is_some(),
            s if s
                .strip_suffix("pass")
                .is_some_and(|stem| COUNTER_PASS_PREFIXES.contains(&stem)) =>
            {
                return Some(Strength::Counter);
            }
            s if STRONG_WORDS.contains(&s) || glued_strong(s) => return Some(Strength::Strong),
            _ => {}
        }
    }
    weak.then_some(Strength::Weak)
}

/// A strong word glued to a prefix: `pgpassword`, `githubtoken`,
/// `clientsecret`, `hftoken`, `masterpassword`. Any prefix counts, except a
/// counter (`maxtoken`) and a short list of non-secret compound words that
/// end in `token` (`jsonwebtoken`, `cancellationtoken`, …).
fn glued_strong(seg: &str) -> bool {
    if NON_SECRET_GLUED.contains(&seg) {
        return false;
    }
    if let Some(prefix) = seg.strip_suffix("token")
        && TOKEN_COUNT_QUALIFIERS.contains(&prefix)
    {
        return false;
    }
    // `…key`: strong when the prefix ENDS with a credential word
    // (`openaiapi|key`, `awssecret|key`, `gcpprivate|key`); otherwise fall
    // through, so `…apikey` still meets `STRONG_SUFFIXES`.
    if let Some(prefix) = seg.strip_suffix("key")
        && GLUED_KEY_PREFIXES.iter().any(|p| prefix.ends_with(p))
    {
        return true;
    }
    if let Some(prefix) = seg.strip_suffix("pass") {
        return !prefix.is_empty() && !NON_SECRET_PASS_PREFIXES.contains(&prefix);
    }
    STRONG_SUFFIXES
        .iter()
        .any(|w| seg.len() > w.len() && seg.ends_with(w))
}

/// Segments before a separate `token` segment that make it a pagination or
/// idempotency handle, not a credential (`NextToken`, `next_page_token`,
/// `IdempotencyToken`).
const HANDLE_TOKEN_QUALIFIERS: &[&str] = &["next", "page", "idempotency"];

/// Stems of a glued `…pass` word that may count something: see
/// [`Strength::Counter`].
const COUNTER_PASS_PREFIXES: &[&str] = &["hash", "last", "end"];

/// A value that is only digits, once quotes and a trailing `,`/`;` are
/// trimmed.
fn is_count(value: &str) -> bool {
    let v = value
        .trim()
        .trim_end_matches([',', ';'])
        .trim_matches(['"', '\'']);
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

/// Prefixes that make a glued `…key` a credential (`MASTERKEY`, `SSHKEY`).
/// `…key` is too common a word ending (`monkey`, `hotkey`, `turnkey`,
/// `sortkey`) to accept any prefix.
const GLUED_KEY_PREFIXES: &[&str] = &[
    // Not `signing`: git's `user.signingkey` is a public key ID.
    "master",
    "encryption",
    "ssh",
    "license",
    "api",
    "access",
    "secret",
    "private",
    "client",
    "app",
    "auth",
    "session",
    "jwt",
    "hmac",
    "aes",
    "crypt",
    "gpg",
    "pgp",
    "deploy",
    "service",
    "webhook",
];

/// Word stems before `pass` that are ordinary words (`bypass`, `compass`).
const NON_SECRET_PASS_PREFIXES: &[&str] = &[
    "by", "com", "sur", "over", "under", "tres", "encom", "im", "re", "first", "second", "single",
    "multi", "one", "two", "ask", "sshask", "gitask",
];

/// Glued `…token` words that are not credential names.
const NON_SECRET_GLUED: &[&str] = &[
    "jsonwebtoken",
    "cancellationtoken",
    "continuationtoken",
    "nexttoken",
    "pagetoken",
    "synctoken",
    "resumetoken",
    "keytoken",
    "idempotencytoken",
];

/// Word endings that make a glued segment strong.
const STRONG_SUFFIXES: &[&str] = &[
    "password", "passwd", "passwort", "secret", "apikey", "pwd", "token",
];

/// Segments that make a name a STRONG secret name wherever they sit.
const STRONG_WORDS: &[&str] = &[
    "secret",
    "secrets",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "credential",
    "credentials",
    "creds",
    "apikey",
    "privatekey",
    "secretkey",
    "accesskey",
    "authorization",
    "cookie",
    "dockerconfigjson",
    "dockercfg",
    "dsn",
];

// ---------------------------------------------------------------------------
// Value policy
// ---------------------------------------------------------------------------

/// Can this value be a secret at all? False only for empty, boolean/null,
/// obvious placeholders and variable references.
fn maskable(value: &str) -> bool {
    let mut v = value.trim();
    if v.len() >= 2
        && let (Some(a), Some(b)) = (v.chars().next(), v.chars().next_back())
        && a == b
        && matches!(a, '"' | '\'')
    {
        v = v[1..v.len() - 1].trim();
    }
    if v.is_empty() {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "none" | "nil" | "~" | "undefined"
    ) || is_placeholder(&lower)
    {
        return false;
    }
    // An auth scheme followed by a placeholder or a variable reference:
    // `Bearer <token>`, `token ***`, `Bearer $TOKEN`, `Bearer ${TOKEN}`.
    if let Some((scheme, rest)) = lower.split_once(' ')
        && matches!(scheme, "bearer" | "basic" | "token" | "digest")
        && (is_placeholder(rest.trim()) || is_var_ref(v[scheme.len()..].trim()))
    {
        return false;
    }
    !is_var_ref(v)
}

/// `***`, `gho_****…`, `<redacted>`, `[REDACTED]`, `(sensitive value)`.
fn is_placeholder(lower: &str) -> bool {
    lower.contains("redacted")
        || lower.contains("****")
        || lower.chars().all(|c| c == '*')
        || (lower.starts_with('<') && lower.ends_with('>'))
        || (lower.starts_with('(')
            && lower.ends_with(')')
            && (lower.contains("sensitive") || lower.contains("known after apply")))
}

/// `$VAR`, `${VAR}`, `${{ secrets.X }}` — a reference, not a value. A bare
/// `$name` counts only in one case (`$DB_PASS`, `$db_pass`): a mixed-case
/// run after `$` is more likely a password that starts with `$`.
fn is_var_ref(v: &str) -> bool {
    if let Some(inner) = v.strip_prefix("${") {
        return inner.ends_with('}');
    }
    let Some(name) = v.strip_prefix('$') else {
        return false;
    };
    let ident = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ident
        && (name.chars().all(|c| !c.is_ascii_lowercase())
            || name.chars().all(|c| !c.is_ascii_uppercase()))
}

/// Words a strong name is followed by in prose and schema output, never a
/// credential: `password: required`, `token: expired`.
const PROSE_VALUES: &[&str] = &[
    "required",
    "expired",
    "invalid",
    "missing",
    "optional",
    "empty",
    "unset",
    "set",
    "changed",
    "updated",
    "denied",
    "incorrect",
    "wrong",
    "reset",
    "hidden",
    "masked",
    "sensitive",
    "unknown",
    "default",
    "n/a",
];

/// Source code, not data: a type annotation (`password: String,`,
/// `token: Option<String>,`, `password: &str`). A bare capitalised word with
/// no trailing `,`/`;` (`password: Hunter`) is NOT code — it may be the value.
fn is_code_value(v: &str) -> bool {
    let v = v.trim();
    let body = v.trim_end_matches([',', ';']).trim();
    let typeish = !body.is_empty()
        && body.chars().all(|c| {
            c.is_ascii_alphabetic() || matches!(c, '_' | ':' | '<' | '>' | '&' | '\'' | ' ' | '|')
        });
    let punctuated = body.len() < v.len() || body.contains(['<', '&']) || body.contains("::");
    // `let token: String = get_token();` — a typed binding, not a value.
    let binding = v.split_once(" = ").is_some_and(|(ty, _)| {
        !ty.is_empty()
            && ty.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '_' | ':' | '<' | '>' | '&' | '\'' | ' ' | ',')
            })
    });
    // `process.env.DB_PASSWORD,` / `config.get('token'),` — an expression
    // closing an object-literal entry.
    let expression = body.len() < v.len()
        && body.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && (body.contains('.') || body.contains('('))
        && !body.contains(' ');
    let lower = body.to_ascii_lowercase();
    binding
        || expression
        || v.starts_with('=')
        || (typeish && punctuated)
        || matches!(
            lower.as_str(),
            "string" | "str" | "bool" | "int" | "number" | "any" | "bytes" | "secretstr"
        )
}

/// The value test for a name of `strength`. `colon` is the unquoted
/// `name: value` form, which is also how prose, schemas and source code read.
fn value_masks(strength: Strength, value: &str, colon: bool) -> bool {
    let v = value.trim();
    match (strength, colon) {
        (Strength::Meta, _) => maskable(v) && !metadata_value(v),
        (Strength::Counter, colon) => !is_count(v) && value_masks(Strength::Strong, v, colon),
        (Strength::Strong, true) => {
            maskable(v)
                && !PROSE_VALUES.contains(&v.to_ascii_lowercase().as_str())
                && !is_yes_no(v)
                && !is_code_value(v)
        }
        (Strength::Weak, true) => secret_like(v),
        (_, false) => maskable(v),
    }
}

/// A bare `YES`/`NO`, optionally closing a parenthesis: MySQL's
/// `Access denied for user 'u'@'h' (using password: YES)` reports whether a
/// password was sent, not the password.
fn is_yes_no(value: &str) -> bool {
    let word = value.trim_end_matches(')').trim();
    word.eq_ignore_ascii_case("yes") || word.eq_ignore_ascii_case("no")
}

/// Does `value` look like metadata rather than a credential: a URL, a path, a
/// number, a reference (`$X`, `${X}`), a plain word, or a lowercase
/// k8s/host-style name (`pg-auth`, `postgres-password`, `auth.example.com`)?
fn metadata_value(value: &str) -> bool {
    // Judge the first word: a mid-line value runs to the end of the line and
    // may carry the closing `}`/`,` of the structure around it.
    let v = value
        .trim()
        .split([' ', '\t', ',', '}', ')', ';'])
        .next()
        .unwrap_or("")
        .trim_matches(['"', '\'']);
    v.contains("://")
        || v.starts_with(['/', '~', '$'])
        || v.starts_with("./")
        || v.chars().all(|c| c.is_ascii_digit() || c == '.')
        || v.chars().all(|c| c.is_ascii_alphabetic())
        || v.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '/' | '_' | ':')
        })
}

/// An HTTP credential header whose value (`Bearer …`, `Basic …`) has spaces
/// by design — never read as prose, even after a label (`curl --trace-ascii`
/// prints `001f: Authorization: Bearer …`).
fn is_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "private-token"
            | "api-key"
    )
}

/// For a WEAK name in a prose-shaped form: the value must look like a
/// credential — one word of at least 8 characters that is not a plain word,
/// number, duration, or identifier/type expression.
fn secret_like(value: &str) -> bool {
    let v = value.trim().trim_end_matches([',', ';']);
    if !maskable(v) || v.chars().any(char::is_whitespace) || v.chars().count() < 8 {
        return false;
    }
    let all = |f: fn(char) -> bool| v.chars().all(f);
    let plain_word = all(|c| c.is_ascii_alphabetic())
        && (all(|c| c.is_ascii_lowercase())
            || all(|c| c.is_ascii_uppercase())
            || v.chars().skip(1).all(|c| c.is_ascii_lowercase()));
    let number = all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+'));
    let duration = v.starts_with(|c: char| c.is_ascii_digit())
        && all(|c| c.is_ascii_digit() || matches!(c, '.' | 'n' | 's' | 'u' | 'µ' | 'm' | 'h'));
    let code =
        all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | ':' | '<' | '>' | '&' | '\'' | '.'));
    !(plain_word || number || duration || code)
}

// ---------------------------------------------------------------------------
// Secret-named values
// ---------------------------------------------------------------------------

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// The name at the end of `head` (after trimming trailing blanks and quotes),
/// with any leading `-`/`--` flag dashes removed.
fn tail_name(head: &str) -> &str {
    let head = head.trim_end_matches([' ', '\t', '"', '\'']);
    let start = head
        .char_indices()
        .rev()
        .take_while(|&(_, c)| is_name_char(c))
        .last()
        .map_or(head.len(), |(i, _)| i);
    head[start..].trim_start_matches('-')
}

/// `"name": "value"` or `"name": 123` anywhere — JSON, pretty or minified.
static JSON_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#""((?:[^"\\\n]|\\.)+)"[ \t]*:[ \t]*(?:"((?:[^"\\\n]|\\.)*)"|(-?[0-9][0-9.eE+\-]*))"#,
    )
    .expect("json pair regex is valid")
});

/// `{"name": "X", "value": "V"}` — ECS / k8s-as-JSON env entries.
static NAME_VALUE_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""name"\s*:\s*"((?:[^"\\\n]|\\.)*)"\s*,\s*"value"\s*:\s*"((?:[^"\\\n]|\\.)*)""#)
        .expect("name/value regex is valid")
});

/// `"NAME=value"` inside a JSON string — `docker inspect`'s `.Config.Env`.
static ENV_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""[A-Za-z_.][A-Za-z0-9_.\-]*=(?:[^"\\\n]|\\.)*""#)
        .expect("env string regex is valid")
});

/// A mid-line `NAME=` / `--name=` (after a separator, quote or `?`/`&`).
static INLINE_EQ: LazyLock<Regex> = LazyLock::new(|| {
    // No `^`/newline alternative: line-start forms are `line_spans`' job, and
    // matching every line start only to discard it was the cost on
    // name-per-line floods.
    Regex::new(r#"[ \t;|&'"(?,{\[](?:--?)?[A-Za-z_][A-Za-z0-9_.\-]*="#)
        .expect("inline eq regex is valid")
});

/// A mid-line `name:` / `Name: ` (after whitespace, a quote or a bracket).
static INLINE_COLON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[ \t'"(\[{,][A-Za-z_][A-Za-z0-9_.\-]*:"#).expect("inline colon regex is valid")
});

/// `--name value` (a secret-named flag with its value as the next word).
static FLAG_SPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|\s)--([A-Za-z][A-Za-z0-9\-]*)[ \t]+([^\s\-]\S*)")
        .expect("flag regex is valid")
});

/// A line-start assignment head: optional list/quote/diff markers and an
/// `export`/`declare -x`/`set` keyword, a name (optionally quoted, may start
/// with `.`), then `=` or `:`. The value is parsed by hand from the match end.
static LINE_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^[ \t]*(?:[-*>+<][ \t]+)*(?:(?:export|declare[ \t]+-x|set)[ \t]+)?["']?[A-Za-z_.][A-Za-z0-9_.\-]*["']?[ \t]*[=:]"#,
    )
    .expect("line head regex is valid")
});

/// `name  value` — a table row (vault `kv get`, `.netrc` lines) whose value
/// is one word.
static WS_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([ \t]*)([A-Za-z_.][A-Za-z0-9_.\-]*)([ \t]+)(\S(?:.*\S)?)[ \t]*$")
        .expect("row regex is valid")
});

/// k8s `name: X` (optionally a list item) — the key of a following `value:`.
static K8S_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[ \t]*(?:-[ \t]+)?name:[ \t]*["']?([A-Za-z_.][A-Za-z0-9_.\-]*)["']?[ \t]*$"#)
        .expect("k8s name regex is valid")
});

/// k8s `value: V`.
static K8S_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*(?:-[ \t]+)?value:[ \t]*").expect("k8s value regex is valid")
});

/// `.netrc` inline `password V`.
static NETRC_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)(?:password|passwd)[ \t]+(\S+)").expect("netrc regex is valid")
});

/// Where the `"` closing a JSON string that starts at `from` sits.
fn json_string_end(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            b'\n' => return None,
            _ => i += 1,
        }
    }
    None
}

fn json_pair_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    if !text.contains("\":") && !text.contains("\" :") && !text.contains("\"\t:") {
        return;
    }
    // Each search resumes at the end of the previous VALUE, not of the match,
    // so the quote closing one value can open the next name. Escaped nested
    // JSON (`"{"password":"…"}"` once decoded) would otherwise misalign and
    // hide the pair. Every step moves forward, so this stays linear.
    let mut pos = 0;
    while pos < text.len() {
        let Some(m) = JSON_PAIR.find_at(text, pos) else {
            break;
        };
        let Some(name_end) = json_string_end(text, m.start() + 1) else {
            break;
        };
        let name = &text[m.start() + 1..name_end];
        let after = text[name_end + 1..m.end()].trim_start_matches([' ', '\t', ':']);
        let value_start = m.end() - after.len();
        let (vs, ve) = if after.starts_with('"') {
            (value_start + 1, m.end() - 1)
        } else {
            (value_start, m.end())
        };
        pos = ve.max(name_end + 1).max(m.start() + 1);
        if vs <= ve
            && let Some(strength) = names.get(name)
            && value_masks(strength, &text[vs..ve], false)
        {
            spans.push(named(vs, ve));
        }
    }
}

fn name_value_json_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    if !text.contains("\"value\"") {
        return;
    }
    for caps in NAME_VALUE_JSON.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if let Some(strength) = names.get(name.as_str())
            && value_masks(strength, value.as_str(), false)
        {
            spans.push(named(value.start(), value.end()));
        }
    }
}

fn env_string_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    for m in ENV_STRING.find_iter(text) {
        let body = &text[m.start() + 1..m.end() - 1];
        let Some((name, value)) = body.split_once('=') else {
            continue;
        };
        let vs = m.start() + 1 + name.len() + 1;
        if let Some(strength) = names.get(name)
            && value_masks(strength, value, false)
        {
            spans.push(named(vs, vs + value.len()));
        }
    }
}

/// A single-quoted or symbol key with its value: Python dict/repr
/// (`{'password': 'V'}`, `environ({'GITHUB_TOKEN': 'V'})`), tuples
/// (`('password', 'V')`), subscript assignment (`os.environ['API_TOKEN'] =
/// 'V'`), and Ruby (`'password' => 'V'`, `:password => "V"`).
static QUOTED_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:'([A-Za-z_.][A-Za-z0-9_.\-]*)'\]?|:([A-Za-z_][A-Za-z0-9_]*))[ \t]*(?::|=>|,|=)[ \t]*(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)")"#,
    )
    .expect("quoted key regex is valid")
});

fn quoted_key_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    if !text.contains('\'') && !text.contains("=>") {
        return;
    }
    // Resume at the end of each VALUE, so `'a': 'b', 'password': 'V'` and a
    // value's closing quote opening the next key both align (linear).
    let mut pos = 0;
    while pos < text.len() {
        let Some(caps) = QUOTED_KEY.captures_at(text, pos) else {
            break;
        };
        let (Some(whole), Some(name)) = (caps.get(0), caps.get(1).or_else(|| caps.get(2))) else {
            break;
        };
        let Some(value) = caps.get(3).or_else(|| caps.get(4)) else {
            break;
        };
        pos = value.end().max(whole.start() + 1);
        if let Some(strength) = names.get(name.as_str())
            && value_masks(strength, value.as_str(), false)
        {
            spans.push(named(value.start(), value.end()));
        }
    }
}

/// Credentials passed as short flags on a command line — what `set -x`
/// traces, `ps` and `history` print. Command-aware: the flag means a
/// password only for these tools (`-P` is psql's port, `-p` ssh's).
/// `(command, flag regex)`; group 1 is the value.
static ARGV_FLAGS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        // mysql family: `-pVALUE` (attached only; a bare `-p` prompts).
        ("mysql", r#"(?:^|\s)-p('[^'\n]*'|"[^"\n]*"|[^\s'"]\S*)"#),
        ("mariadb", r#"(?:^|\s)-p('[^'\n]*'|"[^"\n]*"|[^\s'"]\S*)"#),
        // curl `-u user:VALUE`, a flag cluster ending in `u` (`-su`,
        // `-fsSu`), or `--user user:VALUE`.
        (
            "curl",
            r#"(?:^|\s)(?:-[A-Za-z]*u|--user)[ \t=]*['"]?[^\s:'"]*:([^\s'"]+)"#,
        ),
        // `docker|podman|helm registry login -p VALUE` / `-p=VALUE` / `-up V`.
        (" login", r"(?:^|\s)-[a-zA-Z]*p(?:[ \t]+|=)(\S+)"),
        ("sshpass", r"(?:^|\s)-p[ \t]*(\S+)"),
        ("redis-cli", r"(?:^|\s)-a[ \t]+(\S+)"),
        ("mongo", r"(?:^|\s)-p[ \t]+(\S+)"),
        ("smbclient", r"(?:^|\s)-U[ \t]*[^\s%]*%(\S+)"),
        ("zip", r"(?:^|\s)-P[ \t]+(\S+)"),
        ("unzip", r"(?:^|\s)-P[ \t]+(\S+)"),
        ("7z", r"(?:^|\s)-p(\S+)"),
        ("rar", r"(?:^|\s)-p(\S+)"),
        ("openssl", r"pass:(\S+)"),
        ("ngrok", r"authtoken[ \t]+(\S+)"),
        (
            "keytool",
            r"(?:^|\s)-(?:src|dest)?(?:storepass|keypass)[ \t]+(\S+)",
        ),
        ("lftp", r"(?:^|\s)-u[ \t]+[^\s,]*,(\S+)"),
        // `htpasswd -b[other flags] FILE USER PASSWORD`.
        (
            "htpasswd",
            r"(?:^|\s)-[a-zA-Z]*b[a-zA-Z]*[ \t]+\S+[ \t]+\S+[ \t]+(\S+)",
        ),
    ]
    .into_iter()
    .map(|(cmd, re)| (cmd, Regex::new(re).expect("argv flag regex is valid")))
    .collect()
});

/// `.npmrc` registry credentials: `//host/:_authToken=V`, `:_auth=V`,
/// `:_password=V` — any value but a `${VAR}` reference.
static NPMRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r":_(?:authToken|auth|password)[ 	]*=[ 	]*(\S+)").expect("npmrc regex is valid")
});

fn npmrc_spans(text: &str, spans: &mut Vec<Span>) {
    if !text.contains(":_") {
        return;
    }
    for caps in NPMRC.captures_iter(text) {
        if let Some(v) = caps.get(1)
            && maskable(v.as_str())
        {
            spans.push(named(v.start(), v.end()));
        }
    }
}

/// Flag values judged per command line before the rest is masked whole.
const ARGV_FLAG_CAP: usize = 256;

fn argv_flag_spans(text: &str, spans: &mut Vec<Span>) {
    for (cmd, re) in ARGV_FLAGS.iter() {
        // Each word-bounded occurrence of the command, scanned to its line
        // end once (a later occurrence on an already-scanned line is skipped).
        let mut scanned_to = 0;
        for (at, _) in text.match_indices(cmd) {
            if at < scanned_to {
                continue;
            }
            // The rest of the word counts as the command (`mysqldump`,
            // `mysqladmin`); what follows must be a blank.
            let from = at
                + cmd.len()
                + text[at + cmd.len()..]
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-')
                    .count();
            let before_ok = text[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
                || cmd.starts_with(' ');
            let after_ok = text[from..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace());
            if !(before_ok && after_ok) {
                continue;
            }
            let eol = text[from..].find('\n').map_or(text.len(), |i| from + i);
            scanned_to = eol;
            for (k, caps) in re.captures_iter(&text[from..eol]).enumerate() {
                // A line carrying thousands of flag values is not a command
                // line; past the cap, mask the rest of it rather than pay a
                // capture per flag (fail toward masking, bounded time).
                if k >= ARGV_FLAG_CAP {
                    let at = caps.get(0).map_or(from, |m| from + m.start());
                    spans.push(named(at, eol));
                    break;
                }
                if let Some(v) = caps.get(1) {
                    let (vs, ve) = unquote(0, v.as_str());
                    if ve > vs && maskable(&v.as_str()[vs..ve]) {
                        spans.push(named(from + v.start() + vs, from + v.start() + ve));
                    }
                }
            }
        }
    }
}

/// End of the line containing `from` (exclusive of `\r\n`/`\n`), cached in
/// `cache` so a run of matches on one long line finds its end once — a fresh
/// search per match is quadratic on a 5 MB single line.
fn line_end(text: &str, from: usize, cache: &mut (usize, usize)) -> usize {
    if from < cache.0 || from > cache.1 {
        let raw = text[from..].find('\n').map_or(text.len(), |i| from + i);
        *cache = (from, raw);
    }
    let end = cache.1;
    if end > from && text.as_bytes()[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

fn at_line_start(text: &str, at: usize) -> bool {
    at == 0 || text.as_bytes()[at - 1] == b'\n'
}

/// Mid-line forms: `NAME=value`, `name: value`, `--name value`. Line-start
/// forms are [`line_spans`]' job. Each value is scanned only past the end of
/// the previous masked value, so an adversarial run of `token=token=…` stays
/// linear.
fn inline_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    let mut done = 0;
    let mut eol_cache = (usize::MAX, 0);
    let mut parens = Parens::default();
    for m in INLINE_EQ.find_iter(text) {
        let head = m.as_str();
        let start = m.end();
        // The name starts after the lead separator, which may be the `\n`
        // ending the previous line: then this is a line-start form.
        let name_at =
            m.start() + head.len() - head.trim_start_matches(|c: char| !is_name_char(c)).len();
        if start < done || at_line_start(text, name_at) || text[start..].starts_with('=') {
            continue;
        }
        let Some(strength) = names.get(tail_name(&head[..head.len() - 1])) else {
            continue;
        };
        let lead = head.chars().next().filter(|c| !is_name_char(*c));
        let eol = line_end(text, start, &mut eol_cache);
        // Inside a call's argument list (`Client(api_key=api_key, …)`), a
        // value closed by `,`/`)` that is the name itself, an attribute path,
        // a call, or a lowercase snake identifier is a variable passed along.
        // Anything else — a mixed-case or digit-bearing word, or a value with
        // no closing `,`/`)` (`INFO (pid 12 token=…`) — takes the normal path.
        if parens.depth_at(text, name_at) > 0
            && !matches!(text[start..].chars().next(), Some('"' | '\''))
            && let Some(len) = text[start..eol].find([',', ')'])
        {
            let value = &text[start..start + len];
            let name = tail_name(&head[..head.len() - 1]);
            if is_arg_reference(value, name) || !maskable(value) {
                done = start + len;
                continue;
            }
        }
        let (vs, ve) = match text[start..eol].chars().next() {
            Some(q @ ('"' | '\'')) => {
                let inner = &text[start + 1..eol];
                (
                    start + 1,
                    start + 1 + closing_quote(inner, q).unwrap_or(inner.len()),
                )
            }
            _ => {
                // A strong name masks to the end of the line (a password
                // with spaces is still one password); a weak one, or a
                // value inside a quoted/query context, stops at its delimiter.
                let stop = |c: char| match lead {
                    Some(q @ ('"' | '\'')) => c == q,
                    Some('?' | '&') => c == '&' || c.is_whitespace(),
                    _ if matches!(strength, Strength::Strong | Strength::Counter) => false,
                    _ => c.is_whitespace() || matches!(c, '&' | '"' | '\''),
                };
                let len = text[start..eol].find(stop).unwrap_or(eol - start);
                (start, start + len)
            }
        };
        done = ve.max(start);
        if value_masks(strength, &text[vs..ve], false) {
            spans.push(named(vs, ve));
        }
    }
    done = 0;
    eol_cache = (usize::MAX, 0);
    for m in INLINE_COLON.find_iter(text) {
        let head = m.as_str();
        // The blanks after `:` are skipped here, not matched, so the next
        // `name:` on the line can still use one as its leading separator
        // (`=> Send header: Authorization: Bearer …`).
        let start =
            m.end() + text[m.end()..].len() - text[m.end()..].trim_start_matches([' ', '\t']).len();
        let name_at =
            m.start() + head.len() - head.trim_start_matches(|c: char| !is_name_char(c)).len();
        if start < done || at_line_start(text, name_at) {
            continue;
        }
        let colon = head.rfind(':').unwrap_or(head.len());
        let Some(strength) = names.get(tail_name(&head[..colon])) else {
            continue;
        };
        let eol = line_end(text, start, &mut eol_cache);
        let rest = &text[start..eol];
        if rest.starts_with("//") {
            continue;
        }
        let quote = head.chars().next().filter(|c| matches!(c, '"' | '\''));
        // After a label (`Error: token: …`, `main.go:5: token: …`) the value
        // is a message: several words there are prose, not a credential.
        let label = text[..name_at].trim_end_matches([' ', '\t']).ends_with(':');
        let (vs, ve, quoted) = match (quote, rest.chars().next()) {
            (Some(q), _) => (0, closing_quote(rest, q).unwrap_or(rest.len()), true),
            (None, Some(q @ ('"' | '\''))) => {
                let inner = &rest[1..];
                (1, 1 + closing_quote(inner, q).unwrap_or(inner.len()), true)
            }
            _ => (0, rest.trim_end().len(), false),
        };
        done = start + ve;
        let value = &rest[vs..ve];
        let masks = if quoted {
            value_masks(strength, value, false)
        } else if label && value.trim().contains(' ') && !is_header_name(tail_name(&head[..colon]))
        {
            false
        } else {
            value_masks(strength, value, true)
        };
        if masks {
            spans.push(named(start + vs, start + ve));
        }
    }
    if text.contains("--") {
        for caps in FLAG_SPACE.captures_iter(text) {
            let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            if let Some(strength) = names.get(name.as_str())
                && value_masks(strength, value.as_str(), false)
            {
                spans.push(named(value.start(), value.end()));
            }
        }
    }
}

/// Parenthesis depth on the current line at a byte offset, advanced
/// incrementally across increasing offsets so a long line is scanned once.
#[derive(Default)]
struct Parens {
    pos: usize,
    depth: i32,
}

impl Parens {
    fn depth_at(&mut self, text: &str, at: usize) -> i32 {
        if at < self.pos {
            *self = Parens::default();
        }
        for &b in &text.as_bytes()[self.pos..at] {
            match b {
                b'(' => self.depth += 1,
                b')' => self.depth = (self.depth - 1).max(0),
                b'\n' => self.depth = 0,
                _ => {}
            }
        }
        self.pos = at;
        self.depth
    }
}

/// An argument value that is code referring to something else: the name
/// itself (`api_key=api_key`), an attribute path (`token=self.token`), a call
/// (`password=get_password()`), or a lowercase snake identifier
/// (`password=password_default`). A mixed-case or digit-bearing bare word is
/// never exempt — that is what a secret literal looks like.
fn is_arg_reference(value: &str, name: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v == name {
        return !v.is_empty();
    }
    let (head, call) = match v.split_once('(') {
        Some((head, _)) => (head, true),
        None => (v, false),
    };
    let ident = head.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':'));
    let snake = v.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    ident && (call || head.contains('.') || snake)
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn is_block_indicator(value: &str) -> bool {
    let v = value.trim_end_matches(|c: char| c.is_ascii_digit());
    matches!(v, "|" | "|-" | "|+" | ">" | ">-" | ">+")
}

/// Line-start forms, YAML block-scalar bodies, k8s name/value pairs, table
/// rows and `.netrc` lines.
fn line_spans(text: &str, names: &mut Names, spans: &mut Vec<Span>) {
    // The key line's indent while inside a secret-named block scalar, and the
    // body masked so far: the whole body is ONE span (one mask, not a mask per
    // line — a 5 MB block would otherwise balloon the output).
    let mut block: Option<usize> = None;
    let mut body: Option<(usize, usize)> = None;
    // Lines left in which a `value:` belongs to a secret `name:` just seen,
    // and that name's strength.
    let mut pending_value = 0u8;
    let mut pending_strength = Strength::Strong;
    // A `.netrc` `machine`/`default` block or a vault `Key  Value` table has
    // been seen: bare `password x` rows there are credentials, not prose.
    let mut table_context = false;
    let mut line_start = 0;
    for raw in text.split_inclusive('\n') {
        let start = line_start;
        line_start += raw.len();
        let line = raw.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(key_indent) = block {
            if line.trim().is_empty() {
                continue;
            }
            let indent = leading_indent(line);
            if indent > key_indent {
                let end = start + line.trim_end().len();
                body = Some(body.map_or((start + indent, end), |(s, _)| (s, end)));
                continue;
            }
            block = None;
            if let Some((s, e)) = body.take() {
                spans.push(named(s, e));
            }
        }
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let first_word = trimmed.split_whitespace().next().unwrap_or("");
        let netrc = matches!(first_word, "machine" | "default");
        if netrc || (first_word == "Key" && trimmed.contains("Value")) {
            table_context = true;
        }
        if pending_value > 0 {
            pending_value -= 1;
            if let Some(head) = K8S_VALUE.find(line) {
                let value = line[head.end()..].trim_end();
                let (vs, ve) = unquote(head.end(), value);
                if value_masks(pending_strength, &line[vs..ve], false) {
                    spans.push(named(start + vs, start + ve));
                }
                pending_value = 0;
                continue;
            }
        }
        if (trimmed.starts_with("name:") || trimmed.starts_with("- name:"))
            && let Some(caps) = K8S_NAME.captures(line)
        {
            match caps.get(1).and_then(|n| names.get(n.as_str())) {
                Some(strength) => {
                    pending_value = 3;
                    pending_strength = strength;
                }
                None => pending_value = 0,
            }
            continue;
        }
        if netrc
            && let Some(caps) = NETRC_PASSWORD.captures(line)
            && let Some(value) = caps.get(1)
        {
            spans.push(named(start + value.start(), start + value.end()));
        }
        let Some(head) = LINE_HEAD.find(line) else {
            row_span(line, start, table_context, names, spans);
            continue;
        };
        let sep = &line[head.end() - 1..head.end()];
        let rest = &line[head.end()..];
        if sep == "=" && rest.starts_with('=') {
            continue; // `a == b`
        }
        // `token.c:12:5: warning …`, `secrets.yaml:4: …` — a diagnostic's
        // `path:line:` prefix, not a name/value pair.
        if sep == ":" && rest.starts_with(|c: char| c.is_ascii_digit()) {
            let digits = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            if digits.starts_with(':') {
                continue;
            }
        }
        if rest.starts_with("//") {
            continue; // `https://…`
        }
        let Some(strength) = names.get(tail_name(&line[..head.end() - 1])) else {
            continue;
        };
        let lead = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let value_start = head.end() + lead;
        let value = line[value_start..].trim_end();
        if value.is_empty() {
            continue;
        }
        if sep == ":" && is_block_indicator(value) {
            block = Some(leading_indent(line));
            continue;
        }
        let (vs, ve) = unquote(value_start, value);
        let quoted = vs != value_start;
        // `token = get_token(request)` — a spaced `=` (source code, not an env
        // line) whose value is a call, attribute path or `await …` expression.
        let spaced = sep == "=" && line[..head.end() - 1].ends_with([' ', '\t']);
        let code = spaced && !quoted && is_code_expression(&line[vs..ve]);
        let masks = if code {
            false
        } else if sep == ":" && !quoted {
            value_masks(strength, &line[vs..ve], true)
        } else {
            value_masks(strength, &line[vs..ve], false)
        };
        if masks {
            spans.push(named(start + vs, start + ve));
        }
    }
    if let Some((s, e)) = body {
        spans.push(named(s, e));
    }
}

/// A `name  value` row: only for STRONG names, and only where it reads as a
/// table (indented, two+ spaces apart, or inside a `.netrc`/vault table) —
/// `Token expired` at the start of a line is prose.
fn row_span(line: &str, start: usize, table: bool, names: &mut Names, spans: &mut Vec<Span>) {
    // Classify the first word before running the row regex: almost every
    // line's first word is not a secret name, and the regex is the cost.
    let first = line
        .trim_start_matches([' ', '\t'])
        .split([' ', '\t'])
        .next()
        .unwrap_or("");
    if !matches!(names.get(first), Some(Strength::Strong | Strength::Counter)) {
        return;
    }
    let Some(caps) = WS_ROW.captures(line) else {
        return;
    };
    let (Some(indent), Some(name), Some(gap), Some(value)) =
        (caps.get(1), caps.get(2), caps.get(3), caps.get(4))
    else {
        return;
    };
    // One word: an indented row counts too (`  password x` in a `.netrc`).
    // Several words: only a real table (two+ spaces apart, or a `.netrc`/vault
    // table seen above) — indented prose keeps its words.
    // A value holding its own two-space gap is more columns (`kubectl get`
    // output), not one value.
    if value.as_str().contains("  ") || value.as_str().contains('\t') {
        return;
    }
    // `requirepass x` (redis), `rootpw x` (slapd): directive names, not prose.
    let directive = matches!(name.as_str(), "requirepass" | "masterauth" | "rootpw");
    let wide = gap.as_str().len() >= 2 || table || directive;
    let tabular = if value.as_str().contains([' ', '\t']) {
        wide
    } else {
        wide || !indent.as_str().is_empty()
    };
    let strength = names.get(name.as_str());
    if tabular
        && matches!(strength, Some(Strength::Strong | Strength::Counter))
        && !(strength == Some(Strength::Counter) && is_count(value.as_str()))
        && maskable(value.as_str())
        && !PROSE_VALUES.contains(&value.as_str().to_ascii_lowercase().as_str())
    {
        spans.push(named(start + value.start(), start + value.end()));
    }
}

/// Right-hand side of a spaced source-code assignment: a call
/// (`get_token(request)`, `std::env::var("X")?;`), an attribute or subscript
/// path (`request.form['password']`), or `await`/`new` expression.
fn is_code_expression(value: &str) -> bool {
    let v = value.trim().trim_end_matches(';');
    let ident_start = v.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    let call = ident_start
        && v.split_once('(').is_some_and(|(callee, _)| {
            callee
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':'))
        })
        && v.trim_end_matches(['?', '!']).ends_with(')');
    let path = ident_start
        && !v.contains(' ')
        && v.contains(['.', '['])
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '[' | ']' | '\'' | '"'));
    call || path || v.starts_with("await ") || v.starts_with("new ")
}

/// The span of `value` (which starts at `at`) to mask: inside its quotes when
/// quoted (to the end when the quote never closes), else the whole value.
fn unquote(at: usize, value: &str) -> (usize, usize) {
    match value.chars().next() {
        Some(q @ ('"' | '\'')) => {
            let inner = &value[1..];
            (
                at + 1,
                at + 1 + closing_quote(inner, q).unwrap_or(inner.len()),
            )
        }
        _ => (at, at + value.len()),
    }
}

/// Byte offset of the quote closing `inner` (the text after an opening `q`).
/// Backslash escapes inside double quotes; a doubled `''` inside single quotes
/// (YAML) is a literal quote, not the close.
fn closing_quote(inner: &str, q: char) -> Option<usize> {
    let mut chars = inner.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '\\' && q == '"' {
            chars.next();
        } else if c == q {
            if q == '\'' && chars.peek().is_some_and(|&(_, n)| n == '\'') {
                chars.next();
                continue;
            }
            return Some(i);
        }
    }
    None
}

/// A last segment that makes the name describe the secret rather than hold it.
const METADATA_SUFFIXES: &[&str] = &[
    "url",
    "uri",
    "urls",
    "domain",
    "sock",
    "socket",
    "helper",
    "header",
    "id",
    "ids",
    "name",
    "names",
    "type",
    "types",
    "kind",
    "endpoint",
    "host",
    "hostname",
    "port",
    "path",
    "file",
    "filename",
    "dir",
    "directory",
    "arn",
    "region",
    "env",
    "var",
    "ref",
    "source",
    "provider",
    "method",
    "mode",
    "scheme",
    "algorithm",
    "alg",
    "format",
    "length",
    "len",
    "size",
    "min",
    "max",
    "count",
    "ttl",
    "expiry",
    "expires",
    "expiration",
    "exp",
    "lifetime",
    "timeout",
    "rotation",
    "version",
    "enabled",
    "disabled",
    "required",
    "set",
    "present",
    "exists",
    "hint",
    "policy",
    "label",
    "description",
    "desc",
    "owner",
    "user",
    "username",
    "login",
    "email",
    "account",
    "created",
    "updated",
    "date",
    "time",
    "at",
    "scope",
    "scopes",
    "prefix",
    "suffix",
    "fingerprint",
    "field",
    "fields",
    "location",
    "store",
    "backend",
    "mount",
    "index",
    "pattern",
    "regex",
    "strength",
    "status",
    "state",
    "usage",
    "used",
    "limit",
    "budget",
    "rate",
    "manager",
    "vault",
];

/// Qualifiers that make a `…_key` name a non-secret key.
const NON_SECRET_KEY_QUALIFIERS: &[&str] = &[
    "primary",
    "foreign",
    "sort",
    "partition",
    "public",
    "pub",
    "hash",
    "range",
    "cache",
    "idempotency",
    "row",
    "unique",
    "composite",
    "lookup",
    "map",
    "dict",
    "group",
    "shard",
    "object",
    "i18n",
    "translation",
    "hot",
    "dedup",
    "dedupe",
    "routing",
    "index",
    "known",
    "host",
    "trusted",
];

/// Qualifiers that make a `…_token` name a counter, not a credential.
const TOKEN_COUNT_QUALIFIERS: &[&str] = &[
    "max",
    "min",
    "num",
    "input",
    "output",
    "total",
    "prompt",
    "completion",
    "cache",
    "cached",
    "reasoning",
    "context",
];

/// Most segments a name is split into; the rest are ignored (a name is at
/// most [`MAX_NAME`] bytes).
const MAX_SEGMENTS: usize = 32;

/// Byte ranges of `name`'s segments: split on `_`, `-`, `.` and every other
/// non-alphanumeric byte, and on camelCase / acronym / digit boundaries
/// (`APIKey` → `API`, `Key`). Returns how many ranges were written.
fn segment_ranges(name: &[u8], out: &mut [(usize, usize); MAX_SEGMENTS]) -> usize {
    let mut n = 0;
    let mut push = |a: usize, b: usize, n: &mut usize| {
        if *n < MAX_SEGMENTS && a < b {
            out[*n] = (a, b);
            *n += 1;
        }
    };
    let mut seg_start = 0;
    for i in 0..name.len() {
        let c = name[i];
        if !c.is_ascii_alphanumeric() {
            push(seg_start, i, &mut n);
            seg_start = i + 1;
            continue;
        }
        if i == seg_start {
            continue;
        }
        let p = name[i - 1];
        let next = name.get(i + 1).copied();
        let boundary = if c.is_ascii_uppercase() {
            p.is_ascii_lowercase()
                || p.is_ascii_digit()
                || (p.is_ascii_uppercase() && next.is_some_and(|x| x.is_ascii_lowercase()))
        } else if c.is_ascii_digit() {
            !p.is_ascii_digit()
        } else {
            p.is_ascii_digit()
        };
        if boundary {
            push(seg_start, i, &mut n);
            seg_start = i;
        }
    }
    push(seg_start, name.len(), &mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every fake credential is built by concatenation so no scanner (this
    // repo's own guards included) sees a whole token literal. None is real.
    fn alnum(n: usize) -> String {
        "aB3dE5gH7jK9mN1pQ2sT4vW6yZ8cF0hL"
            .chars()
            .cycle()
            .take(n)
            .collect()
    }
    fn ghp() -> String {
        ["gh", "p_"].concat() + &alnum(36)
    }
    fn akia() -> String {
        ["AK", "IA"].concat() + "QWERTYUIOP123456"
    }
    /// A made-up password canary.
    fn pw() -> String {
        ["Zq", "9vK", "hunter", "7Xw"].concat()
    }
    fn body() -> String {
        ["MIIEpAIBAAKC", "AQEA"].concat() + &alnum(48)
    }
    fn begin(kind: &str) -> String {
        format!("-----BEGIN {kind}-----")
    }
    fn end(kind: &str) -> String {
        format!("-----END {kind}-----")
    }
    const RSA: &str = "RSA PRIVATE KEY";

    fn masked(text: &str) -> String {
        redact(text).unwrap_or_else(|| text.to_string())
    }

    /// Each input carries one of the canaries; none may survive. Includes
    /// every Gate 2 (#776 review) repro that leaked on b58b283.
    #[test]
    fn no_canary_survives() {
        let (p, g, a, b) = (pw(), ghp(), akia(), body());
        let glpat = ["gl", "pat-"].concat() + &alnum(20);
        let npm = ["np", "m_"].concat() + &alnum(36);
        let jwt =
            ["ey", "JhbGciOiJIUzI1NiJ9."].concat() + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + &alnum(43);
        let cases: Vec<(String, Vec<String>)> = vec![
            // Critical 1 + Important 1: escapes, ANSI, %XX before a token.
            (format!(r#"{{"log":"line1\n{g}\n"}}"#), vec![g.clone()]),
            (format!(r#"{{"log":"k\t{a}"}}"#), vec![a.clone()]),
            (
                format!(
                    r#"{{"pem":"{}\n{}\n{b}\n{}\n"}}"#,
                    end("CERTIFICATE"),
                    begin(RSA),
                    end(RSA)
                ),
                vec![b.clone()],
            ),
            (
                format!("\x1b[01;31m\x1b[K{g}\x1b[m\x1b[K\n"),
                vec![g.clone()],
            ),
            (format!("\x1b[1;31m{a}\x1b[0m\n"), vec![a.clone()]),
            (format!("gh\x1b[1mp_{}\n", alnum(36)), vec![alnum(36)]),
            (format!("https://x/?q=token%3D{g}\n"), vec![g.clone()]),
            (format!("abc{g}\n"), vec![g.clone()]),
            // Critical 2: URL credentials.
            (
                format!("DATABASE_URL=postgres://app:{p}@db:5432/app\n"),
                vec![p.clone()],
            ),
            (
                format!("redis_url: redis://:{p}@cache:6379\n"),
                vec![p.clone()],
            ),
            (
                format!("remote.origin.url=https://u:{p}@github.com/x.git\n"),
                vec![p.clone()],
            ),
            (
                format!("Cloning https://oauth2:{p}@gitlab.com/x\n"),
                vec![p.clone()],
            ),
            // Critical 3: unquoted values with code-looking characters.
            (format!("DB_PASSWORD={p}(x\n"), vec![p.clone()]),
            (format!("DB_PASSWORD={p}{{\n"), vec![p.clone()]),
            (format!("API_TOKEN=ab]{p}\n"), vec![p.clone()]),
            (format!("DB_PASSWORD={p},\n"), vec![p.clone()]),
            (format!("DB_PASSWORD={p};\n"), vec![p.clone()]),
            (format!("DB_PASSWORD=${p}\n"), vec![p.clone()]),
            (
                "DB_PASSWORD=Horse.battery.staple\n".into(),
                vec!["Horse.battery".into()],
            ),
            ("PIN_PASSWORD=482913\n".into(), vec!["482913".into()]),
            (format!("DB_PASSWORD={p} tail\n"), vec![p.clone()]),
            // Critical 4: PEM/PGP shapes.
            (
                format!(
                    "{}\nVersion: GnuPG v2\nComment: my key\n\n{b}\n=abcd\n{}\n",
                    begin("PGP PRIVATE KEY BLOCK"),
                    end("PGP PRIVATE KEY BLOCK")
                ),
                vec![b.clone()],
            ),
            (
                format!("{}\n\n{b}\n{b}\n", begin("PGP PRIVATE KEY BLOCK")),
                vec![b.clone()],
            ),
            (format!("{}\n\n{b}\n", begin(RSA)), vec![b.clone()]),
            (
                format!("\x1b[32m{}\n{b}\n{}\x1b[0m\n", begin(RSA), end(RSA)),
                vec![b.clone()],
            ),
            (
                format!("{}\n\x1b[32m{b}\x1b[0m\n{}\n", begin(RSA), end(RSA)),
                vec![b.clone()],
            ),
            (format!("{b}\n{}\n", end(RSA)), vec![b.clone()]),
            (
                format!("key: |\n  {}\n  {b}\n  {}\n", begin(RSA), end(RSA)),
                vec![b.clone()],
            ),
            // Important 3: GitLab, npm, JWT.
            (format!("value: {glpat}\n"), vec![glpat.clone()]),
            (format!("value: {npm}\n"), vec![npm.clone()]),
            (format!("value: {jwt}\n"), vec![alnum(43)]),
            // Important 4: name/value pairs and other named forms.
            (
                format!("env:\n- name: DB_PASSWORD\n  value: {p}\n"),
                vec![p.clone()],
            ),
            (
                format!(r#"{{"name": "DB_PASSWORD", "value": "{p}"}}"#),
                vec![p.clone()],
            ),
            (
                format!(
                    "====== Data ======\nKey         Value\n---         -----\npassword    {p}\n"
                ),
                vec![p.clone()],
            ),
            (
                format!("data:\n  .dockerconfigjson: {p}\n  tls.key: {p}\n"),
                vec![p.clone()],
            ),
            (format!("machine h login u password {p}\n"), vec![p.clone()]),
            (
                format!("machine h\n  login u\n  password {p}\n"),
                vec![p.clone()],
            ),
            (format!("Cookie: session={p}\n"), vec![p.clone()]),
            (format!("Set-Cookie: sid={p}; Path=/\n"), vec![p.clone()]),
            (format!("mysql -u root --password={p}\n"), vec![p.clone()]),
            (format!("vault login --token {p}\n"), vec![p.clone()]),
            (
                format!("+ curl -H 'Authorization: token {p}' https://x\n"),
                vec![p.clone()],
            ),
            (format!("password:{p}\n"), vec![p.clone()]),
            (
                format!("[http]\n\textraheader = AUTHORIZATION: basic {p}\n"),
                vec![p.clone()],
            ),
            (
                format!("{}{} token={p} x\n", "x".repeat(1000), " "),
                vec![p.clone()],
            ),
            // Important 5: nested escapes and doubled quotes.
            (
                format!(r#"{{"cfg":"{{\"password\":\"{p}\"}}"}}"#),
                vec![p.clone()],
            ),
            (format!("password: 'it''s{p}'\n"), vec![p.clone()]),
            (
                r#"{"password": 12345678901}"#.into(),
                vec!["12345678901".into()],
            ),
            // The original incidents and basics.
            (format!("unifi:\n  unifi_api_key: {p}\n"), vec![p.clone()]),
            (format!("HOMEPAGE_VAR_UNIFI_KEY={p}\n"), vec![p.clone()]),
            (format!(r#"["HOME=/x","API_TOKEN={p}"]"#), vec![p.clone()]),
            (format!("> Authorization: Bearer {p}\n"), vec![p.clone()]),
            (format!("DB_PASSWORD={p}\r\nX=1\r\n"), vec![p.clone()]),
            (
                format!("data:\n  password: |\n    {p}\n    line2\n"),
                vec![p.clone()],
            ),
            (format!("      + token    = \"{p}\"\n"), vec![p.clone()]),
        ];
        // Round 2 (#776 review 2): strong names mask short, plain-word,
        // numeric, spaced and table-row values in every form.
        let pw = ["pass", "word"].concat();
        let round2: &[(&str, &str)] = &[
            ("{pw}: hunter2\n", "hunter2"),
            ("{pw}: correcthorse\n", "correcthorse"),
            ("{pw}: Hunter\n", "Hunter"),
            ("{pw}: correct horse battery staple\n", "horse"),
            ("{pw}: my_db_pass_x\n", "my_db_pass_x"),
            ("{pw}: Hunter.Twoz\n", "Hunter.Twoz"),
            ("api_key: abc123\n", "abc123"),
            ("secret: s3cr3t\n", "s3cr3t"),
            ("    POSTGRES_PASSWORD: postgres\n", "postgres"),
            ("      - POSTGRES_PASSWORD=postgres\n", "postgres"),
            ("  MYSQL_ROOT_PASSWORD: rootpass99\n", "rootpass99"),
            ("DB_PASSWORD=correct horse battery staple\n", "staple"),
            ("PASSWORD=short\n", "short"),
            ("x=1 DB_PASSWORD=correct horse battery\n", "horse"),
            ("run: DB_PASSWORD=hunter2 ./app\n", "hunter2"),
            ("machine h\n  login u\n  {pw} x\n", "{pw} x"),
            ("machine h\n  login u\n  {pw} hunter2\n", "hunter2"),
            ("Key      Value\n---      -----\n{pw} hunter2\n", "hunter2"),
            (
                "Key      Value\n---      -----\n{pw}    swordfishes\n",
                "swordfishes",
            ),
            ("{pw}    correct horse battery\n", "horse"),
            ("{pw}:hunter2\n", "hunter2"),
            ("{pw} = hunter2\n", "hunter2"),
            ("X-Api-Key: abc123\n", "abc123"),
            ("X-Auth-Token: abc123def\n", "abc123def"),
            ("user: bob, {pw}: hunter2\n", "hunter2"),
            ("- name: DB_PASSWORD\n  value: swordfish\n", "swordfish"),
            ("token: abcdefghijkl\n", "abcdefghijkl"),
            ("github.com:\n    oauth_token: abcdefgh12\n", "abcdefgh12"),
            ("{pw}: 12h30m5s\n", "12h30m5s"),
            ("{pw}: 12345678\n", "12345678"),
            ("db_{pw}: 123456\n", "123456"),
            ("client_secret: 20240101\n", "20240101"),
            ("secret_key_base: abcdef\n", "abcdef"),
            ("Set-Cookie: theme=dark; Path=/\n", "dark"),
            // Round 3 (#776 review 3): glued names, directives, Meta values,
            // `.netrc` variants.
            ("PGPASSWORD=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("+ PGPASSWORD=Zq9vKh7wR psql -h db\n", "Zq9vKh7wR"),
            ("[\"PGPASSWORD=Zq9vKh7wR\"]\n", "Zq9vKh7wR"),
            ("DBPASSWORD=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("GITHUBTOKEN=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("CLIENTSECRET=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("masterpassword: Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("MYSQL_PWD=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("requirepass Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("masterauth Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("rootpw Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("pass=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("pw=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("PW: Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("SECRET_TOKEN_URL=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("API_KEY_ENV=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("GITHUB_TOKEN_REF=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("DB_PASSWORD_USER=Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("password_source: Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("default login u password Zq9vKh7wR\n", "Zq9vKh7wR"),
            ("machine\th\tlogin\tu\tpassword\tZq9vKh7wR\n", "Zq9vKh7wR"),
            ("machine h password Zq9vKh7wR\\\n", "Zq9vKh7wR"),
            // Round 4 (#776 review 4).
            (
                "connect(host=db, password=Zq9vKh7wR3xPq)\n",
                "Zq9vKh7wR3xPq",
            ),
            (
                "sqlalchemy.url(postgresql, password=Zq9vKh7wR3xPq)\n",
                "Zq9vKh7wR3xPq",
            ),
            ("INFO (pid 12 token=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            (
                "log: retrying (attempt 2 of 3 password=Zq9vKh7wR3xPq\n",
                "Zq9vKh7wR3xPq",
            ),
            ("DEBUG :( failed; token=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("{'password': 'Zq9vKh7wR3xPq'}\n", "Zq9vKh7wR3xPq"),
            (
                "{'user': 'bob', 'password': 'Zq9vKh7wR3xPq'}\n",
                "Zq9vKh7wR3xPq",
            ),
            (
                "environ({'PATH': '/bin', 'GITHUB_TOKEN': 'Zq9vKh7wR3xPq'})\n",
                "Zq9vKh7wR3xPq",
            ),
            (
                "{'Authorization': 'Bearer Zq9vKh7wR3xPq'}\n",
                "Zq9vKh7wR3xPq",
            ),
            ("[('password', 'Zq9vKh7wR3xPq')]\n", "Zq9vKh7wR3xPq"),
            (
                "os.environ['API_TOKEN'] = 'Zq9vKh7wR3xPq'\n",
                "Zq9vKh7wR3xPq",
            ),
            (":password => \"Zq9vKh7wR3xPq\"\n", "Zq9vKh7wR3xPq"),
            ("{:password=>\"Zq9vKh7wR3xPq\"}\n", "Zq9vKh7wR3xPq"),
            ("+ mysql -uroot -pZq9vKh7wR3xPq -h db\n", "Zq9vKh7wR3xPq"),
            ("+ mysql -u root -p'Zq9vKh7wR3xPq' db\n", "Zq9vKh7wR3xPq"),
            (
                "  502  mysqldump -u root -pZq9vKh7wR3xPq app\n",
                "Zq9vKh7wR3xPq",
            ),
            ("+ curl -u user:Zq9vKh7wR3xPq https://h\n", "Zq9vKh7wR3xPq"),
            (
                "+ docker login -u u -p Zq9vKh7wR3xPq reg\n",
                "Zq9vKh7wR3xPq",
            ),
            ("+ sshpass -p Zq9vKh7wR3xPq ssh h\n", "Zq9vKh7wR3xPq"),
            ("+ redis-cli -h h -a Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("+ smbclient -U user%Zq9vKh7wR3xPq //h/s\n", "Zq9vKh7wR3xPq"),
            ("+ zip -P Zq9vKh7wR3xPq a.zip f\n", "Zq9vKh7wR3xPq"),
            ("+ 7z a -pZq9vKh7wR3xPq a.7z f\n", "Zq9vKh7wR3xPq"),
            (
                "001f: Authorization: Bearer Zq9vKh7wR3xPq\n",
                "Zq9vKh7wR3xPq",
            ),
            (
                "=> Send header: Authorization: Bearer Zq9vKh7wR3xPq\n",
                "Zq9vKh7wR3xPq",
            ),
            ("HFTOKEN=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("VAULTTOKEN: Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("MYTOKEN=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("XSRFTOKEN=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("MASTERKEY=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("SSHKEY: Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("DBPASS=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            // Round 5 (#776 review 5).
            ("OPENAIAPIKEY=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("{\"openaiapikey\": \"Zq9vKh7wR3xPq\"}\n", "Zq9vKh7wR3xPq"),
            ("AWSSECRETKEY: Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("GCPPRIVATEKEY=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            (
                "ya29.a0AfB_byFAKEc9Zq9vKh7wR3xPqL8mN2abcdEFGH\n",
                "Zq9vKh7wR3xPq",
            ),
            ("ya29.c.b0AaekZq9vKh7wR3xPqL8mN2abcd\n", "Zq9vKh7wR3xPq"),
            (
                "{\"access_token\": \"ya29.a0Zq9vKh7wR3xPqL8mN2abcd\"}\n",
                "Zq9vKh7wR3xPq",
            ),
            (
                "//registry.npmjs.org/:_authToken=aaaa1111-Zq9vKh7wR3xPq\n",
                "Zq9vKh7wR3xPq",
            ),
            ("//reg.example.com/:_auth=Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            (
                "//reg.example.com/:_password=Zq9vKh7wR3xPq\n",
                "Zq9vKh7wR3xPq",
            ),
            ("+ curl -su user:Zq9vKh7wR3xPq x\n", "Zq9vKh7wR3xPq"),
            ("+ curl -fsSu user:Zq9vKh7wR3xPq x\n", "Zq9vKh7wR3xPq"),
            ("+ mongosh -u u -p Zq9vKh7wR3xPq db\n", "Zq9vKh7wR3xPq"),
            ("+ docker login -up Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("+ docker login -u u -p=Zq9vKh7wR3xPq r\n", "Zq9vKh7wR3xPq"),
            ("+ unzip -P Zq9vKh7wR3xPq a.zip\n", "Zq9vKh7wR3xPq"),
            ("+ keytool -storepass Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("+ lftp -u u,Zq9vKh7wR3xPq h\n", "Zq9vKh7wR3xPq"),
            ("ngrok authtoken Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
            ("+ htpasswd -b f user Zq9vKh7wR3xPq\n", "Zq9vKh7wR3xPq"),
        ];
        let mut cases = cases;
        for (input, canary) in round2 {
            cases.push((
                input.replace("{pw}", &pw),
                vec![canary.replace("{pw}", &pw)],
            ));
        }
        for (input, canaries) in &cases {
            let out = masked(input);
            for c in canaries {
                assert!(
                    !out.contains(c.as_str()),
                    "canary survived in {input:?}: {out:?}"
                );
            }
        }
    }

    #[test]
    fn exact_masking_keeps_every_other_byte() {
        let p = pw();
        let m = NAMED_MARK;
        let cases: Vec<(String, String)> = vec![
            (
                format!("unifi:\n  unifi_api_key: {p}\n  unifi_host: 10.0.0.1\n"),
                format!("unifi:\n  unifi_api_key: {m}\n  unifi_host: 10.0.0.1\n"),
            ),
            (
                format!("HOMEPAGE_ALLOWED_HOSTS=home.lan\nHOMEPAGE_VAR_UNIFI_KEY={p}\n"),
                format!("HOMEPAGE_ALLOWED_HOSTS=home.lan\nHOMEPAGE_VAR_UNIFI_KEY={m}\n"),
            ),
            (
                format!(r#"["HOMEPAGE_ALLOWED_HOSTS=home.lan","HOMEPAGE_VAR_UNIFI_KEY={p}"]"#),
                format!(r#"["HOMEPAGE_ALLOWED_HOSTS=home.lan","HOMEPAGE_VAR_UNIFI_KEY={m}"]"#),
            ),
            (
                format!("héllo ✓\nDB_PASSWORD=ü{p}✓\nfin ✓\n"),
                format!("héllo ✓\nDB_PASSWORD={m}\nfin ✓\n"),
            ),
            (
                format!("DATABASE_URL=postgres://app:{p}@db/app\n"),
                "DATABASE_URL=postgres://app:[redacted: URL password]@db/app\n".to_string(),
            ),
            (
                format!("before\n{}\n{}\n{}\nafter\n", begin(RSA), body(), end(RSA)),
                "before\n[redacted: private key]\nafter\n".to_string(),
            ),
            (
                format!("x\x1b[31m{}\x1b[0m y\n", ghp()),
                "x\x1b[31m[redacted: GitHub token]\x1b[0m y\n".to_string(),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(masked(&input), want, "{input:?}");
        }
    }

    /// Everyday output that must come through with ZERO masks: test runners
    /// (whose PASS/FAIL lines are the result the model needs), build tools,
    /// git over ordinary code that names `password`/`token`, cluster and file
    /// listings, and error prose.
    #[test]
    fn false_positive_corpus_is_untouched() {
        let corpus: &[&str] = &[
            // go test -v
            "=== RUN   TestFoo\n--- PASS: TestFoo (0.00s)\n=== RUN   TestTokenRefresh\n--- FAIL: TestTokenRefresh (0.01s)\n    auth_test.go:42: token expired\nPASS\nFAIL\nok  \tgithub.com/acme/pkg\t0.123s\nFAIL\tgithub.com/acme/auth\t0.456s\n",
            // cargo test
            "running 3 tests\ntest auth::tests::token_roundtrip ... ok\ntest auth::tests::password_hash ... FAILED\n\ntest result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
            // pytest -v
            "tests/test_auth.py::test_token_refresh PASSED                  [ 50%]\ntests/test_auth.py::test_password_reset FAILED                 [100%]\nE   AssertionError: password must be 8 characters\n=========== 1 failed, 1 passed in 0.12s ===========\n",
            // jest / vitest / npm test
            " PASS  src/auth.test.ts\n  ✓ refreshes the token (5 ms)\n FAIL  src/password.test.ts\n  ✕ rejects a short password (3 ms)\nTests:       1 failed, 1 passed, 2 total\nTime:        1.234 s\n",
            " ✓ src/token.test.ts (3 tests) 12ms\n Test Files  1 passed (1)\n      Tests  3 passed (3)\n   Duration  512ms\n",
            "> acme@1.0.0 test\n> vitest run\n\nnpm ERR! Test failed.  See above for more details.\n",
            // make
            "make: Entering directory '/src/app'\ncc -O2 -c token.c -o token.o\nmake: *** [Makefile:12: all] Error 1\n",
            // automake
            "PASS: test_foo\nFAIL: test_bar\nPASS: test_baz\n# PASS:  2\n# FAIL:  1\n",
            // git log / status / diff of ordinary code
            "commit 3f786850e387550fdab836ed7e6dc881de23001b\nAuthor: Dev <dev@example.com>\nDate:   Tue Sep 30 12:00:00 2026 +0000\n\n    fix: token refresh after password change\n\n    auth: handle expired token\n",
            "On branch main\nChanges not staged for commit:\n\tmodified:   src/auth/token.rs\n\tmodified:   src/auth/password.rs\n",
            "diff --git a/src/auth.rs b/src/auth.rs\n@@ -1,6 +1,8 @@\n-    let token = get_token();\n+    let token = get_token()?;\n+    if password.is_empty() {\n+        return Err(Error::InvalidPassword);\n+    }\n     max_tokens: 4096,\n+    token_count=12\n+    pub password: String,\n+    token: Option<String>,\n+    password: &str,\n+    auth: AuthConfig,\n",
            "max_tokens: 4096\ntoken_count=12\ntoken_type: bearer\npassword_min_length: 8\n",
            // docker ps / kubectl get pods / ls -l
            "CONTAINER ID   IMAGE          COMMAND       CREATED       STATUS       PORTS     NAMES\n3f786850e387   nginx:1.27     \"nginx -g…\"   2 hours ago   Up 2 hours   80/tcp    web\n",
            "NAME                    READY   STATUS    RESTARTS   AGE\ntoken-service-7d9f8     1/1     Running   0          3d\n",
            "-rw-r--r--  1 dev staff  1234 Sep 30 12:00 token.rs\ndrwxr-xr-x  3 dev staff    96 Sep 30 12:00 password\n",
            // error prose
            "Error: Token expired\nInvalid password\npassword must be 8 characters\nToken expired\nauth: permission denied\ntoken: expired\npassword: required\n",
            "PASS: hunter2x9\nFAIL: other\nOK: fine\n",
            // Round 2 (#776 review 2) false positives.
            "  + password              = (sensitive value)\n  + manage_master_user_password = true\ndb_password = <sensitive>\napi_token = (sensitive value)\n",
            "TOKEN_URL=https://auth.example.com/oauth/token\nAUTH_DOMAIN=auth.example.com\nSSH_AUTH_SOCK=/private/tmp/com.apple.launchd.abc/Listeners\nKEYCHAIN_PATH=/Users/dev/Library/Keychains/login.keychain-db\nPASSWORD_STORE_DIR=/Users/dev/.password-store\nKEY_FILE=/etc/ssl/key.pem\nSECRET_NAME=prod/api\nCREDENTIALS_FILE=/Users/dev/.aws/credentials\nKEY_ID=abcd1234\nTOKENIZERS_PARALLELISM=false\nGIT_ASKPASS=/usr/local/bin/askpass\n",
            "remote.origin.url=https://github.com/acme/app.git\ncredential.helper=osxkeychain\nuser.signingkey=ABCDEF1234567890\n",
            "Use header Authorization: Bearer <token>\nkey: value\n",
            "  - Token: gho_************************************\n  - Token scopes: 'gist', 'read:org', 'repo'\n",
            "Config { host: \"db\", port: 5432, password: \"<hidden>\", token_ttl: 3600 }\n",
            // Round 3 (#776 review 3) false positives.
            "jsonwebtoken  <=8.5.1\nSeverity: high\n",
            "make[1]: Entering directory '/src/tokens'\ntoken.c:12:5: warning: implicit declaration of function 'tokenize'\n",
            "secrets.yaml:4: bad indentation\npassword.py:3:import bcrypt\n./token.go:10:2: undefined: foo\n",
            "main.go:5: token: invalid character\nError: password: must be at least 8 characters\nerror: token: unexpected EOF while parsing\nValueError: secret_key: must be 32 bytes\n",
            "Client(api_key=api_key, token=self.token, password=None)\n",
            "def login(user, password=password_default):\n",
            "    token = get_token(request)\nconst token = await getToken();\n    password = request.form['password']\n",
            "src/config.ts:12:  password: process.env.DB_PASSWORD,\nsrc/config.ts:13:  token: config.get('token'),\n",
            "  password: string | undefined;\n",
            "auth:\n  existingSecret: pg-auth\n  secretKeys:\n    adminPasswordKey: postgres-password\n    userPasswordKey: password\n",
            "  -H 'Authorization: Bearer $TOKEN'\n  -H \"Authorization: Bearer ${TOKEN}\"\n",
            "PWD=/home/dev/app\nOLDPWD=/home/dev\n",
            "TOKEN_URL=https://auth.example.com/oauth/token\nSECRET_NAME=prod/api\n",
            "jsonwebtoken=9.0.2\ncancellationtoken: x\ntokenizer=fast\nmaxtokens: 4096\n",
            "hotkey=ctrl-k\nmonkey=banana\nbypass=true\ncompass=north\nsortkey=name\n",
            "GIT_ASKPASS=/usr/local/bin/askpass\nSSH_ASKPASS=/usr/bin/ssh-askpass\nuser.signingkey=ABCDEF1234567890\n",
            "mysql -uroot -P 3306 -p -h db\npsql -h db -p 5432 -U app\n",
            "curl -u admin:$ADMIN_PASSWORD https://x\n",
            "//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}\nmonkey=1\nturnkey=yes\n",
            "apiVersion: v1\nkind: ConfigMap\ndata:\n  token_ttl: 1h\n  auth_mode: oidc\n  key_rotation: enabled\n  password_policy: strong\n",
            "  with:\n    token: ***\n    persist-credentials: false\n",
            "properties:\n  password:\n    type: string\n    minLength: 8\n",
            "12 |     let token: String = get_token();\n   |              ------   ^^^^ expected `String`\n",
        ];
        for input in corpus {
            assert_eq!(redact(input), None, "masked something in {input:?}");
        }
    }

    /// cameronsjo/cadence-hooks#1274's false-positive subset: pagination and
    /// idempotency handles, MySQL's 1045 message, and glued `…pass` words that
    /// are not credentials. The neighbouring credential shapes still mask.
    #[test]
    fn issue_1274_false_positives_pass_through() {
        let handle = alnum(40);
        let kept = [
            format!("{{\"NextToken\": \"{handle}\"}}\n"),
            format!("{{\"nextToken\": \"{handle}\"}}\n"),
            format!("NextToken: {handle}\n"),
            format!("{{\"next_page_token\": \"{handle}\"}}\n"),
            format!("{{\"ClientToken\": \"{handle}\"}}\n"),
            format!("{{\"IdempotencyToken\": \"{handle}\"}}\n"),
            "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)\n"
                .to_string(),
            "ERROR 1045 (28000): Access denied for user 'app'@'10.0.0.5' (using password: NO)\n"
                .to_string(),
            "lastpass=1696500000\nendpass=42\n".to_string(),
            "HASHPASS: 12\n".to_string(),
            "{\"lastpass\": 1696500000}\n".to_string(),
        ];
        for input in &kept {
            assert_eq!(redact(input), None, "{input:?}");
        }
        let p = pw();
        let masks = [
            format!("{{\"client_token\": \"{p}\"}}\n"),
            format!("{{\"SessionToken\": \"{p}\"}}\n"),
            format!("{{\"AccessToken\": \"{p}\"}}\n"),
            format!("{{\"ClientSecret\": \"{p}\"}}\n"),
            format!("ClientTokenSecret={p}\n"),
            format!("NEXT_TOKEN_SECRET={p}\n"),
            format!("password: {p}\n"),
            format!("password: NO{p}\n"),
            "{\"password\": \"yes\"}\n".to_string(),
            format!("mypass={p}\n"),
            format!("PGPASSWORD={p}\n"),
            // Only the issue's names and spellings are exempt.
            format!("KEY_TOKEN={p}\n"),
            format!("SYNC_TOKEN={p}\n"),
            format!("RESUME_TOKEN={p}\n"),
            format!("CONTINUATION_TOKEN={p}\n"),
            format!("{{\"keyToken\": \"{p}\"}}\n"),
            // A counter stem exempts only a value of digits.
            format!("LASTPASS={p}\n"),
            format!("HASHPASS={p}\n"),
            format!("lastpass: {p}\n"),
            format!("{{\"hashpass\": \"{p}\"}}\n"),
            format!("endpass={p}\n"),
            "LASTPASS=12ab34cd\n".to_string(),
        ];
        for input in &masks {
            assert_ne!(redact(input), None, "{input:?} was not masked");
        }
    }

    #[test]
    fn values_that_cannot_be_secrets_pass_through() {
        let cases: &[&str] = &[
            "",
            "hello world\n",
            "HOMEPAGE_ALLOWED_HOSTS=home.lan\n",
            "GITHUB_TOKEN=\n",
            "password: '***'\n",
            "password: [REDACTED]\n",
            "require_auth: true\n",
            "max_tokens: 4096\n",
            "token_type: bearer\n",
            "secretName: my-secret\n",
            r#"{"key": "value", "keys": "x"}"#,
            "commit 3f786850e387550fdab836ed7e6dc881de23001b\n",
            "uuid 123e4567-e89b-12d3-a456-426614174000\n",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI fake@host\n",
            "sk-learn is a library\n",
            "password:\n  nested: map\n",
            "see https://example.com/docs here\n",
            "a == b\n",
        ];
        for input in cases {
            assert_eq!(redact(input), None, "{input:?}");
        }
    }

    #[test]
    fn secret_name_classification() {
        let cases: &[(&str, bool)] = &[
            ("unifi_api_key", true),
            ("HOMEPAGE_VAR_UNIFI_KEY", true),
            ("GITHUB_TOKEN", true),
            ("DB_PASSWORD", true),
            ("password", true),
            ("auth", true),
            ("Authorization", true),
            ("clientSecret", true),
            ("APIKey", true),
            ("spring.datasource.password", true),
            ("API_KEY_2", true),
            ("SECRET_KEY_BASE", true),
            ("Cookie", true),
            ("Set-Cookie", true),
            (".dockerconfigjson", true),
            ("SENTRY_DSN", true),
            ("SECRET_URL", false),
            ("TOKEN_URL", false),
            ("AUTH_DOMAIN", false),
            ("SSH_AUTH_SOCK", false),
            ("credential.helper", false),
            ("HOMEPAGE_ALLOWED_HOSTS", false),
            ("key", false),
            ("primary_key", false),
            ("public_key", false),
            ("KEY_ID", false),
            ("secretName", false),
            ("PASSWORD_FILE", false),
            ("token_type", false),
            ("max_tokens", false),
            ("max_token", false),
            ("monkey", false),
            ("authoritative", false),
            ("", false),
        ];
        // `true`: the name alone makes its value secret (Strong or Weak).
        // `false`: not a secret name, or Meta (the value decides).
        for (name, want) in cases {
            let unconditional =
                matches!(name_strength(name), Some(Strength::Strong | Strength::Weak));
            assert_eq!(unconditional, *want, "{name}");
        }
        // Round 3: strong words glued to a prefix, and whole-name directives.
        for name in [
            "PGPASSWORD",
            "DBPASSWORD",
            "ADMINPASSWORD",
            "masterpassword",
            "GITHUBTOKEN",
            "APITOKEN",
            "AUTHTOKEN",
            "ACCESSTOKEN",
            "CLIENTSECRET",
            "MYSQL_PWD",
            "requirepass",
            "masterauth",
            "rootpw",
            "pass",
            "pw",
            "PW",
        ] {
            assert_eq!(name_strength(name), Some(Strength::Strong), "{name}");
        }
        // Strong name, metadata suffix: the value decides.
        for name in [
            "SECRET_URL",
            "SECRET_TOKEN_URL",
            "API_KEY_ENV",
            "GITHUB_TOKEN_REF",
            "DB_PASSWORD_USER",
            "TOKEN_VAULT",
            "password_source",
            "adminPasswordKey",
            "credential.helper",
        ] {
            assert_eq!(name_strength(name), Some(Strength::Meta), "{name}");
        }
        for name in [
            "PASS",
            "FAIL",
            "OK",
            "PWD",
            "OLDPWD",
            "maxtoken",
            "existingSecret",
        ] {
            assert_eq!(name_strength(name), None, "{name}");
        }
    }

    fn response(stdout: &str, stderr: &str) -> ToolResponse {
        ToolResponse {
            stdout: Some(stdout.to_string()),
            stderr: Some(stderr.to_string()),
            interrupted: Some(false),
            is_image: Some(false),
            ..Default::default()
        }
    }

    #[test]
    fn a_key_split_across_stdout_and_stderr_is_masked_on_both_sides() {
        let b = body();
        let r = decide(
            &response(
                &format!("{}\n{b}\n", begin(RSA)),
                &format!("{b}\n{}\n", end(RSA)),
            ),
            false,
        );
        let out = r.updated_tool_output.expect("rewrite");
        let blob = format!("{}{}", out["stdout"], out["stderr"]);
        assert!(!blob.contains(&b), "{blob}");
    }

    #[test]
    fn decide_emits_full_bash_shape_only_when_masked() {
        let p = pw();
        let r = decide(&response(&format!("DB_PASSWORD={p}\n"), "warn\n"), false);
        let out = r.updated_tool_output.expect("masked output rewrites");
        assert_eq!(
            out,
            serde_json::json!({
                "stdout": format!("DB_PASSWORD={NAMED_MARK}\n"),
                "stderr": "warn\n",
                "interrupted": false,
                "isImage": false,
            })
        );
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow);
        let r = decide(&response("", &format!("password: \"{p}\"\n")), false);
        assert!(r.updated_tool_output.is_some());
        assert!(
            decide(&response("ok\n", ""), false)
                .updated_tool_output
                .is_none()
        );
        let mut img = response(&format!("DB_PASSWORD={p}"), "");
        img.is_image = Some(true);
        assert!(decide(&img, false).updated_tool_output.is_none());
        let r = decide(&response(&format!("DB_PASSWORD={p}\n"), ""), true);
        assert!(r.updated_tool_output.is_none());
        assert_eq!(r.bypass.map(|b| b.mechanism).as_deref(), Some(ESCAPE_ENV));
    }

    #[test]
    fn run_ignores_other_tools_and_missing_response() {
        let p = pw();
        let payload = format!(
            r#"{{"tool_name":"Read","tool_input":{{"command":"x"}},"tool_response":{{"stdout":"DB_PASSWORD={p}","stderr":"","interrupted":false,"isImage":false}}}}"#
        );
        let read = HookInput::from_json(&payload).unwrap();
        assert!(RedactSecretOutput.run(&read).updated_tool_output.is_none());
        let none =
            HookInput::from_json(r#"{"tool_name":"Bash","tool_input":{"command":"x"}}"#).unwrap();
        assert!(RedactSecretOutput.run(&none).updated_tool_output.is_none());
    }

    /// Gate 2's perf corpus at 5 MB. The release bound (0.5 s) is what the hook
    /// deadline needs; debug builds get a loose bound so the test still catches
    /// a quadratic blow-up (which took 27 s in release before the fix).
    #[test]
    fn adversarial_5mb_inputs_stay_linear() {
        const MB: usize = 1_000_000;
        let p = pw();
        let hdr = begin(RSA);
        let bound = if cfg!(debug_assertions) {
            std::time::Duration::from_secs(20)
        } else {
            std::time::Duration::from_millis(500)
        };
        let inputs = [
            format!("{hdr} ").repeat(5 * MB / 32),
            format!("{hdr}\n").repeat(5 * MB / 32),
            format!(
                "{hdr}\n{}",
                format!("{}\n", "A".repeat(63)).repeat(5 * MB / 64)
            ),
            format!("\"password\":\"{p}\",").repeat(5 * MB / 28),
            format!("\"password\":\"{}", "\\a".repeat(5 * MB / 2)),
            format!("DB_PASSWORD={p}\n").repeat(5 * MB / 26),
            format!("\"DB_PASSWORD={p}\",").repeat(5 * MB / 28),
            // Round 2: one trailing backslash must not double the whole scan.
            format!("{}\\", "\"PASSWORD=x".repeat(5 * MB / 11)),
            format!("{}\\", format!("DB_PASSWORD={p}\n").repeat(5 * MB / 26)),
            format!("{}\\", "\"password\":\"x".repeat(5 * MB / 13)),
            format!(
                "{}\\",
                "abcdefghijklmnopqrstuvwxyz_passwor=x\n".repeat(5 * MB / 37)
            ),
            "\"PASSWORD=x\\n".repeat(5 * MB / 13),
            // Round 3: `.netrc` lines ending in a line-continuation backslash.
            "machine h password x\\\n".repeat(5 * MB / 22),
            "machine password x\\\n".repeat(5 * MB / 20),
            "DB_PASSWORD=Zq9vKx7Wm3\\\n".repeat(5 * MB / 22),
            // Round 4: distinct names defeat any per-name memo.
            (0..5 * MB / 14)
                .map(|i| format!("{:06x}token=v\n", i * 2_654_435_761usize % 0xFF_FFFF))
                .collect::<String>(),
            "{'password': 'hunter2x', ".repeat(5 * MB / 26),
            format!("mysql {}", "-px ".repeat(5 * MB / 4)),
            "f(g(h(password=x, ".repeat(5 * MB / 20),
            format!("'Authorization: {p}' ").repeat(5 * MB / 32),
            "token=".repeat(5 * MB / 6),
            "password: ".repeat(5 * MB / 10),
            "--token ".repeat(5 * MB / 8),
            "\"".repeat(5 * MB),
            "\x1b[1m".repeat(5 * MB / 4),
            "\\n".repeat(5 * MB / 2),
            format!(
                "password: |\n{}",
                format!("  {}\n", "x".repeat(60)).repeat(5 * MB / 63)
            ),
            "a:".repeat(5 * MB / 2),
        ];
        for input in inputs {
            let started = std::time::Instant::now();
            let _ = redact(&input);
            let took = started.elapsed();
            assert!(took < bound, "{} bytes took {took:?}", input.len());
        }
    }
}
