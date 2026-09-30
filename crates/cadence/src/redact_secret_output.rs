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
//! **Policy: when unsure, mask — except where the shape is also prose.** A miss
//! leaks a secret that cannot be recalled, so data shapes (`NAME=value`,
//! quoted values, JSON, headers) spare only values that cannot be a secret
//! (empty, `true`/`false`/`null`, already masked). The unquoted `name: value`
//! and `name value` shapes are also how test runners, prose and source code
//! read (`--- PASS: TestFoo (0.00s)`, `Token expired`, `password: String,`), so
//! there the value must look like a credential ([`secret_like`]), and a bare
//! `PASS` is a status word, not a name. A corpus test holds everyday output
//! (test runners, builds, git over code, listings, error prose) at zero masks.
//!
//! **Views.** Every detector runs twice: on the output with ANSI CSI sequences
//! removed (`grep --color`, coloured logs), and — when the output carries a
//! backslash — on a copy with JSON/C escapes decoded (`\n`, `\t`, `\r`, `\"`,
//! `\\`, `\/`), so a key or token inside a JSON string (`kubectl logs`, JSONL,
//! `gh api` bodies, escaped nested JSON) is seen as if printed raw. Each span
//! maps back to the original bytes; the masked range may swallow the colour
//! codes or escapes inside it, never a byte outside it.
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
//!    `Cookie`/`Set-Cookie`/`Authorization`, `.dockerconfigjson` and `auth`
//!    are secret names.
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
//! the output size (a 5 MB adversarial line stays well under the deadline).
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

/// A transformed copy of the output and, per byte of the copy (plus one past
/// the end), the offset in the original it came from.
struct View {
    text: String,
    map: Vec<usize>,
}

impl View {
    /// The output with ANSI CSI sequences (`ESC [ params final`) removed.
    fn strip_ansi(src: &str) -> View {
        let bytes = src.as_bytes();
        let mut text = String::with_capacity(src.len());
        let mut map = Vec::with_capacity(src.len() + 1);
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
        map.push(src.len());
        View { text, map }
    }

    /// This view with JSON/C string escapes decoded, mapped through to the
    /// original.
    fn unescape(&self) -> View {
        let mut text = String::with_capacity(self.text.len());
        let mut map = Vec::with_capacity(self.text.len() + 1);
        let mut chars = self.text.char_indices().peekable();
        while let Some((k, c)) = chars.next() {
            let origin = self.map[k];
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
        map.push(self.map[self.text.len()]);
        View { text, map }
    }
}

/// `text` with every secret value masked, or `None` when nothing was masked
/// (or a span could not be applied safely — fail open to "no change").
pub fn redact(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let mut spans = Vec::new();
    let plain = View::strip_ansi(text);
    collect_mapped(&plain, &mut spans);
    if plain.text.contains('\\') {
        collect_mapped(&plain.unescape(), &mut spans);
    }
    if spans.is_empty() {
        return None;
    }
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
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

/// Run every detector over `view` and map its spans back to the original.
fn collect_mapped(view: &View, spans: &mut Vec<Span>) {
    let mut local = Vec::new();
    let t = view.text.as_str();
    token_spans(t, &mut local);
    url_spans(t, &mut local);
    json_pair_spans(t, &mut local);
    name_value_json_spans(t, &mut local);
    env_string_spans(t, &mut local);
    inline_spans(t, &mut local);
    line_spans(t, &mut local);
    for s in local {
        if s.start >= s.end {
            continue;
        }
        let (Some(&start), Some(&end)) = (view.map.get(s.start), view.map.get(s.end)) else {
            continue;
        };
        if start < end {
            spans.push(Span {
                start,
                end,
                label: s.label,
            });
        }
    }
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
// Secret-named values
// ---------------------------------------------------------------------------

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
    Regex::new(r#""([A-Za-z_.][A-Za-z0-9_.\-]*)=((?:[^"\\\n]|\\.)*)""#)
        .expect("env string regex is valid")
});

/// A mid-line `NAME=` / `--name=` (after a separator, quote or `?`/`&`).
static INLINE_EQ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:^|[\s;|&'"(?,{\[])(?:--?)?([A-Za-z_][A-Za-z0-9_.\-]*)="#)
        .expect("inline eq regex is valid")
});

/// A mid-line `name:` / `Name: ` (after whitespace, a quote or a bracket).
static INLINE_COLON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:^|([\s'"(\[{,]))([A-Za-z_][A-Za-z0-9_.\-]*):[ \t]*"#)
        .expect("inline colon regex is valid")
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
        r#"^[ \t]*(?:[-*>+<][ \t]+)*(?:(?:export|declare[ \t]+-x|set)[ \t]+)?["']?([A-Za-z_.][A-Za-z0-9_.\-]*)["']?[ \t]*([=:])"#,
    )
    .expect("line head regex is valid")
});

/// `name    value` — a table row (vault `kv get`, `.netrc` lines) whose value
/// is one word.
static WS_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*([A-Za-z_.][A-Za-z0-9_.\-]*)[ \t]+(\S+)[ \t]*$")
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

fn secret(name: &str) -> bool {
    name.len() <= MAX_NAME && might_be_secret(name) && is_secret_name(name)
}

/// Cheap substring prefilter for [`is_secret_name`]: every segment it accepts
/// contains one of these, so a name without any is rejected without the
/// segment split (the hot path on long runs of ordinary assignments).
fn might_be_secret(name: &str) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"secret", b"token", b"pass", b"pwd", b"cred", b"key", b"auth", b"cookie", b"docker",
        b"dsn",
    ];
    let lower = name.as_bytes().to_ascii_lowercase();
    NEEDLES
        .iter()
        .any(|n| lower.windows(n.len()).any(|w| w == *n))
}

fn json_pair_spans(text: &str, spans: &mut Vec<Span>) {
    // Each search resumes at the end of the previous VALUE, not of the match,
    // so the quote closing one value can open the next name. Escaped nested
    // JSON (`"{"password":"…"}"` once decoded) would otherwise misalign and
    // hide the pair. Every step moves forward, so this stays linear.
    let mut pos = 0;
    while pos < text.len() {
        let Some(caps) = JSON_PAIR.captures_at(text, pos) else {
            break;
        };
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2).or_else(|| caps.get(3))) else {
            break;
        };
        pos = value.end().max(name.end());
        if secret(name.as_str()) && worth_masking(value.as_str()) {
            spans.push(named(value.start(), value.end()));
        }
    }
}

fn name_value_json_spans(text: &str, spans: &mut Vec<Span>) {
    for caps in NAME_VALUE_JSON.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if secret(name.as_str()) && worth_masking(value.as_str()) {
            spans.push(named(value.start(), value.end()));
        }
    }
}

fn env_string_spans(text: &str, spans: &mut Vec<Span>) {
    for caps in ENV_STRING.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if secret(name.as_str()) && worth_masking(value.as_str()) {
            spans.push(named(value.start(), value.end()));
        }
    }
}

/// End of the line containing `from` (exclusive of `\r\n`/`\n`), cached
/// in `cache` so a run of matches on one long line finds its end once — a
/// fresh search per match is quadratic on a 5 MB single line.
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

/// Mid-line forms: `NAME=value`, `name: value`, `--name value`. Each value is
/// scanned only past the end of the previous masked value, so an adversarial
/// run of `token=token=…` stays linear.
fn inline_spans(text: &str, spans: &mut Vec<Span>) {
    let mut done = 0;
    let mut eol_cache = (usize::MAX, 0);
    for caps in INLINE_EQ.captures_iter(text) {
        let (Some(name), Some(head)) = (caps.get(1), caps.get(0)) else {
            continue;
        };
        let start = head.end();
        if start < done || text[start..].starts_with('=') || !secret(name.as_str()) {
            continue;
        }
        let eol = line_end(text, start, &mut eol_cache);
        let (vs, ve) = match text[start..eol].chars().next() {
            Some(q @ ('"' | '\'')) => {
                let inner = &text[start + 1..eol];
                (
                    start + 1,
                    start + 1 + closing_quote(inner, q).unwrap_or(inner.len()),
                )
            }
            _ => {
                let len = text[start..eol]
                    .find(|c: char| c.is_whitespace() || matches!(c, '&' | '"' | '\''))
                    .unwrap_or(eol - start);
                (start, start + len)
            }
        };
        done = ve.max(start);
        if worth_masking(&text[vs..ve]) {
            spans.push(named(vs, ve));
        }
    }
    done = 0;
    eol_cache = (usize::MAX, 0);
    for caps in INLINE_COLON.captures_iter(text) {
        let (Some(name), Some(head)) = (caps.get(2), caps.get(0)) else {
            continue;
        };
        let start = head.end();
        if start < done || !secret(name.as_str()) {
            continue;
        }
        let eol = line_end(text, start, &mut eol_cache);
        let rest = &text[start..eol];
        if rest.starts_with("//") {
            continue;
        }
        let quote = caps
            .get(1)
            .and_then(|m| m.as_str().chars().next())
            .filter(|c| matches!(c, '"' | '\''));
        let len = match quote {
            Some(q) => closing_quote(rest, q).unwrap_or(rest.len()),
            None => rest.trim_end().len(),
        };
        done = start + len;
        let plausible = if quote.is_some() || is_header_name(name.as_str()) {
            worth_masking(&rest[..len])
        } else {
            secret_like(&rest[..len])
        };
        if plausible {
            spans.push(named(start, start + len));
        }
    }
    for caps in FLAG_SPACE.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if secret(name.as_str()) && worth_masking(value.as_str()) {
            spans.push(named(value.start(), value.end()));
        }
    }
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
fn line_spans(text: &str, spans: &mut Vec<Span>) {
    // The key line's indent while inside a secret-named block scalar.
    let mut block: Option<usize> = None;
    // Lines left in which a `value:` belongs to a secret `name:` just seen.
    let mut pending_value = 0u8;
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
                spans.push(named(start + indent, start + line.trim_end().len()));
                continue;
            }
            block = None;
        }
        if pending_value > 0 {
            pending_value -= 1;
            if let Some(head) = K8S_VALUE.find(line) {
                let value = line[head.end()..].trim_end();
                let (vs, ve) = unquote(head.end(), value);
                if worth_masking(&line[vs..ve]) {
                    spans.push(named(start + vs, start + ve));
                }
                pending_value = 0;
                continue;
            }
        }
        if let Some(caps) = K8S_NAME.captures(line) {
            pending_value = if caps.get(1).is_some_and(|n| secret(n.as_str())) {
                3
            } else {
                0
            };
            continue;
        }
        if (line.contains("machine ") || line.trim_start().starts_with("default"))
            && let Some(caps) = NETRC_PASSWORD.captures(line)
            && let Some(value) = caps.get(1)
        {
            spans.push(named(start + value.start(), start + value.end()));
        }
        let Some(caps) = LINE_HEAD.captures(line) else {
            if let Some(caps) = WS_ROW.captures(line)
                && let (Some(name), Some(value)) = (caps.get(1), caps.get(2))
                && secret(name.as_str())
                && secret_like(value.as_str())
            {
                spans.push(named(start + value.start(), start + value.end()));
            }
            continue;
        };
        let (Some(name), Some(sep), Some(head)) = (caps.get(1), caps.get(2), caps.get(0)) else {
            continue;
        };
        let rest = &line[head.end()..];
        if sep.as_str() == "=" && rest.starts_with('=') {
            continue; // `a == b`
        }
        if rest.starts_with("//") || !secret(name.as_str()) {
            continue; // `https://…`
        }
        let lead = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let value_start = head.end() + lead;
        let value = line[value_start..].trim_end();
        if value.is_empty() {
            continue;
        }
        if sep.as_str() == ":" && is_block_indicator(value) {
            block = Some(leading_indent(line));
            continue;
        }
        let (vs, ve) = unquote(value_start, value);
        let quoted = vs != value_start;
        let plausible = if sep.as_str() == ":" && !quoted && !is_header_name(name.as_str()) {
            secret_like(&line[vs..ve])
        } else {
            worth_masking(&line[vs..ve])
        };
        if plausible {
            spans.push(named(start + vs, start + ve));
        }
    }
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

/// An HTTP credential header (`Authorization`, `Cookie`, `Set-Cookie`,
/// `Proxy-Authorization`): its value has spaces (`Bearer …`) by design, so the
/// [`secret_like`] shape test does not apply.
fn is_header_name(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|s| s == "authorization" || s == "cookie")
}

/// The stricter test for the **unquoted colon** and **table-row** forms, which
/// are also how prose, test runners and source code read (`Token expired`,
/// `--- PASS: TestFoo (0.00s)`, `password: String,`). The value must look like
/// a credential: one word of at least 8 characters that is not a plain word,
/// a number, a duration, a boolean, or an identifier/type expression. The `=`
/// form, quoted values and header values keep the plain [`worth_masking`]
/// test: those shapes are data, not prose.
fn secret_like(value: &str) -> bool {
    let v = value.trim().trim_end_matches([',', ';']);
    if !worth_masking(v) || v.chars().any(char::is_whitespace) || v.chars().count() < 8 {
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

/// Could `value` be a secret? Only values that cannot be one are spared:
/// empty, a boolean/null, or already masked. Everything else is masked — code,
/// references and short numbers included (see the module doc's policy).
fn worth_masking(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']).trim();
    if v.is_empty() {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    !(matches!(
        lower.as_str(),
        "true" | "false" | "null" | "none" | "nil" | "~" | "undefined" | "\"\"" | "''"
    ) || lower.contains("redacted")
        || v.chars().all(|c| c == '*'))
}

/// Segments that make a name secret-shaped wherever they sit.
const SECRET_WORDS: &[&str] = &[
    "secret",
    "secrets",
    "token",
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
    "auth",
    "cookie",
    "dockerconfigjson",
    "dockercfg",
    "dsn",
];

/// A last segment that makes the name describe the secret rather than hold it.
const METADATA_SUFFIXES: &[&str] = &[
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

/// Split a name into lowercase segments on `_`, `-`, `.`, other non-alnum
/// characters, and camelCase / acronym boundaries (`APIKey` → `api`, `key`).
fn segments(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in name.split(|c: char| !c.is_ascii_alphanumeric()) {
        let chars: Vec<char> = part.chars().collect();
        let mut current = String::new();
        for (i, &c) in chars.iter().enumerate() {
            let prev = i.checked_sub(1).map(|p| chars[p]);
            let next = chars.get(i + 1).copied();
            let boundary = match prev {
                Some(p) if c.is_ascii_uppercase() => {
                    p.is_ascii_lowercase()
                        || p.is_ascii_digit()
                        || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
                }
                Some(p) if c.is_ascii_digit() => !p.is_ascii_digit(),
                Some(p) if c.is_ascii_alphabetic() => p.is_ascii_digit(),
                _ => false,
            };
            if boundary && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            current.push(c.to_ascii_lowercase());
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    out
}

/// Does this NAME hold a secret value? Segment-matched (see the module doc).
pub fn is_secret_name(name: &str) -> bool {
    let all = segments(name);
    // Numeric segments (`API_KEY_2`) neither qualify nor terminate a name.
    let segs: Vec<&str> = all
        .iter()
        .map(String::as_str)
        .filter(|s| !s.chars().all(|c| c.is_ascii_digit()))
        .collect();
    let Some(last) = segs.last() else {
        return false;
    };
    if METADATA_SUFFIXES.contains(last) {
        return false;
    }
    segs.iter().enumerate().any(|(i, seg)| {
        let prev = i.checked_sub(1).map(|p| segs[p]);
        match *seg {
            // A bare `key` is a key/value listing, and a qualified one is often
            // not a secret at all.
            "key" | "keys" => prev.is_some_and(|p| !NON_SECRET_KEY_QUALIFIERS.contains(&p)),
            "token" => prev.is_none_or(|p| !TOKEN_COUNT_QUALIFIERS.contains(&p)),
            // `DB_PASS` yes; a bare `PASS` is a test runner's status word.
            "pass" => prev.is_some(),
            s => SECRET_WORDS.contains(&s),
        }
    })
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
                "x\x1b[31m[redacted: GitHub token] y\n".to_string(),
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
        ];
        for input in corpus {
            assert_eq!(redact(input), None, "masked something in {input:?}");
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
            ("SECRET_URL", true),
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
        for (name, want) in cases {
            assert_eq!(is_secret_name(name), *want, "{name}");
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
