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
//! **What is masked**, each value replaced in place and every other byte kept:
//! 1. **Credential tokens**, by grammar — the same detector the
//!    `redact-external-content` block tier uses
//!    ([`credential_scan::direct_spans`], one source of truth; no second regex
//!    set). A PEM private-key header is widened over its key body.
//! 2. **Secret-named values** — name-keyed, never value-keyed. `NAME=value`
//!    and `name: value` at a line start (env dumps, dotenv, YAML, HTTP
//!    headers), `"name": "value"` anywhere (JSON), and `"NAME=value"` inside a
//!    JSON string (`docker inspect` env arrays). The value is dropped only when
//!    the NAME is secret-shaped ([`is_secret_name`]), so `unifi_api_key:` keeps
//!    its name and loses its value, and `HOMEPAGE_ALLOWED_HOSTS` stays whole.
//!    YAML block scalars (`password: |`) mask their indented body.
//!
//! [`is_secret_name`] deliberately does **not** reuse
//! `secret_patterns::is_secret_shaped_var_name`: that is bare substring
//! matching (`monkey` holds `key`, `authoritative` holds `auth`), cheap for a
//! nudge but wrong for a mutation. Names are split into `_`/`-`/`.`/camelCase
//! segments and matched per segment.
//!
//! **Deliberately left alone** (masking these would destroy information the
//! session needs, for no secret):
//! - values that are empty, booleans/null, a `$VAR`/`${…}`/`$(…)` reference,
//!   already masked (`***`, `[redacted…]`, `<placeholder>`), a short number
//!   (`max_tokens: 4096`), or code rather than data (`token: string;`,
//!   `api_key = os.environ[…]` — brackets, parens, a trailing `,`/`;`, a
//!   dotted identifier path, a bare type name);
//! - names whose last segment is metadata (`TOKEN_URL`, `KEY_ID`,
//!   `secretName`, `PASSWORD_FILE`), a bare `key` (key/value listings), and
//!   `key` qualified as a non-secret (`primary_key`, `public_key`, `sort_key`);
//! - a bare unnamed value (`security find-generic-password -w`,
//!   `kubectl … -o jsonpath`) — structurally invisible here; that is what the
//!   PreToolUse `guard-secret-dump` Ask backstop exists for;
//! - split token forms (the normalized pass of the block tier): output is not
//!   shell source, and a split form has no byte-exact span to mask.
//!
//! **Output contract.** `updatedToolOutput` is emitted only when something was
//! actually masked — never an identity rewrite, which would race a sibling
//! hook's real rewrite last-write-wins. Image output is never touched. Any
//! doubt about a span (a non-char-boundary offset) abandons the rewrite: the
//! failure mode is "no change", never corrupted output.
//!
//! **Escape:** `CADENCE_ALLOW_SECRET_OUTPUT` (truthy) passes output through
//! unmasked and records a bypass row, like `CADENCE_ALLOW_SOPS_DECRYPT`. The
//! issue's `dismiss-*` snooze is intentionally not built: a snooze the session
//! itself can arm from Bash would let the model unmask the very values this
//! exists to keep from it; an env switch has to be set by the operator before
//! the session starts.
//!
//! **Residuals — what this hook cannot close:**
//! - OpenTelemetry tool spans and analytics events capture the original
//!   output *before* hooks run (Claude Code hooks docs).
//! - A hook failure or timeout leaves the raw output in place (fail open), so
//!   the scan is linear-time and never panics; a 200 KB output stays far inside
//!   the deadline.
//! - The hook itself receives the raw output on stdin (by design).
//! - The compaction path was not probed; the JSONL and model-facing
//!   `tool_result` were.
//! - Very large rewrites (beyond what the probe exercised) are unprobed; if
//!   Claude Code refused an oversized envelope, the raw output would stand.
//! - Anything the model reconstructs from the command text itself.

use crate::credential_scan::{self, PEM_KIND};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput, ToolResponse};
use regex::Regex;
use std::sync::LazyLock;

/// The returnable escape: set truthy to see raw output deliberately.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_SECRET_OUTPUT";

/// Replacement for a value masked because of its name.
const NAMED_MARK: &str = "[redacted: secret-named value]";

/// How far past a PEM header to look for its `-----END` line.
const PEM_WINDOW: usize = 64 * 1024;

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
    Token(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    label: Label,
}

/// `text` with every secret value masked, or `None` when nothing was masked
/// (or a span could not be applied safely — fail open to "no change").
pub fn redact(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let mut spans = Vec::new();
    token_spans(text, &mut spans);
    json_pair_spans(text, &mut spans);
    env_string_spans(text, &mut spans);
    line_spans(text, &mut spans);
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
            // A named token reads better as its kind.
            if let Label::Token(_) = span.label {
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
            Label::Token(kind) => {
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

// ---------------------------------------------------------------------------
// Credential tokens (shared grammar)
// ---------------------------------------------------------------------------

fn token_spans(text: &str, spans: &mut Vec<Span>) {
    for hit in credential_scan::direct_spans(text) {
        let end = if hit.kind == PEM_KIND {
            pem_body_end(text, hit.end)
        } else {
            hit.end
        };
        spans.push(Span {
            start: hit.start,
            end,
            label: Label::Token(hit.kind),
        });
    }
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

/// One line of a PEM body: blank, pure base64, or an RFC 1421 header
/// (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: AES-128-CBC,…`). Prose is none of these.
fn is_key_body_line(line: &str) -> bool {
    let line = line.trim_matches(|c: char| c.is_ascii_whitespace());
    if line.is_empty() || line.chars().all(is_base64_char) {
        return true;
    }
    line.split_once(": ").is_some_and(|(name, value)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ',' | '-'))
    })
}

/// Where a PEM private key that starts right after `header_end` ends.
///
/// With an `-----END …-----` line inside [`PEM_WINDOW`], reached through
/// nothing but key-body lines ([`is_key_body_line`], split on real newlines
/// and on literal `\n` escapes), the span runs through it. Otherwise (a truncated key: `head`, a cut-off dump) it covers the run of
/// body lines that follows, and never text that is not key-shaped.
fn pem_body_end(text: &str, header_end: usize) -> usize {
    let Some(rest) = text.get(header_end..) else {
        return header_end;
    };
    let mut limit = rest.len().min(PEM_WINDOW);
    while !rest.is_char_boundary(limit) {
        limit -= 1;
    }
    let window = &rest[..limit];
    if let Some(end_at) = window.find("-----END") {
        let body_ok = window[..end_at]
            .split('\n')
            .flat_map(|line| line.split("\\n"))
            .all(is_key_body_line);
        let after = end_at + "-----END".len();
        if body_ok && let Some(close) = window[after..].find("-----") {
            return header_end + after + close + "-----".len();
        }
    }
    // Escaped single-line form (a JSON string): `…KEY-----\nMIIE…`.
    if rest.starts_with("\\n") {
        let run = rest
            .char_indices()
            .find(|&(_, c)| !(is_base64_char(c) || c == '\\'))
            .map_or(rest.len(), |(i, _)| i);
        return header_end + run;
    }
    // Raw form: whole following lines of base64.
    let mut end = header_end;
    let mut pos = match rest.find('\n') {
        Some(nl) => nl + 1,
        None => return header_end,
    };
    while pos < rest.len() {
        let line_end = rest[pos..].find('\n').map_or(rest.len(), |i| pos + i);
        let line = rest[pos..line_end].trim_end_matches('\r');
        let body = line.trim_start();
        if body.is_empty() || !body.chars().all(is_base64_char) {
            break;
        }
        end = header_end + pos + line.len();
        pos = line_end + 1;
    }
    end
}

// ---------------------------------------------------------------------------
// Secret-named values
// ---------------------------------------------------------------------------

/// `"name": "value"` anywhere — JSON, pretty or minified.
static JSON_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""((?:[^"\\\n]|\\.)+)"[ \t]*:[ \t]*"((?:[^"\\\n]|\\.)*)""#)
        .expect("json pair regex is valid")
});

/// `"NAME=value"` inside a JSON string — `docker inspect`'s `.Config.Env`.
static ENV_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([A-Za-z_][A-Za-z0-9_.\-]*)=((?:[^"\\\n]|\\.)*)""#)
        .expect("env string regex is valid")
});

/// A line-start assignment head: optional list/quote/diff markers and an
/// `export`/`declare -x`/`set` keyword, a name (optionally quoted), then `=`
/// or `:`. The value is parsed by hand from the match end.
static LINE_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^[ \t]*(?:[-*>+<][ \t]+)*(?:(?:export|declare[ \t]+-x|set)[ \t]+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?[ \t]*([=:])"#,
    )
    .expect("line head regex is valid")
});

fn json_pair_spans(text: &str, spans: &mut Vec<Span>) {
    for caps in JSON_PAIR.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if name.as_str().len() <= 128
            && is_secret_name(name.as_str())
            && worth_masking(value.as_str(), true)
        {
            spans.push(named(value.start(), value.end()));
        }
    }
}

fn env_string_spans(text: &str, spans: &mut Vec<Span>) {
    for caps in ENV_STRING.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if name.as_str().len() <= 128
            && is_secret_name(name.as_str())
            && worth_masking(value.as_str(), true)
        {
            spans.push(named(value.start(), value.end()));
        }
    }
}

fn named(start: usize, end: usize) -> Span {
    Span {
        start,
        end,
        label: Label::Named,
    }
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn is_block_indicator(value: &str) -> bool {
    let v = value.trim_end_matches(|c: char| c.is_ascii_digit());
    matches!(v, "|" | "|-" | "|+" | ">" | ">-" | ">+")
}

/// Line-start `NAME=value` / `name: value`, plus YAML block-scalar bodies.
fn line_spans(text: &str, spans: &mut Vec<Span>) {
    // The key line's indent while inside a secret-named block scalar.
    let mut block: Option<usize> = None;
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
                let end = line.trim_end().len();
                spans.push(named(start + indent, start + end));
                continue;
            }
            block = None;
        }
        let Some(caps) = LINE_HEAD.captures(line) else {
            continue;
        };
        let (Some(name), Some(sep), Some(head)) = (caps.get(1), caps.get(2), caps.get(0)) else {
            continue;
        };
        let rest = &line[head.end()..];
        let is_colon = sep.as_str() == ":";
        if is_colon && !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
            continue; // `https://…`, `a:b`
        }
        if !is_colon && rest.starts_with('=') {
            continue; // `a == b`
        }
        if name.as_str().len() > 128 || !is_secret_name(name.as_str()) {
            continue;
        }
        let lead = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let value_start = head.end() + lead;
        let value = line[value_start..].trim_end();
        if value.is_empty() {
            continue;
        }
        if is_colon && is_block_indicator(value) {
            block = Some(leading_indent(line));
            continue;
        }
        let (vs, ve, quoted) = match value.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let inner = &value[1..];
                let close = closing_quote(inner, q);
                (
                    value_start + 1,
                    value_start + 1 + close.unwrap_or(inner.len()),
                    true,
                )
            }
            _ => (value_start, value_start + value.len(), false),
        };
        if worth_masking(&line[vs..ve], quoted) {
            spans.push(named(start + vs, start + ve));
        }
    }
}

/// Byte offset of the quote closing `inner` (the text after an opening `q`).
/// Backslash escapes only inside double quotes, as in the shell and JSON.
fn closing_quote(inner: &str, q: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in inner.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' && q == '"' {
            escaped = true;
        } else if c == q {
            return Some(i);
        }
    }
    None
}

/// Is `value` a real value worth masking, rather than a placeholder, a
/// reference, or code? `quoted` values skip the code heuristics: a quoted
/// literal after a secret name is a literal.
fn worth_masking(value: &str, quoted: bool) -> bool {
    let v = value.trim();
    if v.is_empty() || v.starts_with('$') {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true"
            | "false"
            | "null"
            | "none"
            | "nil"
            | "yes"
            | "no"
            | "~"
            | "undefined"
            | "\"\""
            | "''"
    ) || lower.contains("redacted")
        || v.chars().all(|c| matches!(c, '*' | '•' | '.'))
        || (v.starts_with('<') && v.ends_with('>'))
        || (v.len() <= 6 && v.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    if quoted {
        return true;
    }
    // Code, not data: an expression, a statement tail, an identifier path, or
    // a type annotation (`token: string;`, `api_key = os.environ["X"]`).
    if v.contains(['(', ')', '[', ']', '{', '}']) || v.ends_with([',', ';']) {
        return false;
    }
    let is_ident = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if v.contains('.') && v.split('.').all(is_ident) {
        return false;
    }
    !TYPE_WORDS.contains(&lower.as_str())
}

/// Bare type names that follow a secret-named field in source code.
const TYPE_WORDS: &[&str] = &[
    "string",
    "str",
    "int",
    "integer",
    "bool",
    "boolean",
    "number",
    "any",
    "bytes",
    "text",
    "secretstr",
    "object",
];

/// Segments that make a name secret-shaped wherever they sit.
const SECRET_WORDS: &[&str] = &[
    "secret",
    "secrets",
    "token",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "pass",
    "credential",
    "credentials",
    "creds",
    "apikey",
    "privatekey",
    "secretkey",
    "accesskey",
    "authorization",
    "auth",
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
    "url",
    "uri",
    "urls",
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
    fn canary() -> String {
        ["CANARY", "-FAKE-", "7f3a9c"].concat()
    }
    fn pem_begin() -> String {
        ["-----BEGIN ", "RSA PRIVATE", " KEY-----"].concat()
    }
    fn pem_end() -> String {
        ["-----END ", "RSA PRIVATE", " KEY-----"].concat()
    }

    fn masked(text: &str) -> String {
        redact(text).unwrap_or_else(|| text.to_string())
    }

    #[test]
    fn secret_name_classification() {
        let cases: &[(&str, bool)] = &[
            ("unifi_api_key", true),
            ("HOMEPAGE_VAR_UNIFI_KEY", true),
            ("GITHUB_TOKEN", true),
            ("DB_PASSWORD", true),
            ("db_pass", true),
            ("password", true),
            ("token", true),
            ("secret", true),
            ("auth", true),
            ("Authorization", true),
            ("clientSecret", true),
            ("apiKey", true),
            ("APIKey", true),
            ("spring.datasource.password", true),
            ("API_KEY_2", true),
            ("SECRET_KEY_BASE", true),
            ("AUTH_HEADER", true),
            ("private-key", true),
            // Not secrets.
            ("HOMEPAGE_ALLOWED_HOSTS", false),
            ("key", false),
            ("primary_key", false),
            ("public_key", false),
            ("sortKey", false),
            ("KEY_ID", false),
            ("AWS_ACCESS_KEY_ID", false),
            ("TOKEN_URL", false),
            ("secretName", false),
            ("PASSWORD_FILE", false),
            ("token_type", false),
            ("max_tokens", false),
            ("max_token", false),
            ("input_tokens", false),
            ("monkey", false),
            ("authoritative", false),
            ("author", false),
            ("keyboard_layout", false),
            ("bypass", false),
            ("AUTH_ENABLED", false),
            ("", false),
        ];
        for (name, want) in cases {
            assert_eq!(is_secret_name(name), *want, "{name}");
        }
    }

    #[test]
    fn incident_shapes_keep_names_and_drop_values() {
        let v = canary();
        let cases: Vec<(String, String)> = vec![
            // Incident 1: grep of decrypted YAML.
            (
                format!("unifi:\n  unifi_api_key: {v}\n  unifi_host: 10.0.0.1\n"),
                format!("unifi:\n  unifi_api_key: {NAMED_MARK}\n  unifi_host: 10.0.0.1\n"),
            ),
            // Incident 2: docker env dump, one line per var.
            (
                format!("HOMEPAGE_ALLOWED_HOSTS=home.lan\nHOMEPAGE_VAR_UNIFI_KEY={v}\n"),
                format!("HOMEPAGE_ALLOWED_HOSTS=home.lan\nHOMEPAGE_VAR_UNIFI_KEY={NAMED_MARK}\n"),
            ),
            // Incident 2, JSON form.
            (
                format!(r#"["HOMEPAGE_ALLOWED_HOSTS=home.lan","HOMEPAGE_VAR_UNIFI_KEY={v}"]"#),
                format!(
                    r#"["HOMEPAGE_ALLOWED_HOSTS=home.lan","HOMEPAGE_VAR_UNIFI_KEY={NAMED_MARK}"]"#
                ),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(masked(&input), want, "{input}");
        }
    }

    #[test]
    fn named_value_shapes() {
        let v = canary();
        let m = NAMED_MARK;
        let cases: Vec<(String, String)> = vec![
            (
                format!("export API_TOKEN={v}"),
                format!("export API_TOKEN={m}"),
            ),
            (
                format!("declare -x DB_PASSWORD=\"{v}\""),
                format!("declare -x DB_PASSWORD=\"{m}\""),
            ),
            (
                format!("DB_PASSWORD='{v}' # prod"),
                format!("DB_PASSWORD='{m}' # prod"),
            ),
            (format!("api_key = \"{v}\""), format!("api_key = \"{m}\"")),
            (format!("  - password: {v}"), format!("  - password: {m}")),
            (
                format!("> Authorization: Bearer {v}"),
                format!("> Authorization: {m}"),
            ),
            (
                format!(r#"{{"user":"bob","password":"{v}"}}"#),
                format!(r#"{{"user":"bob","password":"{m}"}}"#),
            ),
            (
                format!(r#"  "client_secret": "{v}","#),
                format!(r#"  "client_secret": "{m}","#),
            ),
            (
                format!(r#"{{"auth": "{v}"}}"#),
                format!(r#"{{"auth": "{m}"}}"#),
            ),
            (
                format!("DB_PASSWORD={v}\r\nX=1\r\n"),
                format!("DB_PASSWORD={m}\r\nX=1\r\n"),
            ),
            // Escaped quote inside a JSON value stays inside the span.
            (
                format!(r#""token": "a\"{v}""#),
                format!(r#""token": "{m}""#),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(masked(&input), want, "{input}");
        }
    }

    #[test]
    fn yaml_block_scalar_body_is_masked() {
        let v = canary();
        let input = format!("data:\n  password: |\n    {v}\n    line2\n\n  user: bob\n");
        let want =
            format!("data:\n  password: |\n    {NAMED_MARK}\n    {NAMED_MARK}\n\n  user: bob\n");
        assert_eq!(masked(&input), want);
    }

    #[test]
    fn tokens_are_masked_anywhere() {
        let t = ghp();
        let aws = ["AK", "IA"].concat() + "ABCDEFGH23456789";
        let cases: Vec<(String, String)> = vec![
            (
                format!("remote: https://x:{t}@github.com/o/r"),
                "remote: https://x:[redacted: GitHub token]@github.com/o/r".to_string(),
            ),
            (
                format!("id {aws} end"),
                "id [redacted: AWS access key id] end".to_string(),
            ),
            // A token under a non-secret name is still a token.
            (
                format!("NOTE={t}"),
                "NOTE=[redacted: GitHub token]".to_string(),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(masked(&input), want, "{input}");
        }
    }

    #[test]
    fn pem_key_body_is_masked() {
        let (b, e) = (pem_begin(), pem_end());
        let body = "MIIEowIBAAKCAQEA\nq2Vx9+/abc=\n";
        let kind = PEM_KIND;
        let cases: Vec<(String, String)> = vec![
            // Complete block.
            (
                format!("before\n{b}\n{body}{e}\nafter\n"),
                format!("before\n[redacted: {kind}]\nafter\n"),
            ),
            // Truncated (`head`): body lines only, never the prose after.
            (
                format!("{b}\n{body}not base64 here\n"),
                format!("[redacted: {kind}]\nnot base64 here\n"),
            ),
            // Escaped single-line JSON string.
            (
                format!(r#"{{"k":"{b}\nMIIEowIBAAK\nqq==\n{e}\n"}}"#),
                format!(r#"{{"k":"[redacted: {kind}]\n"}}"#),
            ),
            // An END far away through prose is not this key's END.
            (
                format!("{b}\nsome prose line\n{e}\n"),
                format!("[redacted: {kind}]\nsome prose line\n{e}\n"),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(masked(&input), want, "{input}");
        }
    }

    #[test]
    fn non_secrets_pass_through_unchanged() {
        let cases: &[&str] = &[
            "",
            "hello world\n",
            "HOMEPAGE_ALLOWED_HOSTS=home.lan\n",
            "GITHUB_TOKEN=\n",
            "API_TOKEN=$GH_TOKEN\n",
            "password: ${DB_PASSWORD}\n",
            "password: \"$1\"\n",
            "password: '***'\n",
            "password: [REDACTED]\n",
            "password: <your-password>\n",
            "require_auth: true\n",
            "max_tokens: 4096\n",
            "token_type: bearer\n",
            "secretName: my-secret\n",
            r#"{"key": "value", "keys": "x"}"#,
            "  token: string;\n",
            "password: str\n",
            "api_key = os.environ[\"API_KEY\"]\n",
            "Token: token,\n",
            "token = self.config.token\n",
            "see https://example.com/password: here\n",
            "if [ \"$TOKEN\" == x ]; then\n",
            "a == b\n",
            "commit 3f786850e387550fdab836ed7e6dc881de23001b\n",
            "uuid 123e4567-e89b-12d3-a456-426614174000\n",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI fake@host\n",
            "sk-learn is a library\n",
            "password:\n  nested: map\n",
        ];
        for input in cases {
            assert_eq!(redact(input), None, "{input:?}");
        }
    }

    #[test]
    fn non_ascii_text_around_secrets_is_preserved() {
        let v = canary();
        let input = format!("héllo ✓\nDB_PASSWORD=ü{v}✓\nfin ✓\n");
        assert_eq!(
            masked(&input),
            format!("héllo ✓\nDB_PASSWORD={NAMED_MARK}\nfin ✓\n")
        );
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
    fn decide_emits_full_bash_shape_only_when_masked() {
        let v = canary();
        let r = decide(&response(&format!("DB_PASSWORD={v}\n"), "warn\n"), false);
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

        // stderr alone is scanned too (`security -g` prints there).
        let r = decide(&response("", &format!("password: \"{v}\"\n")), false);
        assert!(r.updated_tool_output.is_some());

        // Nothing to mask: no identity rewrite.
        let r = decide(&response("ok\n", ""), false);
        assert!(r.updated_tool_output.is_none());

        // Image output is never touched.
        let mut img = response(&format!("DB_PASSWORD={v}"), "");
        img.is_image = Some(true);
        assert!(decide(&img, false).updated_tool_output.is_none());

        // The escape passes raw output through and records the bypass.
        let r = decide(&response(&format!("DB_PASSWORD={v}\n"), ""), true);
        assert!(r.updated_tool_output.is_none());
        assert_eq!(r.bypass.map(|b| b.mechanism).as_deref(), Some(ESCAPE_ENV));
    }

    #[test]
    fn run_ignores_other_tools_and_missing_response() {
        let v = canary();
        let payload = |tool: &str| {
            format!(
                r#"{{"tool_name":"{tool}","tool_input":{{"command":"x"}},"tool_response":{{"stdout":"DB_PASSWORD={v}","stderr":"","interrupted":false,"isImage":false}}}}"#
            )
        };
        let read = HookInput::from_json(&payload("Read")).unwrap();
        assert!(RedactSecretOutput.run(&read).updated_tool_output.is_none());
        let none =
            HookInput::from_json(r#"{"tool_name":"Bash","tool_input":{"command":"x"}}"#).unwrap();
        assert!(RedactSecretOutput.run(&none).updated_tool_output.is_none());
    }

    #[test]
    fn adversarial_200kb_inputs_stay_fast_and_exact() {
        let v = canary();
        let big_quote = "\"".repeat(200_000);
        let big_backslash = format!("\"password\": \"{}", "\\".repeat(200_000));
        let many_pairs = format!("DB_PASSWORD={v}\n").repeat(200_000 / 30);
        let one_line = format!("password: \"{}", "a".repeat(200_000));
        let pem_flood = format!("{}\n{}", pem_begin(), "QUJD\n".repeat(40_000));
        let json_noise = r#"{"a":"b","c":"d"},"#.repeat(12_000);
        let colons = "a: ".repeat(70_000);
        for input in [
            big_quote,
            big_backslash,
            many_pairs,
            one_line,
            pem_flood,
            json_noise,
            colons,
        ] {
            let started = std::time::Instant::now();
            let out = redact(&input);
            // Debug builds are several times slower than release; this bound
            // is loose on purpose and the release bound is checked by probe.
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{} bytes took {:?}",
                input.len(),
                started.elapsed()
            );
            if let Some(out) = out {
                assert!(!out.contains(&v), "a canary survived");
            }
        }
    }
}
