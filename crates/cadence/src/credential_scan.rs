//! Credential-token tier of `redact-external-content` (cadence-hooks#1022).
//!
//! A posted secret cannot be recalled, so this tier **blocks**, and nothing
//! softens it: not the identity bypass, not repo config. It matches token
//! *grammar* (known prefix + charset + minimum length), never a list of known
//! values.
//!
//! Two passes over each text, one combined regex (linear time, so a 200 KB
//! body stays far inside the hook deadline):
//!
//! 1. **Direct** — the text as written.
//! 2. **Normalized** — a copy with quotes, backslashes, `+` and whitespace
//!    removed wherever they sit *between two token-charset characters*, which
//!    rejoins `"ghp_" + "abc…"`, `ghp_ abc…` and shell-style concatenation.
//!    Offsets map back to the original text.
//!
//! Findings carry the token type, the position and the token length, never the
//! token: the block message reaches the transcript.
//!
//! Deliberately allowed (no known prefix, or too short / not random-looking):
//! git SHAs, UUIDs, base64 blobs without a prefix, and `sk-learn`.

use regex::Regex;
use std::sync::LazyLock;

/// One credential finding. Holds no token text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredHit {
    pub kind: &'static str,
    /// 1-based line in the original text.
    pub line: usize,
    /// Byte offset of the match start in the original text.
    pub offset: usize,
    /// Matched length in characters (of the rejoined token).
    pub len: usize,
    /// Found only after normalization (a split form).
    pub split: bool,
}

/// Stop reporting after this many findings; one is enough to block.
const MAX_HITS: usize = 20;

/// Kind names, index-aligned with the named capture groups below.
const KINDS: &[&str] = &[
    "GitHub token",
    "GitHub fine-grained token",
    "AWS access key id",
    "Slack token",
    "Stripe live key",
    "API key (sk- shape)",
    "Google API key",
    "Private key PEM header",
    "GitLab token",
    "npm token",
];

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?P<k0>gh[pousr]_[A-Za-z0-9]{36,})",
        r"|(?P<k1>github_pat_[A-Za-z0-9_]{22,})",
        r"|(?P<k2>(?:AKIA|ASIA)[A-Z0-9]{16})",
        r"|(?P<k3>xox[abprs]-[A-Za-z0-9-]{10,})",
        r"|(?P<k4>[sr]k_live_[A-Za-z0-9]{16,})",
        r"|(?P<k5>sk-[A-Za-z0-9_-]{20,})",
        r"|(?P<k6>AIza[A-Za-z0-9_-]{35})",
        r"|(?P<k7>-----BEGIN[A-Z ]*PRIVATE ?KEY(?: ?BLOCK)?-----)",
        r"|(?P<k8>glpat-[A-Za-z0-9_-]{20,})",
        r"|(?P<k9>npm_[A-Za-z0-9]{36,})",
    ))
    .expect("credential regex is valid")
});

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_joiner(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '\\' | '+')
}

/// The sk- shape is the only one prose can resemble (`sk-learn-…`), so it must
/// also look random: digit, upper and lower case.
fn looks_random(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase())
}

/// Known token prefixes, for the one plain-space join (see [`normalize`]).
static PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:gh[pousr]_|github_pat_|AKIA|ASIA|xox[abprs]-|[sr]k_live_|sk-|AIza|glpat-|npm_)",
    )
    .expect("prefix regex is valid")
});

/// Copy of `text` with shell-concatenation seams removed, so a split token
/// rejoins. Returns the copy and, per copy byte, the original offset.
///
/// A joiner run between two token-charset characters is dropped only when it
/// is an explicit seam: it contains `+` (spaces around it allowed), contains a
/// backslash (line continuation), or is adjacent quotes with no whitespace
/// (`"a""b"`). A run of plain whitespace is dropped only when the word to its
/// left already starts with a known prefix and both sides are pure token
/// chunks (`ghp_ABC… DEF…`) — never when the join would *create* the prefix.
/// Everything else keeps one space, so prose never fuses into one long run.
fn normalize(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map: Vec<usize> = Vec::with_capacity(text.len());
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (off, c) = chars[i];
        if is_joiner(c) {
            let mut j = i;
            while j < chars.len() && is_joiner(chars[j].1) {
                j += 1;
            }
            let run = &chars[i..j];
            let before = out.chars().next_back().is_some_and(is_token_char);
            let after = j < chars.len() && is_token_char(chars[j].1);
            let has = |f: fn(char) -> bool| run.iter().any(|&(_, c)| f(c));
            let seam = has(|c| c == '+')
                || has(|c| c == '\\')
                || (!has(char::is_whitespace) && has(|c| matches!(c, '"' | '\'' | '`')));
            let plain_space = run.iter().all(|&(_, c)| c.is_whitespace());
            let prefixed_left = plain_space && before && after && {
                // The whitespace-delimited word to the left, in the original.
                let word_start = text[..off]
                    .rfind(|c: char| !is_token_char(c))
                    .map_or(0, |k| {
                        k + text[k..].chars().next().map_or(1, char::len_utf8)
                    });
                PREFIX_RE.is_match(&text[word_start..off])
            };
            if !(before && after && (seam || prefixed_left)) {
                out.push(' ');
                map.push(off);
            }
            i = j;
        } else {
            let start = out.len();
            out.push(c);
            map.extend(std::iter::repeat_n(off, out.len() - start));
            i += 1;
        }
    }
    (out, map)
}

fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// The block tier's per-match gates. [`direct_spans`] (the output redactor)
/// deliberately relaxes the boundary half; see its doc.
fn accepts(idx: usize, token: &str, orig: &str, offset: usize) -> bool {
    // Left boundary, judged in the ORIGINAL text so a token fused onto a
    // quote seam (`x""ghp_…`) is still seen but `task-…` never is.
    if let Some(prev) = orig[..offset].chars().next_back()
        && (prev.is_ascii_alphanumeric() || prev == '_' || (idx == 5 && prev == '-'))
    {
        return false;
    }
    // sk- also needs a random-looking body: prose can resemble it.
    !(idx == 5 && !looks_random(&token[3..]))
}

/// One credential token found by [`direct_spans`]: its kind and its byte
/// range in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSpan {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Every credential token written **as-is** in `text`, as byte ranges, with no
/// hit cap. For `redact-secret-output` (cameronsjo/cadence-hooks#776), which
/// masks each token in place. Same [`TOKEN_RE`] grammar as [`scan`] (the
/// block tiers: `redact-external-content`, `prevent-secret-push`), with three
/// deliberate differences, all toward masking more, because a redactor's miss
/// leaks a secret while its false positive only costs readability:
///
/// - **No left-boundary gate** except for the `sk-` shape, whose prefix prose
///   can form (`task-…`, `risk-…`). A token glued to a JSON escape (`\n` +
///   token), an ANSI colour code or a `%3D` is still a token here.
/// - For `sk-`, a letter right after a backslash, or the end of a `%XX` escape,
///   counts as a boundary.
/// - **JWTs** (`eyJ…` three base64url segments) are masked. They stay out of
///   [`TOKEN_RE`] because an example JWT in a doc or test fixture would start
///   blocking pushes; masking one in output costs nothing.
///
/// The normalized (split-token) pass is skipped: output is not shell source,
/// and a split form has no byte-exact span to mask.
pub fn direct_spans(text: &str) -> Vec<TokenSpan> {
    let mut out = Vec::new();
    for caps in TOKEN_RE.captures_iter(text) {
        let Some((idx, m)) = (0..KINDS.len()).find_map(|i| caps.get(i + 1).map(|m| (i, m))) else {
            continue;
        };
        if idx == 5 && !(sk_boundary(text, m.start()) && looks_random(&m.as_str()[3..])) {
            continue;
        }
        out.push(TokenSpan {
            kind: KINDS[idx],
            start: m.start(),
            end: m.end(),
        });
    }
    for m in JWT_RE.find_iter(text) {
        out.push(TokenSpan {
            kind: JWT_KIND,
            start: m.start(),
            end: m.end(),
        });
    }
    out
}

/// Kind name for a masked JWT (redactor-only, see [`direct_spans`]).
pub const JWT_KIND: &str = "JWT";

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        .expect("jwt regex is valid")
});

/// The END line of a private-key block, of every kind the `k7` header matches.
pub static PEM_END_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----END[A-Z ]*PRIVATE ?KEY(?: ?BLOCK)?-----").expect("pem end regex is valid")
});

/// Left boundary for the `sk-` shape in the redactor: the block-tier rule,
/// except that an escape letter (`\n`) or a `%XX` escape ends a word.
fn sk_boundary(text: &str, offset: usize) -> bool {
    let before = &text[..offset];
    let mut rev = before.chars().rev();
    let Some(prev) = rev.next() else {
        return true;
    };
    if !(prev.is_ascii_alphanumeric() || prev == '_' || prev == '-') {
        return true;
    }
    let prev2 = rev.next();
    if prev2 == Some('\\') {
        return true;
    }
    let prev3 = rev.next();
    prev3 == Some('%') && prev.is_ascii_hexdigit() && prev2.is_some_and(|c| c.is_ascii_hexdigit())
}

/// Kind name of the PEM private-key header, for callers that extend its span
/// over the key body.
pub const PEM_KIND: &str = KINDS[7];

fn scan_one(scan: &str, orig: &str, map: Option<&[usize]>, out: &mut Vec<CredHit>) {
    for caps in TOKEN_RE.captures_iter(scan) {
        if out.len() >= MAX_HITS {
            return;
        }
        let Some((idx, m)) = (0..KINDS.len()).find_map(|i| caps.get(i + 1).map(|m| (i, m))) else {
            continue;
        };
        let s = m.as_str();
        let offset = map.map_or(m.start(), |mp| mp[m.start()]);
        if !accepts(idx, s, orig, offset) {
            continue;
        }
        let hit = CredHit {
            kind: KINDS[idx],
            line: line_of(orig, offset),
            offset,
            len: s.chars().count(),
            split: map.is_some(),
        };
        // A token found in both passes is reported once.
        if !out
            .iter()
            .any(|h| h.kind == hit.kind && h.offset == hit.offset)
        {
            out.push(hit);
        }
    }
}

/// Scan `text` for credential tokens, direct and split forms.
pub fn scan(text: &str) -> Vec<CredHit> {
    let mut out = Vec::new();
    scan_one(text, text, None, &mut out);
    // Split forms only exist if the text has a joiner between token runs;
    // normalizing is linear, so it always runs rather than guess.
    let (norm, map) = normalize(text);
    scan_one(&norm, text, Some(&map), &mut out);
    out
}

/// Render findings for the block message. Names type, position and length;
/// never the token.
pub fn render(hits: &[CredHit]) -> String {
    let mut out = String::from(
        "⛔  redact-external-content: BLOCKED — credential token in outgoing content \
         (a posted secret cannot be recalled; no bypass applies):\n",
    );
    for h in hits {
        out.push_str(&format!(
            "  [{}] line {}, byte {}, {} chars{} — masked\n",
            h.kind,
            h.line,
            h.offset,
            h.len,
            if h.split {
                ", split across fragments"
            } else {
                ""
            }
        ));
    }
    out.push_str(
        "Remove the token (and rotate it if it was ever real). Splitting or quoting it does not \
         hide it from this check.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fake tokens are built by concatenation so repo secret scanners never see
    // a whole literal.
    fn alnum(n: usize) -> String {
        let seed = "aB3dE5gH7jK9mN1pQ2sT4vW6yZ8cF0hL";
        seed.chars().cycle().take(n).collect()
    }
    fn ghp() -> String {
        ["gh", "p_"].concat() + &alnum(36)
    }
    fn kinds(text: &str) -> Vec<&'static str> {
        scan(text).iter().map(|h| h.kind).collect()
    }

    #[test]
    fn direct_shapes_block() {
        let cases: Vec<(String, &str)> = vec![
            (ghp(), "GitHub token"),
            (["gh", "o_"].concat() + &alnum(36), "GitHub token"),
            (["gh", "s_"].concat() + &alnum(40), "GitHub token"),
            (
                ["github", "_pat_"].concat() + &alnum(60),
                "GitHub fine-grained token",
            ),
            (
                ["AK", "IA"].concat() + "ABCDEFGH23456789",
                "AWS access key id",
            ),
            (
                ["xo", "xb-"].concat() + "1234567890-abcdefghij",
                "Slack token",
            ),
            (["sk", "_live_"].concat() + &alnum(24), "Stripe live key"),
            (["sk", "-"].concat() + &alnum(40), "API key (sk- shape)"),
            (
                ["sk", "-ant-api03-"].concat() + &alnum(40),
                "API key (sk- shape)",
            ),
            (["AI", "za"].concat() + &alnum(35), "Google API key"),
            (
                ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat(),
                "Private key PEM header",
            ),
            (
                ["-----BEGIN ", "PRIVATE KEY-----"].concat(),
                "Private key PEM header",
            ),
        ];
        for (tok, kind) in cases {
            let body = format!("here is my key: {tok} thanks");
            assert_eq!(kinds(&body), vec![kind], "case {kind}");
        }
    }

    #[test]
    fn split_forms_block() {
        let (a, b) = ("gh", "p_");
        let rest = alnum(36);
        let (r1, r2) = rest.split_at(10);
        let cases = vec![
            format!("token {a}{b} {rest}"),
            format!("token {a}{b}{r1} {r2}"),
            format!("\"{a}{b}\" + \"{rest}\""),
            format!("'{a}{b}''{r1}''{r2}'"),
            format!("{a}{b}\\\n{rest}"),
            format!("{a}\"\"{b}{rest}"),
            format!("{a}\"{b}{r1}\"+\"{r2}\""),
            format!("{a}{b}{r1}\n  {r2}"),
        ];
        for body in cases {
            let hits = scan(&body);
            assert_eq!(hits.len(), 1, "body {body:?}");
            assert!(hits[0].split, "body {body:?}");
        }
    }

    #[test]
    fn sk_prefix_then_random_chunk_is_a_split() {
        // Left chunk already starts with a known prefix: ambiguity blocks.
        let body = "sk- Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8 later words";
        assert_eq!(kinds(body), vec!["API key (sk- shape)"]);
    }

    #[test]
    fn split_pem_and_slack() {
        let pem = "-----BEGIN RSA PRIVATE\"\"KEY-----";
        assert_eq!(kinds(pem), vec!["Private key PEM header"]);
        let slack = ["xo", "xb-"].concat() + "1234567890\" + \"-abcdefghij";
        assert_eq!(kinds(&slack), vec!["Slack token"]);
    }

    #[test]
    fn control_table_stays_allowed() {
        let b64 =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=";
        let cases = [
            "commit 3f786850e387550fdab836ed7e6dc881de23001b fixes it",
            "id 550e8400-e29b-41d4-a716-446655440000 in the log",
            "```\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=\n```",
            "use sk-learn for this",
            "use sk-learn version 2 is out and works well with numpy",
            "the risk-adjusted-return-of-the-portfolio-is-high",
            "task-management-and-scheduling-for-teams-2024",
            "a ghp_ prefix is what GitHub PATs start with",
            "AKIA is the AWS prefix",
            "write -----BEGIN and -----END markers",
            "Finish the task-Management Plan for Q3 2024 Rollout",
            "we ask-Around Team42 Members Today",
            "risk-Assessment for AWS Region Us1East",
            "desk-Booking System V2 Launch Notes",
            "the Big-Picture Review-Board Action-Items List 2024 Follow-Ups Now",
            "Q3 2024 AKIA-free prose",
            "| Name | Owner |\n|---|---|\n| Alpha Beta | Carol Dan |\n| Eve Frank | Gina Hal2 |",
            "gh p_ Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3",
            "plain prose with + signs and \"quotes\" and 12345 numbers",
        ];
        for c in cases {
            assert!(scan(c).is_empty(), "false positive: {c:?}");
        }
        assert!(scan(b64).is_empty());
    }

    #[test]
    fn message_masks_token_and_names_position() {
        let tok = ghp();
        let body = format!("line one\nkey {tok}\n");
        let msg = render(&scan(&body));
        assert!(!msg.contains(&tok));
        assert!(!msg.contains(&tok[4..14]));
        assert!(msg.contains("GitHub token"));
        assert!(msg.contains("line 2"));
        assert!(msg.contains("byte 13"));
        assert!(msg.contains("40 chars"));
    }

    #[test]
    fn offsets_map_back_through_multibyte_text() {
        let body = format!(
            "héllo ü \"{}\" + \"{}\"",
            "gh".to_string() + "p_",
            alnum(36)
        );
        let h = scan(&body);
        assert_eq!(h.len(), 1);
        assert!(body.is_char_boundary(h[0].offset));
    }

    #[test]
    fn perf_200kb_adversarial() {
        let tok = ghp();
        let inputs = [
            "gh p_ ".repeat(35_000),
            "sk-".repeat(70_000),
            format!("{}\"+\"", "a").repeat(50_000),
            "-----BEGIN ".repeat(20_000),
            format!("{} ", &tok[..30]).repeat(6_000),
            "AKIA \" ".repeat(30_000),
        ];
        for input in &inputs {
            let start = std::time::Instant::now();
            let _ = scan(input);
            let dt = start.elapsed();
            let limit = if cfg!(debug_assertions) { 5.0 } else { 0.5 };
            assert!(dt.as_secs_f64() < limit, "{dt:?} on {} bytes", input.len());
        }
    }
}
