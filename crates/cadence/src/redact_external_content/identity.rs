//! The identity tier — fail-closed scanning for work-identifiable terms.
//!
//! # Why this is a tier and not a separate guard
//!
//! It shares the extraction layer with the shaped tiers: per-segment command
//! gating, `--body-file` bounded reads, the #424 hardening. That layer is where
//! the historical bugs lived, and a standalone identity guard would duplicate
//! exactly it. One guard name, one message surface, one extraction layer, two
//! scan passes with different term-source authority.
//!
//! # Term source
//!
//! `~/.config/cadence/redaction.toml` — deliberately **outside every repo**
//! (cadence-hooks#561's load-bearing property). Nothing committed to a
//! repository can add, remove, or soften a term, because the loader reads no
//! repo path. Softening authority follows term-source authority: the same file
//! carries the `allow` entries.
//!
//! # Fail directions, which run in two different directions on purpose
//!
//! - **The guard's own failure is fail-open** (ADR-0001): no file, unreadable,
//!   malformed, zero terms → the tier is inert and the check allows. A guard
//!   that hard-fails on a missing config makes every commit impossible on a
//!   machine that never had the file.
//! - **A term match is fail-closed**: it blocks, and no repo config can excuse
//!   it.
//!
//! The gap between those — a machine where the file is silently absent — is why
//! [`status`] exists and why the cadence plugin's SessionStart surfaces it. A
//! per-invocation notice on the machine you are not looking at is functionally
//! a silent disarm.

use regex::Regex;
use serde::Deserialize;
use std::path::PathBuf;

/// Enforcement posture, read from the file's top-level `mode`.
///
/// **Default is [`Mode::Enforce`]** (Cameron's ruling, 2026-08-03, superseding
/// the plan's default-warn rollout: "Default on — then we'll gather
/// feedback/issues. Does no good if it's disabled."). An absent or unparseable
/// `mode` therefore blocks rather than warns, which is the fail-closed
/// direction for a field whose whole purpose is enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    #[default]
    Enforce,
    Warn,
}

/// One allow entry — a context in which a term is benign.
///
/// `path` matches when the scanned content's file path contains it (a Write/Edit
/// surface only — a commit message has no path). `pattern` matches against the
/// surrounding text. Either alone is sufficient; both empty is inert — unless
/// `destinations` is set (below).
///
/// `destinations` (cameronsjo/cadence-hooks#630) scopes the entry along the axis
/// `path` cannot express: WHERE the content is going. Each element is an
/// `owner/repo` or an `owner/*` glob, matched case-insensitively against the
/// repo a post targets (`-R`, else the checkout's origin). With it set the
/// entry applies only to a post whose target resolves and matches, and it is
/// ANDed with `path`/`pattern` when those are also set. With `destinations` as
/// the only clause, the destination match alone excuses the term. A surface
/// with no resolvable destination (a Write/Edit, a commit whose origin cannot
/// be read, a command posting to several repos) never satisfies a
/// destination-scoped entry: unknown means the term stays blocked.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct AllowEntry {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub destinations: Vec<String>,
}

/// One deny-list term with its explicit, stable id.
///
/// `id` is authored, never positional. The predecessor format derived a term's
/// "T-code" from its line number, which drifted the moment the file was
/// re-sorted and left older artifacts citing numbers that had moved.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IdentityTerm {
    pub id: String,
    pub term: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub class: Option<String>,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

/// The parsed term source.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct IdentityList {
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<u32>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub terms: Vec<IdentityTerm>,
    /// Global allows, applied to every term.
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
    /// Oldest cadence-hooks release that understands this file, when the
    /// author states one (`min_version = "0.110.0"`). Read by
    /// [`IdentityList::too_new_note`] only; scanning never depends on it.
    #[serde(default)]
    pub min_version: Option<String>,
    /// Regexes compiled once, on first scan, beside the parsed terms
    /// (cameronsjo/cadence-hooks#580).
    #[serde(skip)]
    compiled: std::sync::OnceLock<Compiled>,
}

/// The highest term-source `version` this binary understands.
pub(crate) const SUPPORTED_VERSION: u32 = 1;

/// Match regexes built from a list, index-aligned with its terms and allows.
#[derive(Debug, Clone, Default)]
struct Compiled {
    terms: Vec<Option<Regex>>,
    term_allows: Vec<Vec<Option<Regex>>>,
    global_allows: Vec<Option<Regex>>,
}

fn compile_allows(allows: &[AllowEntry]) -> Vec<Option<Regex>> {
    allows
        .iter()
        .map(|a| {
            a.pattern
                .as_deref()
                .filter(|p| !p.is_empty())
                .and_then(cached_regex)
        })
        .collect()
}

impl IdentityList {
    fn compiled(&self) -> &Compiled {
        self.compiled.get_or_init(|| Compiled {
            terms: self.terms.iter().map(|t| term_regex(&t.term)).collect(),
            term_allows: self
                .terms
                .iter()
                .map(|t| compile_allows(&t.allow))
                .collect(),
            global_allows: compile_allows(&self.allow),
        })
    }

    /// Does any allow entry carry a `destinations` scope? Lets the hook skip
    /// resolving a post's target (a `git` spawn) when nothing could use it.
    pub fn uses_destinations(&self) -> bool {
        self.allow
            .iter()
            .chain(self.terms.iter().flat_map(|t| t.allow.iter()))
            .any(|a| !a.destinations.is_empty())
    }

    /// Why this binary cannot fully read the file, when the file says it needs
    /// something newer: a `version` above [`SUPPORTED_VERSION`], or a
    /// `min_version` above this release. `None` for a file this binary reads.
    /// The scan still runs on such a file (fail-open direction is unchanged);
    /// this is the line an operator needs to know to upgrade.
    pub fn too_new_note(&self) -> Option<String> {
        let running = env!("CARGO_PKG_VERSION");
        if let Some(min) = self.min_version.as_deref()
            && version_newer(min, running)
        {
            return Some(format!(
                "term source requires cadence-hooks >= {min} (this binary is {running}); \
                 run: brew update && brew upgrade cadence-hooks"
            ));
        }
        match self.version {
            Some(v) if v > SUPPORTED_VERSION => Some(format!(
                "term source is format version {v}, newer than the {SUPPORTED_VERSION} this \
                 binary ({running}) reads; upgrade cadence-hooks — the file's `min_version` \
                 names the minimum release when it states one"
            )),
            _ => None,
        }
    }

    /// Is the tier armed? An empty term list is treated exactly like an absent
    /// file — inert, and surfaced by [`status`]. A file that parses but carries
    /// no terms is the silent-disarm shape, not a configuration choice.
    pub fn is_armed(&self) -> bool {
        !self.terms.is_empty()
    }

    /// Number of terms — what `--status` reports as `term_count`.
    pub fn term_count(&self) -> usize {
        self.terms.len()
    }

    /// A fingerprint of the enforced content, not of the file: the first 12 hex
    /// characters of the SHA-256 over the term values, each trimmed, sorted
    /// bytewise and joined by `\n`. Comments, ordering, ids, allow entries and
    /// formatting do not move it; adding, removing or substituting a term does
    /// (cameronsjo/cadence-hooks#589). Case is preserved on purpose — the
    /// provisioning script recomputes it in a different language.
    pub fn term_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut values: Vec<&str> = self.terms.iter().map(|t| t.term.trim()).collect();
        values.sort_unstable();
        let hex: String = Sha256::digest(values.join("\n").as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        hex[..12].to_string()
    }
}

/// Is dotted version `a` strictly newer than `b`? Non-numeric or missing
/// components read as 0, and an unparseable `a` is never newer (a typo in
/// `min_version` must not claim the binary is too old).
fn version_newer(a: &str, b: &str) -> bool {
    fn parts(v: &str) -> Option<[u64; 3]> {
        let mut out = [0u64; 3];
        for (slot, part) in out.iter_mut().zip(v.trim().split('.')) {
            *slot = part.parse().ok()?;
        }
        Some(out)
    }
    match (parts(a), parts(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// One identity match. Carries the term's authored id, never its text, for any
/// caller that logs — the block message names the term verbatim (ruled: the
/// threat model is irrevocable public artifacts, and a block you cannot act on
/// is not a control), but a log line is a different surface.
#[derive(Debug, Clone)]
pub(crate) struct IdentityHit {
    pub id: String,
    pub snippet: String,
    #[allow(dead_code)]
    pub offset: usize,
}

/// Why the tier is not scanning, when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// Armed and scanning, with the term count.
    Armed(usize),
    /// No file at the resolved path.
    Absent,
    /// File exists but could not be read — permissions, a directory, a special
    /// file, or over the bounded-read cap. **Notified exactly like `Absent`**:
    /// silent-inert on a permissions error is the same silent-disarm class the
    /// lenient-config work closed, and the operator cannot tell the difference
    /// from the outcome alone.
    Unreadable,
    /// Read, but did not parse as the expected schema.
    Malformed(String),
    /// Parsed, but carries zero terms.
    ZeroTerms,
}

impl Status {
    /// Should SessionStart surface this? Every non-armed state, by design.
    pub fn needs_notice(&self) -> bool {
        !matches!(self, Status::Armed(_))
    }
}

/// Resolve the term-source path: `$HOME/.config/cadence/redaction.toml`, and
/// nothing else.
///
/// # Why no environment override in production
///
/// An earlier revision honored `CADENCE_REDACTION_TERMS` and
/// `XDG_CONFIG_HOME`. A security review caught what that costs: a project's
/// `.claude/settings.json` `env` block reaches hook subprocesses, and this
/// codebase already documents those blocks as attacker-influenceable
/// (`crates/metrics/src/warn_stale.rs` — the reasoning that put `CADENCE_DISABLE`
/// behind `PROTECTED_GUARDS`). So `{"env": {"CADENCE_REDACTION_TERMS":
/// "/dev/null"}}` in a cloned repo would resolve to an absent file, load an
/// empty list, and fail open — **a silent disarm through a door neither
/// softening call site guards, because it sits upstream of both.**
///
/// That is the same disarm `PROTECTED_GUARDS` exists to prevent, arriving by a
/// different variable, so it gets the same answer. It does not require an
/// adversary either: a repo that sets `XDG_CONFIG_HOME` for its own unrelated
/// reasons disarms the tier by accident, which is squarely inside this estate's
/// threat model.
///
/// The cost is that a non-standard config location is unsupported. Accepted:
/// the override's only real consumers were tests, and an escape hatch that a
/// committed file can pull is not an escape hatch, it is a hole. If a genuine
/// need appears, it must come from a source no repo can write.
pub(crate) fn terms_path() -> Option<PathBuf> {
    #[cfg(test)]
    if let Ok(p) = std::env::var("CADENCE_REDACTION_TERMS")
        && !p.is_empty()
    {
        return Some(PathBuf::from(p));
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("cadence")
                .join("redaction.toml")
        })
}

/// Is this edit targeting the term source itself?
///
/// # Why this exemption has to exist
///
/// The term source contains every term, so writing a term into it is, by the
/// introduced-only rule, "introducing" one — and the tier blocks. That makes
/// the deny-list **unmaintainable through the harness**: adding a term is
/// exactly the edit the guard refuses. Worse, the block message tells the
/// operator to add an `allow` entry *in the term source*, which is the edit it
/// just blocked. A perfectly circular instruction.
///
/// Writing terms into the deny-list is definitionally legitimate — it is what
/// the file is for. Same reasoning that makes the removal edit possible: a
/// guard that cannot be maintained gets bypassed or disabled, and then it
/// protects nothing.
///
/// # Fail direction
///
/// Defaults to **false** (scan) whenever the answer is not certain. A false
/// positive here would exempt an arbitrary file from the identity scan, which
/// is the far worse error — so an unresolvable path is scanned, not skipped.
/// Both the literal and canonicalized comparisons are tried, because the file
/// may not exist yet (the first write that creates it) and because `HOME` is
/// often a symlink.
pub(crate) fn is_term_source(file_path: Option<&str>) -> bool {
    let Some(fp) = file_path.filter(|p| !p.is_empty()) else {
        return false;
    };
    let Some(terms) = terms_path() else {
        return false;
    };
    let target = std::path::Path::new(fp);
    if target == terms {
        return true;
    }
    // Canonicalize both when the paths exist — resolves symlinked HOME and the
    // /tmp vs /private/tmp split. Any failure falls through to `false`.
    match (target.canonicalize(), terms.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Load the term source, returning both the list and why it is what it is.
///
/// Every failure yields an empty list — the guard's own failure is fail-open.
/// The [`Status`] is what keeps that from being silent.
pub(crate) fn load() -> (IdentityList, Status) {
    let Some(path) = terms_path() else {
        return (IdentityList::default(), Status::Absent);
    };
    load_from(&path)
}

/// [`load`] against an explicit path — the one reader both the resolved term
/// source and a test fixture go through.
pub(crate) fn load_from(path: &std::path::Path) -> (IdentityList, Status) {
    if !path.exists() {
        return (IdentityList::default(), Status::Absent);
    }
    // Same bounded, regular-file-only reader the body-file path uses: a symlink
    // to /dev/zero or a multi-GB file must not hang the hook (#157/#194).
    let Some(raw) = cadence_hooks_core::paths::read_untrusted_config(path) else {
        return (IdentityList::default(), Status::Unreadable);
    };
    match toml::from_str::<IdentityList>(&raw) {
        Ok(list) => {
            if list.is_armed() {
                let n = list.terms.len();
                (list, Status::Armed(n))
            } else {
                (list, Status::ZeroTerms)
            }
        }
        // The parse error names a line/column but never the file's content —
        // safe to surface.
        Err(e) => (
            IdentityList::default(),
            Status::Malformed(e.message().to_string()),
        ),
    }
}

/// Structural problems the runtime swallows, named for
/// `redact-scan --validate-config`: a term with no text (never matches), an
/// allow `pattern` that is not a regex (never excuses), a `destinations` entry
/// that is neither `owner/repo` nor `owner/*` (never matches), an unreadable
/// `min_version`. Each is inert at runtime, which is exactly why it is worth
/// saying out loud once.
pub(crate) fn validate(list: &IdentityList) -> Vec<String> {
    let mut errors = Vec::new();
    let check_allows = |errors: &mut Vec<String>, owner: &str, allows: &[AllowEntry]| {
        for (i, a) in allows.iter().enumerate() {
            if let Some(pat) = a.pattern.as_deref().filter(|p| !p.is_empty())
                && let Err(e) = Regex::new(pat)
            {
                let first = e.to_string().lines().last().unwrap_or("").to_string();
                errors.push(format!(
                    "{owner} allow[{i}].pattern is not a valid regex: {first}"
                ));
            }
            for d in &a.destinations {
                let ok = match d.trim().strip_suffix("/*") {
                    Some(o) => !o.is_empty() && !o.contains('/') && !o.contains('*'),
                    None => {
                        let mut it = d.trim().split('/');
                        matches!(
                            (it.next(), it.next(), it.next()),
                            (Some(o), Some(r), None)
                                if !o.is_empty() && !r.is_empty() && !d.contains('*')
                        )
                    }
                };
                if !ok {
                    errors.push(format!(
                        "{owner} allow[{i}].destinations entry {d:?} must be `owner/repo` or `owner/*`"
                    ));
                }
            }
        }
    };
    for t in &list.terms {
        if t.term.trim().is_empty() {
            errors.push(format!("term {:?} has an empty `term`", t.id));
        }
        check_allows(&mut errors, &format!("term {:?}", t.id), &t.allow);
    }
    check_allows(&mut errors, "global", &list.allow);
    if let Some(min) = list.min_version.as_deref()
        && !min.trim().split('.').all(|p| p.parse::<u64>().is_ok())
    {
        errors.push(format!(
            "min_version {min:?} is not a dotted numeric version"
        ));
    }
    errors
}

/// Build the match regex for one term: case-insensitive, and word-boundary
/// anchored only on the sides where the term's own edge is a word character
/// (an unconditional `\b` around a term starting with `.` or `/` would never
/// match). Multi-word terms match across space, hyphen, and underscore, because
/// that is how the same name is spelled in prose, in a hostname, and in a slug.
fn term_regex(term: &str) -> Option<Regex> {
    let t = term.trim();
    if t.is_empty() {
        return None;
    }
    // `regex::escape` leaves spaces untouched (they are not regex metachars),
    // so a single replace on the bare space is the whole job — an earlier
    // version also replaced `"\\ "`, which never matched anything.
    let body = regex::escape(t).replace(' ', "[ _-]");
    let starts_word = t
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let ends_word = t
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let pattern = format!(
        "(?i){}{}{}",
        if starts_word { r"\b" } else { "" },
        body,
        if ends_word { r"\b" } else { "" }
    );
    cached_regex(&pattern)
}

/// Compile `pattern` once per process. A scan runs once per posted text, and
/// one command can post tens of thousands of texts (every `gh api` field,
/// every repeated flag); recompiling each term and allow pattern per text
/// took a 200 KB command past the hook deadline, where the guard fails open.
/// The cache is bounded by the term source and repo config, which a command
/// cannot grow. An invalid pattern caches as `None`.
pub(super) fn cached_regex(pattern: &str) -> Option<Regex> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static CACHE: RefCell<HashMap<String, Option<Regex>>> = RefCell::new(HashMap::new());
    }
    CACHE.with(|cache| {
        cache
            .borrow_mut()
            .entry(pattern.to_string())
            .or_insert_with(|| Regex::new(pattern).ok())
            .clone()
    })
}

/// Does a destination scope admit this post target? Empty scope admits every
/// target (it is no restriction). A non-empty scope admits only a resolved
/// `destination` (`owner/repo`, lowercase) equal to an `owner/repo` element or
/// covered by an `owner/*` one.
fn destination_admits(scope: &[String], destination: Option<&str>) -> bool {
    if scope.is_empty() {
        return true;
    }
    let Some(dest) = destination else {
        return false;
    };
    let dest = dest.to_ascii_lowercase();
    scope.iter().any(|pat| {
        let pat = pat.trim().to_ascii_lowercase();
        match pat.strip_suffix("/*") {
            Some(owner) => {
                !owner.is_empty()
                    && !owner.contains('/')
                    && dest.split_once('/').is_some_and(|(o, _)| o == owner)
            }
            None => pat == dest,
        }
    })
}

/// Does an allow entry excuse this match?
///
/// `path` is a containment test against the scanned surface's file path (absent
/// for a commit message, so a path-only allow never fires there). `pattern` is
/// a regex against the full scanned text — the form that expresses "this term,
/// in this sentence, is the English word." `destinations` limits either (or
/// stands alone) to posts targeting the named repos; see [`AllowEntry`].
fn is_allowed(
    entry: &AllowEntry,
    pattern: Option<&Regex>,
    text: &str,
    file_path: Option<&str>,
    destination: Option<&str>,
) -> bool {
    if !destination_admits(&entry.destinations, destination) {
        return false;
    }
    let path = entry.path.as_deref().filter(|p| !p.is_empty());
    let has_pattern = entry.pattern.as_deref().is_some_and(|p| !p.is_empty());
    if path.is_none() && !has_pattern {
        // Only a destination scope can make a clause-less entry live.
        return !entry.destinations.is_empty();
    }
    if let Some(p) = path
        && file_path.is_some_and(|fp| fp.contains(p))
    {
        return true;
    }
    pattern.is_some_and(|re| re.is_match(text))
}

/// Scan `text` for identity terms.
///
/// **Config-blind by signature.** There is no `RedactionConfig` parameter, no
/// audience tier, no repo allowlist — so no committed file can reach this
/// function's behavior even by future accident. That is the type-level half of
/// the same property [`super::ConfigScope::SourceFileOnly`] enforces for the
/// shaped-tier call sites. `destination` is the resolved `owner/repo` of the
/// post (a fact about the command, never read from a repo file); it only ever
/// lets the term source's own `destinations`-scoped allows apply.
pub(crate) fn scan_identity(
    text: &str,
    list: &IdentityList,
    file_path: Option<&str>,
    destination: Option<&str>,
) -> Vec<IdentityHit> {
    if !list.is_armed() {
        return Vec::new();
    }
    let compiled = list.compiled();
    let mut hits: Vec<IdentityHit> = Vec::new();
    for (i, term) in list.terms.iter().enumerate() {
        let Some(re) = compiled.terms[i].as_ref() else {
            continue;
        };
        // A term-level or global allow excusing this context skips the term.
        let excused = term
            .allow
            .iter()
            .zip(&compiled.term_allows[i])
            .chain(list.allow.iter().zip(&compiled.global_allows))
            .any(|(a, pat)| is_allowed(a, pat.as_ref(), text, file_path, destination));
        if excused {
            continue;
        }
        for m in re.find_iter(text) {
            hits.push(IdentityHit {
                id: term.id.clone(),
                snippet: m.as_str().to_string(),
                offset: m.start(),
            });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_of(terms: &[(&str, &str)]) -> IdentityList {
        IdentityList {
            version: Some(1),
            mode: Mode::Enforce,
            terms: terms
                .iter()
                .map(|(id, t)| IdentityTerm {
                    id: (*id).to_string(),
                    term: (*t).to_string(),
                    class: None,
                    allow: Vec::new(),
                })
                .collect(),
            allow: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn matches_case_insensitively() {
        let l = list_of(&[("T1", "acmecorp")]);
        assert_eq!(
            scan_identity("We use AcmeCorp here", &l, None, None).len(),
            1
        );
    }

    #[test]
    fn respects_word_boundaries() {
        let l = list_of(&[("T1", "acme")]);
        // `acmecorp` must not match the shorter standalone term.
        assert!(scan_identity("acmecorp tooling", &l, None, None).is_empty());
        assert_eq!(scan_identity("the acme tool", &l, None, None).len(), 1);
    }

    #[test]
    fn multiword_matches_across_separators() {
        let l = list_of(&[("T9", "acme widget")]);
        for spelling in ["acme widget", "acme-widget", "acme_widget", "Acme Widget"] {
            assert_eq!(
                scan_identity(spelling, &l, None, None).len(),
                1,
                "should match: {spelling}"
            );
        }
    }

    #[test]
    fn hostname_with_dots_matches() {
        let l = list_of(&[("T5", "ghe.example.com")]);
        assert_eq!(
            scan_identity("push to ghe.example.com/org/repo", &l, None, None).len(),
            1
        );
    }

    #[test]
    fn empty_list_is_inert() {
        let l = IdentityList::default();
        assert!(!l.is_armed());
        assert!(scan_identity("acmecorp", &l, None, None).is_empty());
    }

    #[test]
    fn mode_defaults_to_enforce() {
        // The ruled default: shipping disabled "does no good".
        let parsed: IdentityList = toml::from_str("version = 1\n").expect("parses");
        assert_eq!(parsed.mode, Mode::Enforce);
    }

    #[test]
    fn mode_warn_parses_when_stated() {
        let parsed: IdentityList = toml::from_str("mode = \"warn\"\n").expect("parses");
        assert_eq!(parsed.mode, Mode::Warn);
    }

    #[test]
    fn pattern_allow_excuses_the_english_collision() {
        let mut l = list_of(&[("T8", "clarion")]);
        l.terms[0].allow.push(AllowEntry {
            path: None,
            pattern: Some(r"(?i)clarion\s+(call|bell)".to_string()),
            ..Default::default()
        });
        assert!(scan_identity("a clarion call to arms", &l, None, None).is_empty());
        assert_eq!(
            scan_identity("the clarion platform", &l, None, None).len(),
            1
        );
    }

    #[test]
    fn path_allow_only_fires_when_a_path_is_present() {
        let mut l = list_of(&[("T8", "clarion")]);
        l.terms[0].allow.push(AllowEntry {
            path: Some("test_fixtures.py".to_string()),
            pattern: None,
            ..Default::default()
        });
        assert!(scan_identity("clarion", &l, Some("a/test_fixtures.py"), None).is_empty());
        // A commit message has no path — the allow cannot fire there.
        assert_eq!(scan_identity("clarion", &l, None, None).len(), 1);
    }

    #[test]
    fn global_allow_applies_to_every_term() {
        let mut l = list_of(&[("T1", "acmecorp"), ("T2", "widgetco")]);
        l.allow.push(AllowEntry {
            path: Some("docs/redaction-tests/".to_string()),
            pattern: None,
            ..Default::default()
        });
        assert!(
            scan_identity(
                "acmecorp and widgetco",
                &l,
                Some("docs/redaction-tests/fixtures.md"),
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn malformed_toml_is_fail_open_with_a_named_status() {
        // Not via load() (which reads the real path) — parse directly.
        let err = toml::from_str::<IdentityList>("terms = [ this is not toml").unwrap_err();
        assert!(!err.message().is_empty());
    }

    #[test]
    fn status_notices_every_unarmed_state() {
        assert!(!Status::Armed(3).needs_notice());
        for s in [
            Status::Absent,
            Status::Unreadable,
            Status::ZeroTerms,
            Status::Malformed("x".into()),
        ] {
            assert!(s.needs_notice(), "{s:?} must notify");
        }
    }

    #[test]
    fn identity_ignores_a_term_the_repo_allowlist_would_suppress() {
        // Replaces an earlier `assert_signature` test that only type-checked —
        // it would have passed at runtime no matter what the function did,
        // because a changed signature fails compilation rather than the test.
        //
        // This asserts the property behaviorally instead: the exact string that
        // a repo's allowlist DOES suppress in a shaped category is still a hit
        // here. The shaped-side half of the pair lives in the parent module's
        // `allowlist_bare_term_suppresses_matching_harness_noun`, which proves
        // the same entry genuinely suppresses there — so together they show the
        // divergence is the identity pass ignoring config, not the term simply
        // never matching anything.
        let l = list_of(&[("T1", "tool_input")]);
        let hits = scan_identity("the tool_input field", &l, None, None);
        assert_eq!(
            hits.len(),
            1,
            "identity must flag a term that repo config allowlists for shaped categories"
        );
        assert_eq!(hits[0].id, "T1");
    }

    fn with_allow(entry: AllowEntry) -> IdentityList {
        let mut l = list_of(&[("T1", "acmecorp")]);
        l.terms[0].allow.push(entry);
        l
    }

    #[test]
    fn destination_scope_table() {
        // (scope, destination, excused?)
        let table: &[(&[&str], Option<&str>, bool)] = &[
            (&["me/tool"], Some("me/tool"), true),
            (&["Me/Tool"], Some("me/TOOL"), true),
            (&["me/*"], Some("me/anything"), true),
            (&["me/*"], Some("other/anything"), false),
            (&["me/*"], Some("menace/x"), false),
            (&["me/tool"], Some("me/other"), false),
            (&["a/b", "c/*"], Some("c/d"), true),
            // Unknown destination never satisfies a scope.
            (&["me/*"], None, false),
            // Malformed scope entries match nothing.
            (&["*"], Some("me/tool"), false),
            (&["*/*"], Some("me/tool"), false),
            (&["me"], Some("me/tool"), false),
            (&["/*"], Some("me/tool"), false),
            (&["a/b/*"], Some("a/b/c"), false),
        ];
        for (scope, dest, want) in table {
            let l = with_allow(AllowEntry {
                destinations: scope.iter().map(|s| (*s).to_string()).collect(),
                ..Default::default()
            });
            let hits = scan_identity("acmecorp", &l, None, *dest);
            assert_eq!(hits.is_empty(), *want, "scope {scope:?} dest {dest:?}");
        }
    }

    #[test]
    fn destination_scope_is_anded_with_path_and_pattern() {
        let l = with_allow(AllowEntry {
            pattern: Some("acme".into()),
            destinations: vec!["me/*".into()],
            ..Default::default()
        });
        // Both must hold: pattern matches, destination in scope.
        assert!(scan_identity("acmecorp", &l, None, Some("me/x")).is_empty());
        assert_eq!(scan_identity("acmecorp", &l, None, Some("out/x")).len(), 1);
        assert_eq!(scan_identity("acmecorp", &l, None, None).len(), 1);
        let l = with_allow(AllowEntry {
            pattern: Some("no-such-text".into()),
            destinations: vec!["me/*".into()],
            ..Default::default()
        });
        assert_eq!(scan_identity("acmecorp", &l, None, Some("me/x")).len(), 1);
    }

    #[test]
    fn an_entry_with_no_clause_at_all_stays_inert() {
        let l = with_allow(AllowEntry::default());
        assert_eq!(scan_identity("acmecorp", &l, None, Some("me/x")).len(), 1);
    }

    #[test]
    fn global_destination_scoped_allow_applies_to_every_term() {
        let mut l = list_of(&[("T1", "acmecorp"), ("T2", "widgetco")]);
        l.allow.push(AllowEntry {
            destinations: vec!["me/*".into()],
            ..Default::default()
        });
        assert!(scan_identity("acmecorp widgetco", &l, None, Some("me/x")).is_empty());
        assert_eq!(scan_identity("acmecorp widgetco", &l, None, None).len(), 2);
    }

    #[test]
    fn regexes_compile_once_and_scans_agree() {
        let mut l = list_of(&[("T1", "acmecorp")]);
        l.terms[0].allow.push(AllowEntry {
            pattern: Some("(?i)acmecorp\\s+holiday".into()),
            ..Default::default()
        });
        assert!(std::ptr::eq(l.compiled(), l.compiled()));
        for _ in 0..3 {
            assert_eq!(scan_identity("acmecorp here", &l, None, None).len(), 1);
            assert!(scan_identity("acmecorp holiday", &l, None, None).is_empty());
        }
    }

    #[test]
    fn term_digest_tracks_content_not_formatting() {
        let digest = |src: &str| toml::from_str::<IdentityList>(src).unwrap().term_digest();
        let base =
            digest("[[terms]]\nid=\"T1\"\nterm=\"alpha\"\n[[terms]]\nid=\"T2\"\nterm=\"beta\"\n");
        // Order, ids, comments, allow entries and whitespace do not move it.
        assert_eq!(
            base,
            digest(
                "# note\n[[terms]]\nid=\"Z9\"\nterm=\" beta \"\n[[terms]]\nid=\"T1\"\nterm=\"alpha\"\n[[terms.allow]]\npath=\"x\"\n"
            )
        );
        // A substitution with the count unchanged moves it — the 19-vs-18 class.
        assert_ne!(
            base,
            digest("[[terms]]\nid=\"T1\"\nterm=\"alpha\"\n[[terms]]\nid=\"T2\"\nterm=\"gamma\"\n")
        );
        // So does a dropped term.
        assert_ne!(base, digest("[[terms]]\nid=\"T1\"\nterm=\"alpha\"\n"));
        assert_eq!(base.len(), 12);
        // Pinned value: scripts/replicate-redaction-terms.sh recomputes this in
        // Python, so the algorithm is a contract. sha256("alpha\nbeta")[..12].
        assert_eq!(base, "bbfb79e82216");
    }

    #[test]
    fn version_newer_table() {
        let table: &[(&str, &str, bool)] = &[
            ("0.114.0", "0.113.0", true),
            ("0.113.0", "0.113.0", false),
            ("0.9.0", "0.113.0", false),
            ("1.0.0", "0.999.9", true),
            ("1", "0.5.0", true),
            ("", "0.1.0", false),
            ("soon", "0.1.0", false),
            ("1.x.0", "0.1.0", false),
        ];
        for (a, b, want) in table {
            assert_eq!(version_newer(a, b), *want, "{a} vs {b}");
        }
    }

    #[test]
    fn validate_names_each_swallowed_problem() {
        let l: IdentityList = toml::from_str(
            "min_version = \"x\"\n[[terms]]\nid=\"T1\"\nterm=\"\"\n[[terms.allow]]\npattern=\"(\"\ndestinations=[\"bad\"]\n",
        )
        .unwrap();
        let errs = validate(&l);
        assert_eq!(errs.len(), 4, "{errs:?}");
        assert!(validate(&list_of(&[("T1", "x")])).is_empty());
    }
}
