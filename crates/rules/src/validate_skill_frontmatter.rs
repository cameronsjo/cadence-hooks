//! Validate YAML frontmatter in skill and command markdown files.
//!
//! Checks that `SKILL.md` and command `.md` files have valid frontmatter
//! with required fields, kebab-case names, and no unknown keys.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

const VALID_FIELDS: &[&str] = &[
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
    "argument-hint",
    "arguments",
    "disallowed-tools",
    "disable-model-invocation",
    "user-invocable",
    "model",
    "context",
    "background",
    "agent",
    "hooks",
    "paths",
    "when_to_use",
    "effort",
    "shell",
];

// House strictness: boolean fields take exactly `true` or `false`. The
// platform (Claude Code >= 2.1.218) also accepts yes/no/on/off/1/0 —
// cadence deliberately does not: one spelling keeps the corpus greppable.
const BOOLEAN_FIELDS: &[&str] = &["background", "disable-model-invocation", "user-invocable"];

// Enum fields: value must be exactly one of the listed options (same
// unquoted-only house strictness as BOOLEAN_FIELDS). Sets verified against
// the raw Claude Code docs (code.claude.com/docs/en/skills), not assumed.
const ENUM_FIELDS: &[(&str, &[&str])] = &[
    ("effort", &["low", "medium", "high", "xhigh", "max"]),
    ("shell", &["bash", "powershell"]),
];

// Kebab-case name with NO namespace prefix — a colon is rejected outright.
//
// Claude Code owns the prefix: it builds a skill's invocation id from
// `<plugin>:<directory>` and prepends the prefix itself, so a declared
// `cadence:attune` renders as `/cadence:cadence:attune`. Release 2.1.216
// ("fixed plugin skills with a `name` frontmatter field losing their plugin
// prefix in slash-command autocomplete") is what made the prefix doubling;
// 2.1.218 then made agent markdown reject `:` in a name for the same reason,
// reserving the character for plugin namespacing.
//
// This pattern previously allowed an optional `namespace:` prefix (0.19.0),
// because 2.1.94 had made plugin skills use the frontmatter `name` as the
// invocation name — which made the prefixed form render correctly. That is the
// convention this reverses.
//
// IF THE PLATFORM FLIPS BACK — de-duplication is requested upstream in
// anthropics/claude-code#80631; watch that issue — the order matters:
// relax this pattern and SHIP A RELEASE FIRST, then
// sweep the corpus with `cadence/scripts/skill-names.py --prefixed`. Tightened
// as it stands, this check blocks every edit to a prefixed SKILL.md — including
// the sweep that would undo it. Restoring the old form means re-adding the
// optional trailing group `(:[a-z0-9]+(-[a-z0-9]+)*)?` and the `rsplit_once`
// suffix comparison in `run` below.
static NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").expect("pattern should compile"));

#[derive(Debug, PartialEq)]
enum FileType {
    Skill,
    Command,
    /// A plugin-distributed agent definition (`<plugin>/agents/*.md`).
    Agent,
    /// An agent definition outside a plugin (`.claude/agents/*.md`): honours
    /// every field, but `skills`/`mcpServers` are still ignored when the
    /// definition spawns a teammate.
    ProjectAgent,
    /// A living plan (`docs/plans/*.md`).
    Plan,
    Other,
}

/// Upper bound on a path we will scan. Past this we classify as `Other` rather
/// than walk it: `file_path` is unbounded agent-supplied input, and the scan
/// below pays a `stat` per candidate directory, so an absurd path is a way to
/// stall the hook. Failing open here matches ADR-0001 — a guard that times out
/// protects nobody either.
const MAX_PATH_BYTES: usize = 4096;

/// Split a path into segments, dropping what carries no meaning (`//` and
/// `/./`) and folding `..`, so the classifier sees the directory the write
/// actually lands in.
///
/// `normalize_path` upstream (`crates/core`) only maps `\` to `/`, strips NULs,
/// and trims trailing slashes — it does none of this — so `/repo/.claude//commands/x.md`
/// and `/repo/.claude/./commands/x.md` arrive verbatim. Comparing raw segments
/// would see `""` or `"."` as the parent and miss a real command definition.
///
/// Returns the absolute ROOT PREFIX alongside the segments, because the two
/// supported platforms spell it differently and the marker probe has to
/// reconstruct a real path from them. On Unix the prefix is `/`; on Windows a
/// path reaches us as `C:/Users/...` — `normalize_path` maps `\` to `/` but
/// leaves the drive letter — so the prefix is `C:/` and rebuilding with a
/// leading slash would produce `/C:/Users/...`, which stats nothing.
///
/// `None` means "do not classify": a relative path, or one past the size bound.
/// Relative paths are refused because the marker probe below resolves against
/// the hook process's cwd, so the same path would classify differently
/// depending on where the process happens to stand.
///
/// The Windows case is easy to lose and expensive when lost: every test fixture
/// in this file is a Unix-style string, which is a perfectly valid input on
/// either platform, so a predicate that rejects `C:/...` disables the whole
/// command arm on Windows with the suite fully green. `windows_drive_paths_still_classify`
/// is the control for that.
fn normalized_segments(path: &str) -> Option<(&str, Vec<&str>)> {
    if path.len() > MAX_PATH_BYTES {
        return None;
    }
    let (prefix, rest) = if let Some(rest) = path.strip_prefix('/') {
        ("/", rest)
    } else if path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/')
    {
        (&path[..3], &path[3..])
    } else {
        return None;
    };

    let mut segments: Vec<&str> = Vec::new();
    for raw in rest.split('/') {
        match raw {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    Some((prefix, segments))
}

/// Is `segments` — the directory that holds a `commands/` or `skills/` tree —
/// somewhere Claude Code actually loads definitions from?
///
/// Three shapes:
///
/// 1. A config directory: user (`~/.claude`) or project (`<repo>/.claude`) —
///    and whatever `CLAUDE_CONFIG_DIR` names, per [`CONFIG_DIR_NAME`].
/// 2. A plugin root, identified by its sibling `.claude-plugin/` marker. This
///    covers the installed cache (`<cache>/<marketplace>/<plugin>/<sha>/`), the
///    monorepo's `plugins/<plugin>/`, and a standalone plugin repo root alike —
///    all 14 plugins in the cadence monorepo carry the marker, so nothing needs
///    a `plugins/` path-segment rule to be recognised.
/// 3. A repo that is itself a Claude workspace, identified by a sibling
///    `.claude/` directory. This is the SYMLINK-FARM layout: `cmux` keeps its
///    20 skills at `cmux/skills/<name>/` and links them in from
///    `cmux/.claude/skills/<name>`, so the canonical path an agent edits — the
///    link TARGET — has no `.claude` ancestor at all and rule 1 never sees it.
///    Narrow by construction: the candidate root is the `skills/` or
///    `commands/` parent, so `<repo>/docs/skills/…` asks about `<repo>/docs`,
///    which is not a workspace, and stays documentation.
///
/// An earlier draft of this fix DID carry that extra rule — accept any
/// `plugins/<name>/commands/` triple — as a fast path to skip the `stat`. It
/// reintroduced the very bug being fixed one directory deeper:
/// `<repo>/docs/plugins/<name>/commands/overview.md` is documentation ABOUT
/// plugins and was hard-blocked by it. The marker covers every real instance,
/// so the fast path bought one `stat` and cost a false block.
///
/// Comparisons are ASCII-case-insensitive because APFS and NTFS are: a write to
/// `/repo/.Claude/commands/x.md` lands in the real `.claude` directory, and a
/// case-sensitive compare would let it skip validation.
///
/// Fails OPEN: an absent or unreadable marker classifies as `Other`, so the
/// guard's own I/O trouble can never block an edit (ADR-0001). The known cost is
/// a missed nudge on a plugin being scaffolded whose `.claude-plugin/` does not
/// exist yet — the cheaper failure, since a guardrail's real price is a false
/// block on legitimate work, not a missed nudge.
/// Is this path segment a Claude config directory?
///
/// Pure and parameterised over the config-dir name **so it can be tested**.
/// [`CONFIG_DIR_NAME`] is a process-lifetime cache, and on a machine whose
/// `CLAUDE_CONFIG_DIR` is unset it resolves to `.claude` — so a test written
/// against the cache passes identically whether or not the relocated-dir rule
/// exists, which is no test at all. Passing the name in is what lets a control
/// go red.
fn is_config_dir_segment(segment: &str, config_dir_name: &str) -> bool {
    segment.eq_ignore_ascii_case(".claude") || segment.eq_ignore_ascii_case(config_dir_name)
}

fn is_definition_root(prefix: &str, segments: &[&str]) -> bool {
    if segments
        .last()
        .is_some_and(|parent| is_config_dir_segment(parent, &CONFIG_DIR_NAME))
    {
        return true;
    }
    if segments.is_empty() {
        return false;
    }
    let root = std::path::Path::new(prefix).join(segments.join("/"));
    root.join(".claude-plugin").is_dir() || root.join(".claude").is_dir()
}

/// The basename of the ACTIVE config dir, which is `.claude` by default but is
/// whatever `CLAUDE_CONFIG_DIR` names when a second subscription profile is in
/// use (`claude-as` runs one; `~/.claude-alt` holds 26 live skills). Matching
/// only the literal `.claude` silently stops validating every definition in
/// that profile — the same six rules, no error, no signal.
///
/// The binary already resolves this correctly for every other purpose
/// (`cadence_hooks_core::paths::claude_config_dir`); the classifier simply
/// never asked. Cached because a hook is a short-lived process and the env does
/// not move underneath it.
static CONFIG_DIR_NAME: LazyLock<String> = LazyLock::new(|| {
    cadence_hooks_core::paths::claude_config_dir()
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| ".claude".to_string())
});

/// Does this path pass through a `<kind>/` directory that a definition root
/// actually owns — `commands` for slash commands, `skills` for skills?
///
/// Both arms were once a bare substring test (`contains("/commands/")`,
/// `contains("/skills/")`), and both swept in ordinary project documentation:
/// `<repo>/docs/commands/*.md` is a natural home for a CLI's per-command-group
/// pages (forgectl keeps nine, none of which has or should have YAML
/// frontmatter), and `<repo>/docs/skills/<x>/SKILL.md` is the same thing one
/// noun over. Every edit to those files was hard-blocked for "missing
/// frontmatter", with no way forward but adding meaningless frontmatter or
/// bypassing the guard (cameronsjo/cadence-hooks#802 for commands,
/// cameronsjo/cadence-hooks#806 for skills).
///
/// One predicate rather than two near-identical ones, deliberately: the whole
/// lesson of #806 is that fixing one arm and leaving its twin is how the defect
/// survives. A shared function cannot drift apart.
fn is_definition_of(kind: &str, prefix: &str, segments: &[&str]) -> bool {
    segments.iter().enumerate().any(|(i, segment)| {
        segment.eq_ignore_ascii_case(kind) && is_definition_root(prefix, &segments[..i])
    })
}

fn classify_path(path: &str) -> FileType {
    let Some((prefix, segments)) = normalized_segments(path) else {
        return FileType::Other;
    };
    // The filename tests are ASCII-case-insensitive for the same reason the
    // directory tests are: on APFS and NTFS a write to `Skill.md` lands in the
    // loaded `SKILL.md`, so a case-sensitive compare here would let it skip
    // validation while the case-folding rationale on `is_definition_root`
    // claimed otherwise.
    let is_skill_file = segments
        .last()
        .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"));
    let is_markdown = segments
        .last()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".md"));

    if is_skill_file && is_definition_of("skills", prefix, &segments) {
        FileType::Skill
    } else if is_markdown && is_definition_of("commands", prefix, &segments) {
        FileType::Command
    } else if is_markdown && is_plugin_agent(prefix, &segments) {
        FileType::Agent
    } else if is_markdown && is_definition_of("agents", prefix, &segments) {
        FileType::ProjectAgent
    } else if is_markdown && is_plan_path(&segments) {
        FileType::Plan
    } else {
        FileType::Other
    }
}

/// Is this an agent definition inside a PLUGIN — an `agents/` directory whose
/// parent carries a `.claude-plugin/` marker? `<repo>/.claude/agents/` is
/// deliberately not matched: `hooks`, `mcpServers` and `permissionMode` are
/// honoured there, so the silent-ignore warning would be false. Fails open on
/// an absent marker, like [`is_definition_root`].
fn is_plugin_agent(prefix: &str, segments: &[&str]) -> bool {
    segments.iter().enumerate().any(|(i, segment)| {
        i > 0
            && i + 1 < segments.len()
            && segment.eq_ignore_ascii_case("agents")
            && std::path::Path::new(prefix)
                .join(segments[..i].join("/"))
                .join(".claude-plugin")
                .is_dir()
    })
}

/// `docs/plans/<name>.md` — a direct child only, so nested docs stay out.
fn is_plan_path(segments: &[&str]) -> bool {
    let n = segments.len();
    n >= 3
        && segments[n - 2].eq_ignore_ascii_case("plans")
        && segments[n - 3].eq_ignore_ascii_case("docs")
}

fn extract_frontmatter(content: &str) -> Option<Vec<(String, String)>> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.first() != Some(&"---") {
        return None;
    }

    let end = lines[1..].iter().position(|l| *l == "---")?;
    let fm_lines = &lines[1..=end];

    let mut fields = Vec::new();
    for line in fm_lines {
        // Indented lines are nested keys (e.g. `author:` under `metadata:`) —
        // only top-level keys are validated against VALID_FIELDS. The check
        // must run on the raw line: after `.trim()` every key looks top-level.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            if !key.is_empty() {
                fields.push((key, value));
            }
        }
    }

    Some(fields)
}

/// Extract directory name for a skill path (parent of SKILL.md).
fn skill_dir_name(path: &str) -> Option<&str> {
    // Derive from the SAME normalised view `classify_path` uses, not from the
    // raw string. The two were on different path models, and the gap was a
    // false BLOCK: `/repo/.claude/skills/my-skill/./SKILL.md` classifies as a
    // skill (that is what normalisation is for), but a raw
    // `strip_suffix` + `rsplit` then reported the directory as "." and rejected
    // a perfectly valid `name: my-skill` with "must match directory '.'".
    // `//` gave the same result with an empty string.
    //
    // `normalize_path` upstream does not collapse those shapes, so they do
    // reach production — `unnormalized_shapes_still_reach_the_command_arm` is
    // the standing evidence. Deriving both from one view is what keeps the
    // classifier and the name rule from disagreeing about the same path.
    let (_prefix, segments) = normalized_segments(path)?;
    if !segments.last()?.eq_ignore_ascii_case("SKILL.md") {
        return None;
    }
    segments.get(segments.len().checked_sub(2)?).copied()
}

/// Strip a trailing inline YAML comment from a scalar value. Per YAML, `#`
/// opens a comment only when preceded by whitespace — `true  # why` yields
/// `true`, while `true#x` stays intact (it is the value, not a comment).
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && bytes[i - 1].is_ascii_whitespace() {
            return value[..i].trim_end();
        }
    }
    value
}

/// Hard cap on `description`, from the Agent Skills spec. The house target
/// (250 chars) is advisory: 20 of 103 shipped skills exceed it, so blocking on
/// it would lock edits to skills nobody is touching the description of.
const DESCRIPTION_MAX_CHARS: usize = 1024;

/// A problem found in a document: a stable `kind` (used to decide whether an
/// edit INTRODUCED it) and the message shown to the user.
type Problem = (&'static str, String, usize);

/// Keep only the problems whose kind the on-disk document did not already
/// have. Every new blocking rule is introduced-only: a file that already
/// violates stays editable, so a rule can never lock a file for an unrelated
/// edit (ticking a plan checkbox, fixing a typo). No readable on-disk file
/// (a new Write) means every problem counts as introduced.
///
/// A problem with a magnitude (the third field, e.g. a length) is also counted
/// as introduced when it GREW past the on-disk magnitude: a legacy 1100-char
/// description may be edited, but not extended.
fn introduced(now: Vec<Problem>, before: Option<Vec<Problem>>) -> Vec<Problem> {
    let before = before.unwrap_or_default();
    now.into_iter()
        .filter(|(kind, _, mag)| {
            !before
                .iter()
                .any(|(k, _, m)| k == kind && (*kind != "description-length" || mag <= m))
        })
        .collect()
}

/// The text of a scalar value with quoting resolved BEFORE any comment strip:
/// inside quotes a `#` is content (`"Parses # headings"`, `'#12'`), and a
/// comment can only follow the closing quote. An unclosed quote yields the
/// rest of the line, without the quote.
fn scalar_text(raw: &str) -> String {
    let raw = raw.trim();
    let mut chars = raw.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => {
            let mut out = String::new();
            let mut it = raw[1..].chars().peekable();
            while let Some(c) = it.next() {
                if q == '"' && c == '\\' {
                    if let Some(n) = it.next() {
                        out.push(n);
                    }
                } else if c == q {
                    if q == '\'' && it.peek() == Some(&'\'') {
                        it.next();
                        out.push('\'');
                    } else {
                        return out;
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }
        _ => strip_inline_comment(raw).to_string(),
    }
}

/// Is `line` the top-level `key:` line — `key` then optional blanks then `:`
/// (YAML allows `description :`)?
fn is_key_line(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.trim_start_matches([' ', '\t']).starts_with(':'))
}

/// Text of a top-level frontmatter field, including a block scalar's or
/// continuation lines' indented text, so a `when_to_use: >-` value is read
/// before the trigger check runs.
fn field_full_text(content: &str, key: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.first() != Some(&"---") {
        return None;
    }
    let end = lines[1..].iter().position(|l| *l == "---")? + 1;
    let i = (1..end).find(|&i| is_key_line(lines[i], key))?;
    let raw = lines[i][lines[i].find(':')? + 1..].trim();
    let mut text = if raw.starts_with('|') || raw.starts_with('>') {
        String::new()
    } else {
        scalar_text(raw)
    };
    for l in lines[i + 1..end]
        .iter()
        .take_while(|l| l.starts_with(char::is_whitespace) || l.trim().is_empty())
    {
        text.push(' ');
        text.push_str(l.trim());
    }
    Some(text)
}

static TRIGGER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:use\b(?: this(?: skill)?| it| proactively)?\s+(?:when|whenever|after|before)|invoke when)\b",
    )
    .expect("pattern should compile")
});

/// Does `text` carry a trigger clause ("Use when", "Use this skill after",
/// "Invoke when" …) that is not negated by a preceding not / don't / never?
fn has_trigger_clause(text: &str) -> bool {
    let lower = text.to_lowercase().replace('\u{2019}', "'");
    TRIGGER_PATTERN.find_iter(&lower).any(|m| {
        // Negated when not / don't / never is one of the two words before the
        // match ("do not ever use when").
        // The lookback stops at a sentence boundary (. ; !).
        !lower[..m.start()]
            .rsplit(['.', ';', '!'])
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .rev()
            .take(2)
            .any(|w| matches!(w, "not" | "don't" | "dont" | "never"))
    })
}

/// The BLOCKING Description Format Rules (#613): a single YAML line — no block
/// scalar, no continuation line, no multi-line quoted string — within the spec
/// length cap. A block scalar or continuation fragments skill routing: the
/// listing shows the indicator or the first line only.
fn description_problems(content: &str, fields: &[(String, String)]) -> Vec<Problem> {
    let mut problems: Vec<Problem> = Vec::new();
    let Some((_, raw)) = fields.iter().find(|(k, _)| k == "description") else {
        return problems; // missing-field error is reported elsewhere
    };
    let raw = raw.trim();

    let lines: Vec<&str> = content.lines().collect();
    let end = lines
        .iter()
        .skip(1)
        .position(|l| *l == "---")
        .map_or(lines.len(), |p| p + 1);
    let idx = lines[1..end.min(lines.len())]
        .iter()
        .position(|l| is_key_line(l, "description"))
        .map(|p| p + 1);
    // YAML folds blank lines, so `description: x\n\n  more` continues too.
    let continued = idx.is_some_and(|i| {
        lines
            .get(i + 1..end)
            .unwrap_or_default()
            .iter()
            // Blank lines fold, and an indented `# …` is a YAML comment.
            .find(|l| {
                !l.trim().is_empty()
                    && !(l.starts_with(char::is_whitespace) && l.trim_start().starts_with('#'))
            })
            .is_some_and(|next| next.starts_with(char::is_whitespace))
    });

    if raw.starts_with('|') || raw.starts_with('>') {
        problems.push((
            "description-shape",
            "description must be a single YAML line — a block scalar ('>-', '|') fragments skill routing".into(),
            0,
        ));
        return problems;
    }
    if continued {
        problems.push((
            "description-shape",
            "description must be a single YAML line — an indented continuation line, including a multi-line quoted string, is not part of the routing text".into(),
            0,
        ));
        return problems;
    }

    let len = scalar_text(raw).chars().count();
    if len > DESCRIPTION_MAX_CHARS {
        problems.push((
            "description-length",
            format!("description is {len} characters — the spec cap is {DESCRIPTION_MAX_CHARS}"),
            len,
        ));
    }
    problems
}

/// The trigger-clause rule is a NUDGE, never a block: it also reaches
/// third-party and synced first-party skills ("Use this skill when …") that
/// cannot be gated. Accepts the clause in `description` or `when_to_use`.
fn trigger_nudge(content: &str, fields: &[(String, String)]) -> Option<Problem> {
    let (_, raw) = fields.iter().find(|(k, _)| k == "description")?;
    if raw.trim().is_empty() || raw.trim().starts_with(['|', '>']) {
        return None; // shape error reported instead
    }
    let mut text = scalar_text(raw);
    if let Some(w) = field_full_text(content, "when_to_use") {
        text.push(' ');
        text.push_str(&w);
    }
    (!has_trigger_clause(&text)).then(|| {
        (
            "description-trigger",
            "description has no trigger clause — say when to use the skill ('Use when …' / 'Use after …' / 'Use before …')".to_string(),
            0,
        )
    })
}

/// Where Claude Code ends the frontmatter: it splits with the lazy regex
/// `^---\s*\n([\s\S]*?)---\s*\n?`, so the FIRST `---` anywhere after the opener
/// closes it — mid-line, or followed by trailing whitespace — and the body
/// starts after the whitespace that follows. `None` when the document does not
/// open that way.
fn claude_code_body_start(content: &str) -> Option<usize> {
    let rest = content.strip_prefix("---")?;
    let ws = rest.len() - rest.trim_start().len();
    let nl = rest[..ws].rfind('\n')?;
    let inner_start = 3 + nl + 1;
    let close = inner_start + content[inner_start..].find("---")?;
    let after = &content[close + 3..];
    Some(close + 3 + (after.len() - after.trim_start().len()))
}

/// The markdown body of a skill or command. The frontmatter is YAML, not
/// markdown: parsing it as markdown lets a block-scalar line (`   <!--`, a
/// leading fence) swallow the real body. The body starts at the EARLIER of
/// two ends of the frontmatter — the first exact `---` line (as
/// [`extract_frontmatter`] finds it) and Claude Code's lazy-match end
/// ([`claude_code_body_start`]) — because scanning a little frontmatter only
/// fails toward blocking, while scanning too little lets a reference the
/// platform reads as body go unseen. Without either, the whole document.
fn body_after_frontmatter(content: &str) -> &str {
    let mut offset = 0;
    let mut exact = None;
    for (i, line) in content.split_inclusive('\n').enumerate() {
        let text = line.trim_end_matches(['\r', '\n']);
        if i == 0 && text != "---" {
            break;
        }
        offset += line.len();
        if i > 0 && text == "---" {
            exact = Some(offset);
            break;
        }
    }
    let start = [exact, claude_code_body_start(content)]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(0);
    &content[start..]
}

/// Every `@skills/…` token in prose (#614). `@skills/` force-loads the file
/// and bypasses conditional activation.
///
/// A CommonMark parser is used ONLY to locate code: code blocks (fenced or
/// indented, in lists or not) and inline code spans are blanked out of the raw
/// body, keeping offsets, and the tokens are then scanned in the RAW text. So
/// every construct that carries no text event — raw HTML, comments, link
/// reference definitions, link destinations and titles — is still scanned,
/// while `&#64;skills`, `\@skills` and `@skills/*x*` (not a path) are not
/// references. The token must start a word (`user@skills/x` does not match)
/// and loses trailing `.,;:)>` and backticks.
fn force_load_refs(content: &str) -> Vec<String> {
    use pulldown_cmark::{Event, Parser, Tag};
    let body = body_after_frontmatter(content);
    let mut masked = body.as_bytes().to_vec();
    let mut blank = |range: std::ops::Range<usize>| {
        for b in &mut masked[range] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    for (event, range) in Parser::new(body).into_offset_iter() {
        match event {
            Event::Start(Tag::CodeBlock(_)) | Event::Code(_) => blank(range),
            _ => {}
        }
    }
    let masked = String::from_utf8(masked).unwrap_or_default();
    let mut refs = Vec::new();
    scan_tokens(&masked, &mut refs);
    refs
}

fn scan_tokens(text: &str, refs: &mut Vec<String>) {
    for (pos, _) in text.match_indices("@skills/") {
        let prev = text[..pos].chars().next_back();
        if prev.is_some_and(|p| p.is_alphanumeric() || matches!(p, '_' | '.' | '-' | '\\')) {
            continue;
        }
        // A path must follow: `@skills/*x*` and a bare `@skills/` are not references.
        let next = text[pos + "@skills/".len()..].chars().next();
        if !next.is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-')) {
            continue;
        }
        let token: String = text[pos..]
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, ']' | ')' | '<' | '>' | '"' | '\''))
            .collect();
        refs.push(
            token
                .trim_end_matches(['.', ',', ';', ':', ')', '`', '>', '*'])
                .to_string(),
        );
    }
}

/// `@skills/` references the resulting document has that the on-disk one did
/// not. A file already carrying one stays editable; only an introduction blocks.
fn introduced_force_loads(path: &str, content: &str) -> Vec<String> {
    let now = force_load_refs(content);
    if now.is_empty() {
        return Vec::new();
    }
    let before = std::fs::read_to_string(path)
        .map(|old| force_load_refs(&old))
        .unwrap_or_default();
    let mut seen: Vec<String> = Vec::new();
    now.into_iter()
        .filter(|r| {
            let fresh = !before.contains(r) && !seen.contains(r);
            seen.push(r.clone());
            fresh
        })
        .map(|r| {
            format!(
                "'{r}' force-loads a skill and bypasses conditional activation — name the skill (`plugin:skill`) instead of an @skills/ path"
            )
        })
        .collect()
}

/// Does this agent description say the definition is dispatched as a team
/// teammate? The file shows no dispatch mode, so the description is the only
/// signal, and it is the same one `scripts/lint-agent-tools.py`'s
/// `teammate-ignored-field` keys on: the words "teammate" or "agent team(s)".
/// A definition that is a teammate without saying so is not caught.
fn describes_teammate(description: &str) -> bool {
    static TEAMMATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\bteammates?\b|\bagent[- ]teams?\b").expect("static regex")
    });
    TEAMMATE.is_match(description)
}

/// Agent definitions (#615), by distribution surface. A NUDGE, not a block:
/// the file is otherwise valid.
///
/// - Plugin agents (`plugin == true`): `hooks`, `mcpServers` and
///   `permissionMode` are accepted and silently ignored. The same agent copied
///   to `.claude/agents/` honours all three.
/// - Any agent whose description names teammate use: `skills` and
///   `mcpServers` are ignored when a definition spawns a teammate, which
///   loads both from settings only.
fn check_agent(content: &str, plugin: bool) -> CheckResult {
    let Some(fields) = extract_frontmatter(content) else {
        return CheckResult::allow();
    };
    let has = |f: &str| fields.iter().any(|(k, _)| k == f);
    let mut notes = Vec::new();
    if plugin {
        let ignored: Vec<&str> = ["hooks", "mcpServers", "permissionMode"]
            .into_iter()
            .filter(|f| has(f))
            .collect();
        if !ignored.is_empty() {
            notes.push(format!(
                "Plugin-distributed agents silently ignore {} — the field is accepted but has no effect. Drop it, or ship the agent to .claude/agents/ where it is honoured.",
                ignored.join(", ")
            ));
        }
    }
    if field_full_text(content, "description").is_some_and(|d| describes_teammate(&d)) {
        let ignored: Vec<&str> = ["skills", "mcpServers"]
            .into_iter()
            .filter(|f| has(f))
            .collect();
        if !ignored.is_empty() {
            notes.push(format!(
                "This agent's description names teammate use, and a definition that spawns a teammate has its {} ignored — teammates load skills and MCP servers from project/user settings only. Move it there, or drop the field.",
                ignored.join(", ")
            ));
        }
    }
    if notes.is_empty() {
        CheckResult::allow()
    } else {
        CheckResult::nudge(notes.join(" "))
    }
}

/// Does a FENCED code block whose first non-blank line is `provenance:` appear
/// before the first top-level heading? Parsed as CommonMark, so a fence's extent
/// and an indented code block follow the spec; a body below a heading may
/// document it. A heading inside a blockquote or list item is not a top-level
/// heading and does not end the search.
fn fenced_provenance_before_heading(body: &str) -> bool {
    use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag, TagEnd};
    let mut in_fence = false;
    let mut depth = 0usize;
    let mut text = String::new();
    for event in Parser::new(body) {
        match event {
            Event::Start(Tag::BlockQuote(_) | Tag::List(_) | Tag::Item) => depth += 1,
            Event::End(TagEnd::BlockQuote(_) | TagEnd::List(_) | TagEnd::Item) => {
                depth = depth.saturating_sub(1);
            }
            Event::Start(Tag::Heading { .. }) if depth == 0 => return false,
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_))) => {
                in_fence = true;
                text.clear();
            }
            Event::Text(t) if in_fence => text.push_str(&t),
            Event::End(TagEnd::CodeBlock) if in_fence => {
                in_fence = false;
                let first = text.lines().find(|l| !l.trim().is_empty());
                if first.map(str::trim_end) == Some("provenance:") {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Is the first non-blank line a `---` that opens a real second frontmatter
/// block? It must be followed by a closing `---`, and its first inner line must
/// be a `key:` line, or `#` comment lines and then a `key:` line. A bare
/// thematic break right after the frontmatter is not one.
fn second_frontmatter_block(rest: &[&str]) -> bool {
    let Some(open) = rest.iter().position(|l| !l.trim().is_empty()) else {
        return false;
    };
    if rest[open] != "---" {
        return false;
    }
    // The closing `---` must come before the first ATX heading: past it the
    // opener was a thematic break in the body, not a frontmatter block.
    let is_heading = |l: &str| {
        let t = l.trim_start_matches(' ');
        l.len() - t.len() <= 3 && t.starts_with('#') && {
            let h = t.trim_start_matches('#');
            t.len() - h.len() <= 6 && (h.is_empty() || h.starts_with([' ', '\t']))
        }
    };
    // Leading `#` lines right after the opener are YAML comments, not headings.
    let comments = rest[open + 1..]
        .iter()
        .take_while(|l| l.trim_start().starts_with('#'))
        .count();
    let search = comments
        + rest[open + 1 + comments..]
            .iter()
            .position(|l| is_heading(l))
            .unwrap_or(rest.len() - open - 1 - comments);
    let Some(len) = rest[open + 1..open + 1 + search]
        .iter()
        .position(|l| *l == "---")
    else {
        return false;
    };
    let inner = &rest[open + 1..open + 1 + len];
    let is_key = |l: &str| {
        l.split_once(':').is_some_and(|(k, _)| {
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
        })
    };
    inner
        .iter()
        .find(|l| !l.trim_start().starts_with('#'))
        .is_some_and(|l| is_key(l))
}

/// Living-plan frontmatter shape (#607): producer tuple as FLAT keys in one
/// frontmatter block above the title, never a nested `provenance:` block. A
/// plan with no frontmatter at all predates the contract and is not checked.
/// The fenced-block rule looks only at fences BEFORE the first heading, so a
/// plan body can document the rule.
fn plan_problems(content: &str) -> Vec<Problem> {
    let lines: Vec<&str> = content.lines().collect();
    let mut errors: Vec<Problem> = Vec::new();
    if lines.first() != Some(&"---") {
        return errors;
    }
    let Some(end) = lines[1..].iter().position(|l| *l == "---").map(|p| p + 1) else {
        return errors;
    };
    if lines[1..end].iter().any(|l| l.starts_with("provenance:")) {
        errors.push((
            "plan-provenance-key",
            "a 'provenance:' key in frontmatter — a plan carries the producer tuple as flat keys (date, session_id, model, harness, machine)".into(),
            0,
        ));
    }
    if second_frontmatter_block(&lines[end + 1..]) {
        errors.push((
            "plan-second-frontmatter",
            "a second frontmatter block — a plan has exactly one, above the title".into(),
            0,
        ));
    }
    if fenced_provenance_before_heading(&lines[end + 1..].join("\n")) {
        errors.push((
            "plan-fenced-provenance",
            "a fenced nested 'provenance:' block above the first heading — plans use flat frontmatter keys instead".into(),
            0,
        ));
    }
    errors
}

fn check_plan(path: &str, content: &str) -> CheckResult {
    let before = std::fs::read_to_string(path)
        .ok()
        .map(|old| plan_problems(&old));
    let errors = introduced(plan_problems(content), before);
    if errors.is_empty() {
        CheckResult::allow()
    } else {
        CheckResult::block(format!(
            "Living-plan frontmatter validation failed: {}",
            errors
                .into_iter()
                .map(|(_, m, _)| m)
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }
}

/// Validates YAML frontmatter in skill and command markdown files.
pub struct ValidateSkillFrontmatter;

impl Check for ValidateSkillFrontmatter {
    fn name(&self) -> &str {
        "validate-skill-frontmatter"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        let file_type = classify_path(&path);
        if file_type == FileType::Other {
            return CheckResult::allow();
        }

        // Validate the document the tool call will *produce*, not the raw tool
        // payload. For Edit/MultiEdit this simulates the edit against the
        // on-disk file — an Edit's new_string is a fragment, not the document.
        // Unreadable/missing file → None → allow (fail open, ADR-0001).
        let Some(content) = input.effective_content() else {
            return CheckResult::allow();
        };

        // The write target as sent — the file `effective_content` simulated
        // against — so every "before" read sees the same file.
        let literal = input.literal_file_path().unwrap_or(path.as_str());

        match file_type {
            FileType::Plan => return check_plan(literal, &content),
            FileType::Agent => return check_agent(&content, true),
            FileType::ProjectAgent => return check_agent(&content, false),
            _ => {}
        }

        let Some(fields) = extract_frontmatter(&content) else {
            return CheckResult::block("Frontmatter validation failed: file missing YAML frontmatter (must start with ---)".to_string());
        };

        let mut errors = Vec::new();
        let mut nudge: Option<String> = None;

        // Check for unknown fields
        for (key, _) in &fields {
            if !VALID_FIELDS.contains(&key.as_str()) {
                errors.push(format!("Unknown frontmatter field: '{key}'"));
            }
        }

        // Boolean fields: exactly `true` or `false` — house strictness, one
        // rule for all three (the platform accepts yes/no/on/off/1/0). A
        // trailing inline comment is not part of the value; quoted values
        // (`"true"`) stay blocked — unquoted is the house spelling.
        for (key, value) in &fields {
            let bare = strip_inline_comment(value);
            if BOOLEAN_FIELDS.contains(&key.as_str()) && bare != "true" && bare != "false" {
                errors.push(format!(
                    "'{key}' must be exactly 'true' or 'false' (got: '{bare}') — the platform accepts yes/no/on/off/1/0, cadence house style does not"
                ));
            }
        }

        // Enum fields: value must exactly match one of the allowed options.
        for (key, value) in &fields {
            let bare = strip_inline_comment(value);
            if let Some((_, allowed)) = ENUM_FIELDS.iter().find(|(k, _)| *k == key.as_str())
                && !allowed.contains(&bare)
            {
                errors.push(format!(
                    "'{key}' must be one of {allowed:?} (got: '{bare}')"
                ));
            }
        }

        match file_type {
            FileType::Skill => {
                let has_name = fields.iter().any(|(k, _)| k == "name");
                let has_desc = fields.iter().any(|(k, _)| k == "description");

                if !has_name {
                    errors.push("Missing required 'name' field".into());
                }
                if !has_desc {
                    errors.push("Missing required 'description' field".into());
                }

                if let Some((_, name_value)) = fields.iter().find(|(k, _)| k == "name") {
                    // Check name format. A colon fails here, which is the whole
                    // point: Claude Code prepends `<plugin>:` itself, so a
                    // declared prefix doubles in the slash menu.
                    if !NAME_PATTERN.is_match(name_value) {
                        errors.push(format!(
                            "name must be the bare skill directory — only lowercase letters, numbers, and hyphens, no 'plugin:' prefix (got: '{name_value}')"
                        ));
                    }

                    // Check the name matches the directory. With colons rejected
                    // above, the declared name IS the skill part, so this is a
                    // direct comparison.
                    if let Some(dir_name) = skill_dir_name(&path)
                        && name_value.as_str() != dir_name
                    {
                        errors.push(format!(
                            "name '{name_value}' must match directory '{dir_name}'"
                        ));
                    }
                }

                let before = std::fs::read_to_string(literal).ok();
                let before_fields = before.as_deref().and_then(extract_frontmatter);
                errors.extend(
                    introduced(
                        description_problems(&content, &fields),
                        before_fields
                            .as_deref()
                            .map(|f| description_problems(before.as_deref().unwrap_or(""), f)),
                    )
                    .into_iter()
                    .map(|(_, m, _)| m),
                );
                let old_nudge = before_fields
                    .as_deref()
                    .and_then(|f| trigger_nudge(before.as_deref().unwrap_or(""), f));
                if old_nudge.is_none() {
                    nudge = trigger_nudge(&content, &fields).map(|(_, m, _)| m);
                }
            }
            FileType::Command => {
                if fields.iter().any(|(k, _)| k == "name") {
                    errors.push(
                        "Remove 'name:' from command files — commands derive name from filename"
                            .into(),
                    );
                }
            }
            FileType::Agent | FileType::ProjectAgent | FileType::Plan | FileType::Other => {}
        }

        // `@skills/` force-load syntax (#614): skill and command bodies only,
        // and only a reference this edit introduces.
        errors.extend(introduced_force_loads(literal, &content));

        if errors.is_empty() {
            match nudge {
                Some(message) => CheckResult::nudge(message),
                None => CheckResult::allow(),
            }
        } else {
            CheckResult::block(format!(
                "Frontmatter validation failed: {}",
                errors.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render an on-disk fixture path the way the check actually receives one.
    ///
    /// `classify_path` is fed by `HookInput::file_path()`, which runs
    /// `normalize_path` first — and that maps `\` to `/`. A test that hands a
    /// raw `PathBuf` straight to `classify_path` skips that step, so on Windows
    /// it passes `C:\Users\…\Temp\…` into a function that splits on `/`, gets
    /// one segment, and finds no `commands`. The assertion then fails for a
    /// reason that has nothing to do with the behaviour under test.
    ///
    /// Deliberately NOT solved by making the production splitter accept `\` as
    /// well: a backslash is a legal filename character on Unix, so a file named
    /// `a\commands\b.md` would gain a phantom `commands` segment and could be
    /// falsely blocked. The fixture is what is wrong here, not the splitter.
    fn as_hook_path(p: &std::path::Path) -> String {
        p.to_str().expect("utf-8 fixture path").replace('\\', "/")
    }

    #[test]
    fn valid_skill_passes() {
        let content = "---\nname: my-skill\ndescription: Use when testing\n---\n# Content";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "name");
    }

    #[test]
    fn missing_frontmatter_detected() {
        let content = "# No frontmatter here";
        assert!(extract_frontmatter(content).is_none());
    }

    #[test]
    fn valid_name_format() {
        assert!(NAME_PATTERN.is_match("my-skill"));
        assert!(NAME_PATTERN.is_match("skill123"));
        assert!(NAME_PATTERN.is_match("add-narrative-logging"));
        assert!(!NAME_PATTERN.is_match("My-Skill"));
        assert!(!NAME_PATTERN.is_match("-leading"));
        assert!(!NAME_PATTERN.is_match("trailing-"));
        assert!(!NAME_PATTERN.is_match("double--hyphen"));
        // A `plugin:` prefix is rejected outright — Claude Code prepends it
        // itself (2.1.216), so declaring it renders `/cadence:cadence:attune`.
        assert!(!NAME_PATTERN.is_match("cadence:attune"));
        assert!(!NAME_PATTERN.is_match("cadence-forge:add-narrative-logging"));
        assert!(!NAME_PATTERN.is_match("cadence-rules:init-all"));
        // Colon edge cases stay rejected for the same reason.
        assert!(!NAME_PATTERN.is_match("cadence:")); // dangling colon
        assert!(!NAME_PATTERN.is_match(":attune")); // leading colon
        assert!(!NAME_PATTERN.is_match("a::b")); // double colon
        assert!(!NAME_PATTERN.is_match("Cadence:attune")); // uppercase namespace
        assert!(!NAME_PATTERN.is_match("cadence:At")); // uppercase suffix
    }

    /// Both arms of the shared predicate stay live — a `.claude/` tree owns its
    /// `skills/` and its `commands/` alike, and neither noun may quietly stop
    /// being recognised while the other keeps working. Fixing one arm and
    /// leaving its twin is the exact failure cadence-hooks#806 exists to close,
    /// so the two assertions belong in one test rather than in two that can be
    /// updated independently.
    #[test]
    fn both_arms_recognise_a_claude_tree() {
        assert_eq!(
            classify_path("/repo/.claude/skills/my-skill/SKILL.md"),
            FileType::Skill
        );
        assert_eq!(
            classify_path("/repo/.claude/commands/my-cmd.md"),
            FileType::Command
        );
    }

    #[test]
    fn classify_dot_claude_command_path() {
        assert_eq!(
            classify_path("/Users/x/.claude/commands/my-cmd.md"),
            FileType::Command
        );
        assert_eq!(
            classify_path("/repo/.claude/commands/nested/my-cmd.md"),
            FileType::Command
        );
    }

    /// The cameronsjo/cadence-hooks#802 regression, pinned.
    ///
    /// `docs/commands/` is ordinary project documentation — a natural home for
    /// a CLI's per-command-group pages, and forgectl keeps nine of them with no
    /// frontmatter by convention. The old bare `contains("/commands/")`
    /// predicate classified every one as a command DEFINITION, so the check
    /// hard-blocked each edit for "missing YAML frontmatter".
    ///
    /// This is the control for the fix: it fails on the old predicate and is
    /// the reason the new one splits on path segments instead of substrings.
    #[test]
    fn docs_commands_dir_is_not_a_command_definition() {
        for path in [
            "/repo/docs/commands/projects-and-review.md",
            "/repo/docs/commands/pr.md",
            "/repo/documentation/commands/index.md",
            "/srv/commands/readme.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Other,
                "{path} is documentation, not a command definition"
            );
        }
    }

    /// A plugin root is identified by its sibling `.claude-plugin/` marker —
    /// the installed-cache and standalone-plugin-repo layouts, neither of which
    /// carries a `plugins/` path segment for the string fast paths to catch.
    ///
    /// The negative half is what keeps the marker load-bearing: the identical
    /// tree WITHOUT `.claude-plugin/` must classify as `Other`, or this test
    /// would pass for a reason that has nothing to do with the marker.
    #[test]
    fn plugin_root_marker_classifies_commands() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("some-plugin");
        let commands = root.join("commands");
        std::fs::create_dir_all(&commands).expect("fixture dirs");
        let cmd_path = commands.join("my-cmd.md");
        let cmd_str = as_hook_path(&cmd_path);
        let cmd_str = cmd_str.as_str();

        // No marker yet — indistinguishable from any other `commands` dir.
        assert_eq!(
            classify_path(cmd_str),
            FileType::Other,
            "without .claude-plugin/ this is not a plugin root"
        );

        std::fs::create_dir_all(root.join(".claude-plugin")).expect("marker dir");
        assert_eq!(
            classify_path(cmd_str),
            FileType::Command,
            "the .claude-plugin/ marker is what makes it a plugin root"
        );
    }

    /// The installed-cache shape, which is the reason the marker rule exists —
    /// and which carries a DECOY `plugins` segment at a non-matching offset
    /// (`.../plugins/cache/<marketplace>/<plugin>/<sha>/commands/`).
    ///
    /// An earlier draft accepted any `plugins/<name>/commands/` triple as a fast
    /// path. That rule could not reach this shape (the offsets do not line up)
    /// while it DID reach `docs/plugins/<name>/commands/`, which is exactly
    /// backwards. This test pins the real shape so a future "simplify the
    /// predicate" edit cannot quietly reintroduce the substring form.
    #[test]
    fn installed_cache_shape_with_decoy_plugins_segment() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp
            .path()
            .join("plugins")
            .join("cache")
            .join("workbench")
            .join("cadence-forge")
            .join("960c588950a6-7712fab0");
        std::fs::create_dir_all(root.join("commands")).expect("fixture dirs");
        std::fs::create_dir_all(root.join(".claude-plugin")).expect("marker dir");

        let cmd = root.join("commands").join("polish.md");
        assert_eq!(
            classify_path(&as_hook_path(&cmd)),
            FileType::Command,
            "the installed cache layout is a real command definition location"
        );
    }

    /// The cameronsjo/cadence-hooks#806 regression, pinned — the mirror of the
    /// `docs/commands/` case below.
    ///
    /// `docs/skills/<x>/SKILL.md` is documentation about skills. The old
    /// `contains("/skills/")` predicate classified every one as a skill
    /// DEFINITION and hard-blocked each edit for missing frontmatter, by the
    /// same mechanism and for the same reason as #802.
    #[test]
    fn docs_skills_dir_is_not_a_skill_definition() {
        for path in [
            "/repo/docs/skills/attune/SKILL.md",
            "/repo/documentation/skills/my-skill/SKILL.md",
            "/repo/docs/plugins/p/skills/x/SKILL.md",
            "/srv/skills/whatever/SKILL.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Other,
                "{path} is documentation, not a skill definition"
            );
        }
    }

    /// A plugin root's `skills/` is a definition location, identified by the
    /// same `.claude-plugin/` marker the command arm uses — and the negative
    /// half keeps the marker load-bearing rather than incidental.
    #[test]
    fn plugin_root_marker_classifies_skills() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("some-plugin");
        let skill = root.join("skills").join("my-skill");
        std::fs::create_dir_all(&skill).expect("fixture dirs");
        let skill_md = as_hook_path(&skill.join("SKILL.md"));

        assert_eq!(
            classify_path(&skill_md),
            FileType::Other,
            "without .claude-plugin/ this is not a plugin root"
        );

        std::fs::create_dir_all(root.join(".claude-plugin")).expect("marker dir");
        assert_eq!(
            classify_path(&skill_md),
            FileType::Skill,
            "the .claude-plugin/ marker is what makes it a plugin root"
        );
    }

    /// The symlink-farm layout: a repo that is itself a Claude workspace keeps
    /// its definitions at `<repo>/skills/<name>/` and links them in from
    /// `<repo>/.claude/skills/<name>`. The path an agent actually edits is the
    /// link TARGET, which has no `.claude` ancestor — so a `.claude`-only rule
    /// stops validating all 20 of cmux's skills while the symlinked spelling
    /// keeps working, which is exactly the kind of split nobody notices.
    ///
    /// The negative half is what keeps the rule narrow: the identical tree
    /// WITHOUT the sibling `.claude/` is not a workspace, and `docs/skills/`
    /// asks about `docs`, which never is.
    #[test]
    fn workspace_repo_owns_its_top_level_definitions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().join("cmux-like");
        std::fs::create_dir_all(repo.join("skills").join("my-skill")).expect("fixture dirs");
        std::fs::create_dir_all(repo.join("docs").join("skills").join("about"))
            .expect("fixture dirs");
        let target = as_hook_path(&repo.join("skills/my-skill/SKILL.md"));
        let docs = as_hook_path(&repo.join("docs/skills/about/SKILL.md"));

        assert_eq!(
            classify_path(&target),
            FileType::Other,
            "without a sibling .claude/ this repo is not a workspace"
        );

        std::fs::create_dir_all(repo.join(".claude")).expect("workspace marker");
        assert_eq!(
            classify_path(&target),
            FileType::Skill,
            "the sibling .claude/ is what makes the repo a definition root"
        );
        assert_eq!(
            classify_path(&docs),
            FileType::Other,
            "docs/skills asks about docs/, which is still not a workspace"
        );
    }

    /// A relocated config dir (`CLAUDE_CONFIG_DIR`, as `claude-as` uses for a
    /// second subscription profile) is still a config dir. Matching only the
    /// literal `.claude` silently stops validating every definition in that
    /// profile — 26 live skills under `~/.claude-alt` at the time of writing.
    ///
    /// The rule itself, proved against a name this machine does not use.
    ///
    /// The wiring test below cannot carry this: `CONFIG_DIR_NAME` caches for
    /// the process, and where `CLAUDE_CONFIG_DIR` is unset it resolves to
    /// `.claude` — so the literal arm already answers every case and deleting
    /// the relocated arm changes nothing. Verified: mutating the rule away left
    /// that test green. This one is parameterised, so it goes red.
    #[test]
    fn a_relocated_config_dir_is_still_a_config_dir() {
        assert!(is_config_dir_segment(".claude-alt", ".claude-alt"));
        assert!(
            is_config_dir_segment(".CLAUDE-ALT", ".claude-alt"),
            "case-folded like every other segment compare"
        );
        assert!(
            is_config_dir_segment(".claude", ".claude-alt"),
            "the default stays a config dir even when another is active"
        );
        assert!(
            !is_config_dir_segment(".claude-alt", ".claude"),
            "a lookalike is not a config dir just because it shares a prefix"
        );
        assert!(!is_config_dir_segment("docs", ".claude-alt"));
    }

    /// Asserted through the same accessor production reads, rather than by
    /// setting the env var: `CONFIG_DIR_NAME` is a process-lifetime cache, so a
    /// test that mutated the env would race every other test in the binary and
    /// prove nothing repeatable. This pins the WIRING; the test above pins the
    /// RULE.
    #[test]
    fn config_dir_name_tracks_the_resolved_config_dir() {
        let resolved = cadence_hooks_core::paths::claude_config_dir();
        let expected = resolved
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| ".claude".to_string());
        assert_eq!(
            *CONFIG_DIR_NAME, expected,
            "the classifier must use the config dir the rest of the binary resolves"
        );

        let path = format!("/Users/x/{}/skills/my-skill/SKILL.md", *CONFIG_DIR_NAME);
        assert_eq!(
            classify_path(&path),
            FileType::Skill,
            "{path} is a real skill definition under the active config dir"
        );
    }

    /// The skill arm inherits normalisation, case-folding, the Windows drive
    /// branch, and the relative/oversize refusals from the shared predicate —
    /// but inheritance is a claim until something pins it. Every other control
    /// in this file exercises `commands` only, so drift would land here unseen.
    #[test]
    fn skill_arm_inherits_the_shared_path_handling() {
        for path in [
            "/repo/.claude//skills/my-skill/SKILL.md",
            "/repo/.claude/./skills/my-skill/SKILL.md",
            "/repo/.claude/x/../skills/my-skill/SKILL.md",
            "/repo/.Claude/SKILLS/my-skill/SKILL.md",
            "/repo/.claude/skills/my-skill/Skill.md",
            "C:/repo/.claude/skills/my-skill/SKILL.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Skill,
                "{path} resolves into a real skills tree"
            );
        }
        assert_eq!(
            classify_path("repo/.claude/skills/my-skill/SKILL.md"),
            FileType::Other,
            "a relative path has no stable meaning on either arm"
        );
        let huge = format!("/{}/skills/x/SKILL.md", "a".repeat(MAX_PATH_BYTES));
        assert_eq!(classify_path(&huge), FileType::Other, "past the size bound");
    }

    /// Documentation ABOUT plugins is still documentation.
    ///
    /// This is the second half of cadence-hooks#802 and the reason the
    /// `plugins/<name>/commands/` fast path was dropped rather than kept: that
    /// rule reintroduced the identical false block one directory deeper, on a
    /// path shape (`docs/plugins/…`) that is if anything more likely than the
    /// original.
    #[test]
    fn docs_about_plugins_is_not_a_command_definition() {
        for path in [
            "/repo/docs/plugins/my-plugin/commands/overview.md",
            "/repo/node_modules/foo/plugins/bar/commands/doc.md",
            "/repo/plugins/some-plugin/commands/x.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Other,
                "{path} has no .claude-plugin/ marker, so it is not a plugin root"
            );
        }
    }

    /// `normalize_path` upstream does not collapse `//`, resolve `.`/`..`, or
    /// case-fold, so these reach the classifier verbatim — and every one of them
    /// writes to a real `.claude/commands/` file on disk. Comparing raw segments
    /// saw `""`, `"."`, or `".."` as the parent and let a genuine command
    /// definition skip validation entirely.
    #[test]
    fn unnormalized_shapes_still_reach_the_command_arm() {
        for path in [
            "/repo/.claude//commands/x.md",
            "/repo/.claude/./commands/x.md",
            "/repo/.claude/sub/../commands/x.md",
            "/repo/.Claude/commands/x.md",
            "/repo/.claude/COMMANDS/x.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Command,
                "{path} resolves into a real .claude/commands tree"
            );
        }
    }

    /// A relative path would make the marker probe resolve against whatever
    /// directory the hook process is standing in, so the same path could
    /// classify two ways in one session. Refuse rather than answer
    /// inconsistently — and refuse an absurd path rather than walk it.
    #[test]
    fn relative_and_oversized_paths_are_not_classified() {
        assert_eq!(
            classify_path("repo/.claude/commands/x.md"),
            FileType::Other,
            "a relative path has no stable meaning here"
        );
        let huge = format!("/{}/commands/x.md", "a".repeat(MAX_PATH_BYTES));
        assert_eq!(
            classify_path(&huge),
            FileType::Other,
            "past the size bound we decline to scan"
        );
    }

    #[test]
    fn skill_dir_extraction() {
        assert_eq!(
            skill_dir_name("/repo/.claude/skills/my-skill/SKILL.md"),
            Some("my-skill")
        );
    }

    /// The classifier and the name rule must agree about the same path.
    ///
    /// `classify_path` normalises; `skill_dir_name` used to read the raw string.
    /// So `/repo/.claude/skills/my-skill/./SKILL.md` classified as a skill and
    /// then reported its directory as ".", rejecting a valid `name: my-skill`
    /// with "must match directory '.'" — a FALSE BLOCK, the exact defect class
    /// this whole change exists to remove. `//` gave an empty string.
    #[test]
    fn skill_dir_name_uses_the_normalised_view() {
        for path in [
            "/repo/.claude/skills/my-skill/./SKILL.md",
            "/repo/.claude/skills/my-skill//SKILL.md",
            "/repo/.claude/skills/sub/../my-skill/SKILL.md",
            "C:/repo/.claude/skills/my-skill/SKILL.md",
        ] {
            assert_eq!(
                skill_dir_name(path),
                Some("my-skill"),
                "{path} names the my-skill directory"
            );
            assert_eq!(
                classify_path(path),
                FileType::Skill,
                "{path} must also classify as a skill, or the pair disagrees"
            );
        }
        assert_eq!(skill_dir_name("/SKILL.md"), None, "no directory to name");
    }

    #[test]
    fn skill_dir_name_none_for_non_skill() {
        assert_eq!(skill_dir_name("/repo/docs/commands/my-cmd.md"), None);
    }

    /// `normalize_path` maps `\` to `/` but leaves the drive letter, so a
    /// Windows path arrives as `C:/Users/...` and does not start with `/`.
    /// An absolute-path test written as `starts_with('/')` therefore declines
    /// every real Windows path and disables the command arm entirely — with the
    /// whole suite green, because every other fixture here is a Unix-style
    /// string that is equally valid as a test input on either platform.
    ///
    /// The negative half is what stops this passing for the wrong reason: the
    /// drive-letter branch must still discriminate, not classify everything.
    #[test]
    fn windows_drive_paths_still_classify() {
        assert_eq!(
            classify_path("C:/Users/x/.claude/commands/my-cmd.md"),
            FileType::Command,
            "a Windows path must not silently disable the command arm"
        );
        assert_eq!(
            classify_path("C:/repo/docs/commands/pr.md"),
            FileType::Other,
            "the drive-letter branch must still tell docs from definitions"
        );
        assert_eq!(
            classify_path("C:/repo/.claude/./commands/x.md"),
            FileType::Command,
            "normalisation applies on the drive-letter branch too"
        );
    }

    #[test]
    fn classify_other_path() {
        assert_eq!(classify_path("/project/src/main.rs"), FileType::Other);
    }

    #[test]
    fn empty_frontmatter() {
        let content = "---\n---\n# Content";
        let fields = extract_frontmatter(content).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn frontmatter_with_extra_colons() {
        let content = "---\nname: my-skill\ndescription: A skill: for testing\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].1, "A skill: for testing");
    }

    // Full Check::run() integration tests
    use cadence_hooks_core::test_builders::make_write as make_write_input;

    #[test]
    fn run_other_file_allowed() {
        let input = make_write_input("/project/src/main.rs", "fn main() {}");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_missing_frontmatter_blocks() {
        let input = make_write_input("/repo/.claude/skills/my-skill/SKILL.md", "# No frontmatter");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn run_skill_missing_name_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\ndescription: A test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'name'"));
    }

    #[test]
    fn run_skill_missing_description_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Missing required 'description'")
        );
    }

    #[test]
    fn run_skill_invalid_name_format_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: My-Skill\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("lowercase"));
    }

    #[test]
    fn run_skill_name_dir_mismatch_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: other-name\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
    }

    #[test]
    fn run_skill_namespaced_name_blocks_even_when_suffix_matches() {
        // The plugin:directory form is rejected even though the post-colon
        // suffix equals the directory — this is the form 0.19.0 through
        // 0.63.0 accepted, and the one that renders `/cadence:cadence:my-skill`.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: cadence:my-skill\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("bare skill directory"));
    }

    #[test]
    fn run_skill_namespaced_name_suffix_mismatch_blocks() {
        // Still blocks, now for two reasons rather than one: the colon fails
        // the format check AND `cadence:wrong` is not the directory `my-skill`.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: cadence:wrong\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
    }

    #[test]
    fn run_skill_bare_name_matching_dir_passes() {
        // The correct form as of Claude Code 2.1.216.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_valid_skill_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_command_with_name_field_blocks() {
        let input = make_write_input(
            "/repo/.claude/commands/my-cmd.md",
            "---\nname: my-cmd\ndescription: Use when testing\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Remove 'name:'"));
    }

    #[test]
    fn run_command_without_name_passes() {
        let input = make_write_input(
            "/repo/.claude/commands/my-cmd.md",
            "---\ndescription: A command\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_unknown_field_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nunknown-field: value\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Unknown frontmatter field")
        );
    }

    #[test]
    fn run_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_no_content_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/repo/.claude/skills/my-skill/SKILL.md".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn name_with_numbers_valid() {
        assert!(NAME_PATTERN.is_match("skill-v2"));
        assert!(NAME_PATTERN.is_match("s3-uploader"));
        assert!(NAME_PATTERN.is_match("123"));
    }

    #[test]
    fn name_with_underscores_invalid() {
        assert!(!NAME_PATTERN.is_match("my_skill"));
    }

    #[test]
    fn name_with_spaces_invalid() {
        assert!(!NAME_PATTERN.is_match("my skill"));
    }

    #[test]
    fn name_single_char_valid() {
        assert!(NAME_PATTERN.is_match("a"));
    }

    #[test]
    fn frontmatter_missing_end_delimiter() {
        let content = "---\nname: my-skill\ndescription: Use when testing\n# No end delimiter";
        assert!(extract_frontmatter(content).is_none());
    }

    #[test]
    fn frontmatter_nested_keys_excluded() {
        // Indented (nested) keys belong to a parent mapping — they are not
        // top-level fields and must not be validated against VALID_FIELDS.
        let content = "---\nname: my-skill\n  nested: value\ndescription: Use when testing\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().all(|(k, _)| k != "nested"));
    }

    #[test]
    fn run_multiple_errors_all_reported() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nunknown1: val\nunknown2: val\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("unknown1"));
        assert!(msg.contains("unknown2"));
        assert!(msg.contains("Missing required 'name'"));
        assert!(msg.contains("Missing required 'description'"));
    }

    // --- Edit/MultiEdit simulation against on-disk files (#60, #63) ---

    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit};

    const VALID_SKILL: &str =
        "---\nname: my-skill\ndescription: Use when testing\n---\n# My Skill\n\nBody text here.\n";

    /// Write a valid SKILL.md into a temp dir shaped like a REAL plugin skill
    /// tree — a plugin root carrying a `.claude-plugin/` marker, with the skill
    /// beneath it. Returns (tempdir guard, absolute SKILL.md path).
    ///
    /// The marker is load-bearing, not decoration. This helper previously built
    /// a bare `<tmp>/skills/my-skill/SKILL.md`, which under the pre-#806
    /// substring predicate classified as a skill purely because the string
    /// `/skills/` appeared. Once the predicate started requiring a definition
    /// root, that shape became `Other` — so every caller expecting a BLOCK
    /// failed, and, more quietly, every caller expecting an ALLOW kept passing
    /// while exercising nothing at all. Only one test went red; several went
    /// vacuous. Building the marker is what keeps this helper's whole cohort
    /// meaningful, and it is also the on-disk plugin-skill coverage the fixture
    /// migration would otherwise have dropped when the string fixtures moved to
    /// project-skill paths.
    fn on_disk_skill(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let plugin_root = dir.path().join("some-plugin");
        std::fs::create_dir_all(plugin_root.join(".claude-plugin")).unwrap();
        let skill_dir = plugin_root.join("skills/my-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        let path = skill_dir.join("SKILL.md");
        std::fs::write(&path, content).unwrap();
        let hook_path = as_hook_path(&path);
        // Self-guarding, so every present and future caller carries its own
        // proof rather than depending on one block-expecting neighbour to
        // notice. A fixture that stops classifying as a skill makes ALLOW-
        // expecting callers pass while exercising nothing — the failure mode
        // this helper already had once.
        assert_eq!(
            classify_path(&hook_path),
            FileType::Skill,
            "fixture must classify as a skill or every caller is vacuous"
        );
        (dir, hook_path)
    }

    #[test]
    fn run_body_only_edit_on_valid_skill_allowed() {
        // Regression for #60: a mid-file Edit to a valid SKILL.md must not be
        // blocked just because the edit fragment lacks frontmatter.
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_edit(&path, "Body text here.", "Updated body text.");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_edit_corrupting_frontmatter_blocks() {
        // The false-negative direction: an Edit that breaks the frontmatter of
        // a valid file must still be caught.
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_edit(&path, "name: my-skill", "not a valid key line");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'name'"));
    }

    #[test]
    fn run_multi_edit_body_edit_on_valid_skill_allowed() {
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_multi_edit(
            &path,
            &[("# My Skill", "# My Skill v2"), ("Body text", "New body")],
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_edit_on_missing_file_allowed() {
        // Fail open (ADR-0001): if the file can't be read, the edit can't be
        // simulated — allow rather than block on incomplete information.
        let input = make_edit(
            "/nonexistent/.claude/skills/my-skill/SKILL.md",
            "old",
            "new",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_write_with_nested_metadata_allowed() {
        // Regression for #63 (bug 2): nested keys under `metadata:` are not
        // unknown top-level fields.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nmetadata:\n  author: cameron\n  version: 1.0.0\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn valid_skill_with_optional_fields() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nmodel: opus\nallowed-tools: Read,Grep\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn valid_skill_with_paths_field() {
        // #227: `paths` is a valid Claude Code conditional-activation field
        // (scopes a skill to activate only when matching files are touched).
        // It must not be rejected as an unknown frontmatter field.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\npaths: src/**/*.rs\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Background fork skills (Claude Code 2.1.218) + strict booleans ---

    #[test]
    fn run_skill_with_background_true_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ncontext: fork\nbackground: true\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_background_false_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ncontext: fork\nbackground: false\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_background_yes_blocks() {
        // The platform loosened boolean parsing (yes/no/on/off/1/0) in
        // 2.1.218; cadence house style stays strict true/false.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ncontext: fork\nbackground: yes\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_user_invocable_yes_blocks() {
        // One rule for all boolean fields — pre-existing booleans get the
        // same strictness as the new `background` field.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nuser-invocable: yes\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("'user-invocable' must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_disable_model_invocation_numeric_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ndisable-model-invocation: 1\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("'disable-model-invocation' must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_boolean_true_false_still_pass() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nuser-invocable: false\ndisable-model-invocation: true\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_boolean_with_inline_comment_passes() {
        // A trailing YAML comment is not part of the value — `true  # why`
        // is the boolean true, not a malformed spelling.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ncontext: fork\nbackground: true  # opt out later\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_quoted_boolean_blocks() {
        // Deliberate: `"true"` is a string spelling, not the house boolean.
        // Unquoted true/false is the one greppable form.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ncontext: fork\nbackground: \"true\"\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn strip_inline_comment_edges() {
        assert_eq!(strip_inline_comment("true  # opt out later"), "true");
        assert_eq!(strip_inline_comment("true"), "true");
        // `#` without preceding whitespace is part of the value, not a comment.
        assert_eq!(strip_inline_comment("true#x"), "true#x");
        assert_eq!(strip_inline_comment("#leading"), "#leading");
        assert_eq!(strip_inline_comment(""), "");
    }

    #[test]
    fn command_valid_with_description_only() {
        let input = make_write_input(
            "/repo/.claude/commands/deploy.md",
            "---\ndescription: Deploy the app\nallowed-tools: Bash\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn skill_dir_name_deeply_nested() {
        assert_eq!(
            skill_dir_name("/a/b/c/.claude/skills/deep-skill/SKILL.md"),
            Some("deep-skill")
        );
    }

    #[test]
    fn classify_skill_md_not_in_skills_dir() {
        // SKILL.md but not under /skills/
        assert_eq!(classify_path("/project/SKILL.md"), FileType::Other);
    }

    #[test]
    fn frontmatter_line_without_colon() {
        // A line in frontmatter with no colon
        let content = "---\nname: my-skill\nbroken line\ndescription: Use when testing\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2); // broken line is skipped
    }

    // --- Platform sweep: when_to_use, arguments, disallowed-tools, effort, shell ---

    #[test]
    fn run_skill_with_when_to_use_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nwhen_to_use: Use when doing X\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_arguments_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\narguments: issue branch\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_disallowed_tools_passes() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\ndisallowed-tools: AskUserQuestion\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_valid_effort_passes() {
        for level in ["low", "medium", "high", "xhigh", "max"] {
            let content = format!(
                "---\nname: my-skill\ndescription: Use when testing\neffort: {level}\n---\n# Content"
            );
            let input = make_write_input("/repo/.claude/skills/my-skill/SKILL.md", &content);
            let result = ValidateSkillFrontmatter.run(&input);
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "effort: {level} should pass"
            );
        }
    }

    #[test]
    fn run_skill_with_invalid_effort_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\neffort: extreme\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("'effort' must be one of"));
    }

    #[test]
    fn run_skill_with_valid_shell_passes() {
        for shell in ["bash", "powershell"] {
            let content = format!(
                "---\nname: my-skill\ndescription: Use when testing\nshell: {shell}\n---\n# Content"
            );
            let input = make_write_input("/repo/.claude/skills/my-skill/SKILL.md", &content);
            let result = ValidateSkillFrontmatter.run(&input);
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "shell: {shell} should pass"
            );
        }
    }

    #[test]
    fn run_skill_with_invalid_shell_blocks() {
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\nshell: zsh\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("'shell' must be one of"));
    }

    #[test]
    fn run_skill_unknown_field_still_rejected_alongside_new_fields() {
        // The new fields don't loosen the allowlist — an unrelated unknown
        // key is still rejected.
        let input = make_write_input(
            "/repo/.claude/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: Use when testing\neffort: high\ntotally-made-up: value\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Unknown frontmatter field: 'totally-made-up'")
        );
    }

    // ---- #613: Description Format Rules ----

    const SKILL_PATH: &str = "/repo/.claude/skills/my-skill/SKILL.md";

    fn skill_verdict(frontmatter_body: &str) -> (cadence_hooks_core::Outcome, String) {
        let content = format!("---\nname: my-skill\n{frontmatter_body}\n---\n# Content");
        let r = ValidateSkillFrontmatter.run(&make_write_input(SKILL_PATH, &content));
        (r.outcome, r.message.unwrap_or_default())
    }

    #[test]
    fn description_block_scalar_blocks() {
        for indicator in [">-", "|", ">", "|-"] {
            let (o, m) = skill_verdict(&format!(
                "description: {indicator}\n  Use when testing things"
            ));
            assert_eq!(o, cadence_hooks_core::Outcome::Block, "{indicator}");
            assert!(m.contains("single YAML line"), "{m}");
        }
    }

    #[test]
    fn description_continuation_line_blocks() {
        let (o, m) = skill_verdict("description: Use when testing\n  and more text");
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
        assert!(m.contains("single YAML line"), "{m}");
    }

    #[test]
    fn description_over_spec_cap_blocks_and_at_cap_passes() {
        let at_cap = format!(
            "Use when testing {}",
            "x".repeat(DESCRIPTION_MAX_CHARS - 17)
        );
        assert_eq!(at_cap.chars().count(), DESCRIPTION_MAX_CHARS);
        let (o, _) = skill_verdict(&format!("description: {at_cap}"));
        assert_eq!(o, cadence_hooks_core::Outcome::Allow);
        let (o, m) = skill_verdict(&format!("description: {at_cap}y"));
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
        assert!(m.contains("spec cap"), "{m}");
    }

    #[test]
    fn description_without_trigger_clause_nudges_not_blocks() {
        let (o, m) = skill_verdict("description: Liveness-gated reclaim of cruft");
        assert_eq!(o, cadence_hooks_core::Outcome::Nudge);
        assert!(m.contains("no trigger clause"), "{m}");
    }

    #[test]
    fn trigger_matcher_accepts_real_forms_and_rejects_negations() {
        for yes in [
            "Use when testing",
            "Reclaims cruft. Use after a crash.",
            "Audits usage. USE BEFORE shipping.",
            "Use this skill when the user asks",
            "Use proactively whenever code changes",
            "Invoke when reviewing",
        ] {
            assert!(has_trigger_clause(yes), "{yes}");
        }
        for no in [
            "Do not use when offline",
            "Don't use after merge",
            "Never use before review",
            "Fixed because when it broke",
            "Reclaims cruft",
            "Misuse when",
        ] {
            assert!(!has_trigger_clause(no), "{no}");
        }
    }

    #[test]
    fn quoted_hash_is_content_not_a_comment() {
        // Length and trigger both read the unquoted text.
        assert_eq!(
            scalar_text("\"Parses # headings. Use when x\""),
            "Parses # headings. Use when x"
        );
        assert_eq!(scalar_text("'#12'"), "#12");
        assert_eq!(scalar_text("'it''s'"), "it's");
        assert_eq!(scalar_text("\"a\" # comment"), "a");
        assert_eq!(scalar_text("plain # comment"), "plain");
        let (o, _) = skill_verdict("description: \"Parses # headings. Use when testing\"");
        assert_eq!(o, cadence_hooks_core::Outcome::Allow);
        let (o, _) = skill_verdict("description: 'Tracks #12. Use when testing'");
        assert_eq!(o, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_scalar_when_to_use_supplies_the_trigger() {
        let (o, _) =
            skill_verdict("description: Reclaims cruft\nwhen_to_use: >-\n  Use when the lane dies");
        assert_eq!(o, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn already_violating_skill_stays_editable_but_new_violation_blocks() {
        let old = "---\nname: my-skill\ndescription: >-\n  Use when testing\n---\nBody line.\n";
        let (_dir, path) = on_disk_skill(old);
        let ok =
            ValidateSkillFrontmatter.run(&make_edit(&path, "Body line.", "Body line, edited."));
        assert_eq!(ok.outcome, cadence_hooks_core::Outcome::Allow);
        // Introducing a DIFFERENT violation (length) on top still blocks.
        let long = "x".repeat(DESCRIPTION_MAX_CHARS + 1);
        let (_dir2, path2) = on_disk_skill(VALID_SKILL);
        let bad = ValidateSkillFrontmatter.run(&make_edit(
            &path2,
            "description: Use when testing",
            &format!("description: Use when {long}"),
        ));
        assert_eq!(bad.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn already_missing_trigger_is_not_renudged_on_unrelated_edit() {
        let old = "---\nname: my-skill\ndescription: Reclaims cruft\n---\nBody line.\n";
        let (_dir, path) = on_disk_skill(old);
        let r = ValidateSkillFrontmatter.run(&make_edit(&path, "Body line.", "Edited."));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn description_trigger_forms_pass() {
        for fm in [
            "description: Use when testing",
            "description: Reclaims cruft. Use after a crash.",
            "description: Audits usage. USE BEFORE shipping.",
            "description: \"use WHEN quoted\"",
            "description: Reclaims cruft\nwhen_to_use: Use when the lane dies",
            "description: Audits usage. USE BEFORE shipping.",
        ] {
            assert_eq!(
                skill_verdict(fm).0,
                cadence_hooks_core::Outcome::Allow,
                "{fm}"
            );
        }
    }

    #[test]
    fn description_rules_do_not_apply_to_commands() {
        let input = make_write_input(
            "/repo/.claude/commands/my-cmd.md",
            "---\ndescription: >-\n  a command\n---\n# Content",
        );
        assert_eq!(
            ValidateSkillFrontmatter.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    // ---- #614: @skills/ force-load ----

    #[test]
    fn force_load_reference_in_prose_blocks() {
        let content = "---\nname: my-skill\ndescription: Use when testing\n---\nSee @skills/other/SKILL.md for more.\n";
        let r = ValidateSkillFrontmatter.run(&make_write_input(SKILL_PATH, content));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Block);
        assert!(r.message.unwrap().contains("@skills/other/SKILL.md"));
    }

    #[test]
    fn force_load_in_code_span_fence_or_word_is_a_mention() {
        for body in [
            "Never write `@skills/x/SKILL.md` here.",
            "```\n@skills/x/SKILL.md\n```",
            "mail me at dev@skills/x",
        ] {
            let content =
                format!("---\nname: my-skill\ndescription: Use when testing\n---\n{body}\n");
            let r = ValidateSkillFrontmatter.run(&make_write_input(SKILL_PATH, &content));
            assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow, "{body}");
        }
    }

    #[test]
    fn force_load_already_on_disk_stays_editable_but_a_new_one_blocks() {
        let old =
            "---\nname: my-skill\ndescription: Use when testing\n---\nSee @skills/a/SKILL.md\n";
        let (_dir, path) = on_disk_skill(old);
        let ok = ValidateSkillFrontmatter.run(&make_edit(&path, "See", "Look at"));
        assert_eq!(ok.outcome, cadence_hooks_core::Outcome::Allow);
        let bad = ValidateSkillFrontmatter.run(&make_edit(&path, "See", "@skills/b/SKILL.md and"));
        assert_eq!(bad.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---- #615: plugin agents ----

    fn plugin_agent() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("some-plugin");
        std::fs::create_dir_all(root.join(".claude-plugin")).unwrap();
        std::fs::create_dir_all(root.join("agents")).unwrap();
        let path = as_hook_path(&root.join("agents/reviewer.md"));
        (dir, path)
    }

    #[test]
    fn plugin_agent_with_ignored_fields_nudges() {
        let (_d, path) = plugin_agent();
        assert_eq!(classify_path(&path), FileType::Agent);
        let content =
            "---\nname: r\ndescription: d\npermissionMode: plan\nhooks:\n  x: y\n---\nbody";
        let r = ValidateSkillFrontmatter.run(&make_write_input(&path, content));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Nudge);
        let m = r.message.unwrap();
        assert!(m.contains("hooks") && m.contains("permissionMode"), "{m}");
    }

    #[test]
    fn plugin_agent_without_ignored_fields_is_silent() {
        let (_d, path) = plugin_agent();
        let content = "---\nname: r\ndescription: d\nmodel: opus\nskills: a\n---\nbody";
        let r = ValidateSkillFrontmatter.run(&make_write_input(&path, content));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn project_agent_dir_is_not_a_plugin_agent() {
        // `.claude/agents/` honours all three fields — a warning would be false.
        assert_eq!(
            classify_path("/repo/.claude/agents/r.md"),
            FileType::ProjectAgent
        );
    }

    // ---- #615: teammate `skills:`/`mcpServers:` ----

    fn project_agent() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(root.join(".claude/agents")).unwrap();
        let path = as_hook_path(&root.join(".claude/agents/reviewer.md"));
        (dir, path)
    }

    #[test]
    fn teammate_ignored_fields_table() {
        let (_p, plugin_path) = plugin_agent();
        let (_q, project_path) = project_agent();
        let cases: &[(&str, &str, &str, &[&str])] = &[
            // (name, surface, frontmatter, expected nudge needles; empty = allow)
            (
                "project teammate skills",
                "project",
                "description: A teammate reviewer\nskills: a",
                &["skills", "teammate"],
            ),
            (
                "project teammate mcp",
                "project",
                "description: teammate\nmcpServers: x",
                &["mcpServers"],
            ),
            (
                "plugin teammate skills",
                "plugin",
                "description: A teammate reviewer\nskills: a",
                &["skills"],
            ),
            (
                "plugin both halves",
                "plugin",
                "description: teammate\nskills: a\nhooks:\n  x: y",
                &["skills", "hooks"],
            ),
            (
                "agent-team phrase",
                "project",
                "description: Reviewer that runs as an agent team member\nskills: a",
                &["skills"],
            ),
            (
                "no teammate wording",
                "project",
                "description: Reviews code\nskills: a",
                &[],
            ),
            (
                "teammate wording, no fields",
                "project",
                "description: A teammate reviewer\nmodel: opus",
                &[],
            ),
            (
                "word boundary",
                "project",
                "description: Reviews steammates data\nskills: a",
                &[],
            ),
            (
                "block scalar description",
                "project",
                "description: >\n  Runs as a teammate\nskills: a",
                &["skills"],
            ),
            (
                "project hooks are honoured",
                "project",
                "description: Reviews\nhooks:\n  x: y\npermissionMode: plan",
                &[],
            ),
        ];
        for (name, surface, fm, needles) in cases {
            let path = if *surface == "plugin" {
                &plugin_path
            } else {
                &project_path
            };
            let content = format!("---\nname: r\n{fm}\n---\nbody");
            let r = ValidateSkillFrontmatter.run(&make_write_input(path, &content));
            if needles.is_empty() {
                assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow, "{name}");
            } else {
                assert_eq!(r.outcome, cadence_hooks_core::Outcome::Nudge, "{name}");
                let m = r.message.unwrap();
                for n in *needles {
                    assert!(m.contains(n), "{name}: {m}");
                }
            }
        }
    }

    #[test]
    fn project_agent_classifies_and_never_blocks_on_missing_frontmatter() {
        let (_q, project_path) = project_agent();
        assert_eq!(classify_path(&project_path), FileType::ProjectAgent);
        let r = ValidateSkillFrontmatter.run(&make_write_input(&project_path, "no frontmatter"));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---- #607: living-plan frontmatter ----

    fn plan_verdict(content: &str) -> (cadence_hooks_core::Outcome, String) {
        let r = ValidateSkillFrontmatter.run(&make_write_input(
            "/repo/docs/plans/2026-09-29-x.md",
            content,
        ));
        (r.outcome, r.message.unwrap_or_default())
    }

    #[test]
    fn plan_with_flat_keys_passes_and_frontmatterless_plan_passes() {
        let ok = "---\nstatus: planned\nnext: go\ndate: 2026-09-29\nmodel: m\n---\n\n# Plan\n";
        assert_eq!(plan_verdict(ok).0, cadence_hooks_core::Outcome::Allow);
        assert_eq!(
            plan_verdict("# Old plan\n").0,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn plan_nested_provenance_in_frontmatter_blocks() {
        let bad = "---\nstatus: planned\nprovenance:\n  date: 2026-09-29\n---\n# Plan\n";
        let (o, m) = plan_verdict(bad);
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
        assert!(m.contains("provenance"), "{m}");
    }

    #[test]
    fn plan_fenced_provenance_above_first_heading_blocks_but_body_docs_pass() {
        let bad = "---\nstatus: planned\n---\n\n```yaml\nprovenance:\n  date: x\n```\n\n# Plan\n";
        assert_eq!(plan_verdict(bad).0, cadence_hooks_core::Outcome::Block);
        // Below the first heading a plan may document the rule.
        let doc = "---\nstatus: planned\n---\n# Plan\n\n```yaml\nprovenance:\n  date: x\n```\n";
        assert_eq!(plan_verdict(doc).0, cadence_hooks_core::Outcome::Allow);
        let fine = "---\nstatus: planned\n---\n\n```yaml\nother: 1\n```\n# Plan\n";
        assert_eq!(plan_verdict(fine).0, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn already_violating_plan_stays_editable_but_new_violation_blocks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs/plans")).unwrap();
        let path = as_hook_path(&dir.path().join("docs/plans/2026-09-29-x.md"));
        let legacy = "---\nstatus: planned\n---\n---\ndate: x\n---\n# Plan\n- [ ] task\n";
        std::fs::write(&path, legacy).unwrap();
        assert_eq!(classify_path(&path), FileType::Plan);
        let tick = ValidateSkillFrontmatter.run(&make_edit(&path, "- [ ] task", "- [x] task"));
        assert_eq!(tick.outcome, cadence_hooks_core::Outcome::Allow);
        // Adding a different violation to the same file still blocks.
        let bad = ValidateSkillFrontmatter.run(&make_edit(
            &path,
            "status: planned",
            "status: planned\nprovenance:\n  date: x",
        ));
        assert_eq!(bad.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_load_tokens_lose_trailing_punctuation_and_fences_match_marker_and_length() {
        assert_eq!(
            force_load_refs("see (@skills/a/SKILL.md)."),
            vec!["@skills/a/SKILL.md"]
        );
        assert_eq!(
            force_load_refs("@skills/a, @skills/b;"),
            vec!["@skills/a", "@skills/b"]
        );
        // A ~~~ inside a ``` fence, or a shorter ``` inside a longer one, does not close it.
        assert!(force_load_refs("```\n~~~\n@skills/x\n```\n").is_empty());
        assert!(force_load_refs("````\n```\n@skills/x\n````\n").is_empty());
        // After the fence closes, prose counts again.
        assert_eq!(force_load_refs("```\nx\n```\n@skills/y"), vec!["@skills/y"]);
        // Indentation is NOT an escape hatch (I1): these are prose under CommonMark.
        for prose in [
            "1. Step\n    Then load @skills/x/SKILL.md",
            "- outer\n    - inner @skills/x/SKILL.md",
            "-\tbullet @skills/x/SKILL.md",
            "- outer\n\t- tab-indented bullet @skills/x/SKILL.md",
            "Para\n    @skills/x/SKILL.md",
        ] {
            assert_eq!(
                force_load_refs(prose),
                vec!["@skills/x/SKILL.md"],
                "{prose:?}"
            );
        }
    }

    #[test]
    fn plan_second_frontmatter_block_blocks() {
        let bad = "---\nstatus: planned\n---\n---\ndate: x\n---\n# Plan\n";
        assert_eq!(plan_verdict(bad).0, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn only_direct_docs_plans_children_are_plans() {
        assert_eq!(classify_path("/repo/docs/plans/x.md"), FileType::Plan);
        assert_eq!(classify_path("/repo/docs/plans/sub/x.md"), FileType::Other);
        assert_eq!(classify_path("/repo/plans/x.md"), FileType::Other);
    }

    // ---- delta review (N1-N9, I1) ----

    #[test]
    fn n1_legacy_long_description_may_shrink_or_stay_but_not_grow() {
        let cap = DESCRIPTION_MAX_CHARS;
        let long = |n: usize| format!("Use when {}", "x".repeat(n - 9));
        let doc = |d: &str| format!("---\nname: my-skill\ndescription: {d}\n---\nBody.\n");
        let (_dir, path) = on_disk_skill(&doc(&long(cap + 76)));
        let same = ValidateSkillFrontmatter.run(&make_edit(&path, "Body.", "Body edited."));
        assert_eq!(same.outcome, cadence_hooks_core::Outcome::Allow);
        let shrink =
            ValidateSkillFrontmatter.run(&make_edit(&path, &long(cap + 76), &long(cap + 10)));
        assert_eq!(shrink.outcome, cadence_hooks_core::Outcome::Allow);
        let grow =
            ValidateSkillFrontmatter.run(&make_edit(&path, &long(cap + 76), &long(cap + 5000)));
        assert_eq!(grow.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn n2_before_reads_use_the_literal_path_the_edit_simulated() {
        // A trailing space is trimmed by `file_path()` but not by
        // `effective_content`; the before-read must follow the literal path.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("plug");
        std::fs::create_dir_all(root.join(".claude-plugin")).unwrap();
        std::fs::create_dir_all(root.join("skills/my-skill")).unwrap();
        let literal = format!("{}/skills/my-skill/SKILL.md ", as_hook_path(&root));
        std::fs::write(
            &literal,
            "---\nname: my-skill\ndescription: >-\n  Use when testing\n---\nBody.\n",
        )
        .unwrap();
        let r = ValidateSkillFrontmatter.run(&make_edit(&literal, "Body.", "Edited."));
        assert_eq!(
            r.outcome,
            cadence_hooks_core::Outcome::Allow,
            "{:?}",
            r.message
        );
    }

    #[test]
    fn n3_a_non_fence_does_not_hide_the_rest_of_the_document() {
        // A non-fence must not hide the rest of the document.
        assert_eq!(
            force_load_refs("```not a fence```\n@skills/y"),
            vec!["@skills/y"]
        );
    }

    #[test]
    fn n4_code_spans_match_by_run_length_and_unclosed_runs_are_literal() {
        assert!(force_load_refs("``a ` @skills/x``").is_empty());
        assert!(force_load_refs("`@skills/x`").is_empty());
        // Mismatched run lengths do not close the span, so the token is prose...
        assert_eq!(force_load_refs("`` @skills/x `"), vec!["@skills/x"]);
        // ...and an unclosed backtick does not hide the rest of the line.
        assert_eq!(force_load_refs("a ` b @skills/x"), vec!["@skills/x"]);
    }

    #[test]
    fn n5_blank_line_before_continuation_still_counts_as_multiline() {
        let (o, m) = skill_verdict("description: Use when x\n\n  continued");
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
        assert!(m.contains("single YAML line"), "{m}");
    }

    #[test]
    fn n6_negation_handles_curly_apostrophe_and_two_word_lookback() {
        assert!(!has_trigger_clause("Don\u{2019}t use when offline"));
        assert!(!has_trigger_clause("Do not ever use when offline"));
        assert!(has_trigger_clause("Not for X. Use when Y"));
    }

    #[test]
    fn n7_repeated_new_reference_is_reported_once() {
        let content = "---\nname: my-skill\ndescription: Use when testing\n---\n@skills/a and @skills/a again\n";
        let r = ValidateSkillFrontmatter.run(&make_write_input(SKILL_PATH, content));
        assert_eq!(r.message.unwrap().matches("'@skills/a'").count(), 1);
    }

    #[test]
    fn n8_thematic_break_after_frontmatter_is_not_a_second_block() {
        let ok = "---\nstatus: planned\n---\n---\n\n# Plan\n\nprose\n---\n";
        assert_eq!(plan_verdict(ok).0, cadence_hooks_core::Outcome::Allow);
        let bad = "---\nstatus: planned\n---\n---\ndate: x\n---\n# Plan\n";
        assert_eq!(plan_verdict(bad).0, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn n9_description_key_with_space_before_colon_is_recognised() {
        let (o, _) = skill_verdict("description : >-\n  Use when x");
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
        let (o, _) = skill_verdict("description : Use when x\n\n  more");
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
    }

    // ---- CommonMark parser replaces the hand-rolled scan ----

    #[test]
    fn commonmark_repros_from_review() {
        let f = "```";
        let allow = [
            format!("- item\n\n    {f}\n    @skills/x/SKILL.md\n    {f}"),
            "Para\n\n    @skills/x/SKILL.md".to_string(),
            format!("{f}\n@skills/x/SKILL.md\n{f}"),
        ];
        for doc in &allow {
            assert!(force_load_refs(doc).is_empty(), "{doc:?}");
        }
        let block = [
            format!("- item\n  {f}\n  code\n- next @skills/x/SKILL.md"),
            format!(" \t{f}\n@skills/x/SKILL.md"),
            "text `a\nb` @skills/x/SKILL.md `c`".to_string(),
            "\\` @skills/x/SKILL.md `".to_string(),
        ];
        for doc in &block {
            assert_eq!(force_load_refs(doc), vec!["@skills/x/SKILL.md"], "{doc:?}");
        }
    }

    #[test]
    fn links_and_emphasis_are_prose_and_backtick_is_trimmed() {
        assert_eq!(
            force_load_refs("[see @skills/x/SKILL.md](http://e)"),
            vec!["@skills/x/SKILL.md"]
        );
        assert_eq!(force_load_refs("*@skills/x*"), vec!["@skills/x"]);
        assert_eq!(force_load_refs("@skills/x`"), vec!["@skills/x"]);
    }

    #[test]
    fn na_negation_lookback_stops_at_sentence_boundary() {
        assert!(has_trigger_clause("Never touch X. Use when Y"));
        assert!(has_trigger_clause("Not for X; use when Y"));
        assert!(has_trigger_clause("Don't panic! Use when Y"));
        assert!(!has_trigger_clause("Never use when Y"));
    }

    #[test]
    fn nb_second_frontmatter_needs_a_key_or_comment_then_key_first() {
        // Blank line first: not a frontmatter block.
        let a = "---\nstatus: p\n---\n---\n\ndate: x\n---\n# Plan\n";
        assert_eq!(plan_verdict(a).0, cadence_hooks_core::Outcome::Allow);
        // Key first, blank lines later: still a block (N2).
        let b = "---\nstatus: p\n---\n---\ndate: x\n\nmore: y\n---\n# Plan\n";
        assert_eq!(plan_verdict(b).0, cadence_hooks_core::Outcome::Block);
        // Comment then key: a block (N2).
        let c = "---\nstatus: p\n---\n---\n# note\ndate: x\n---\n# Plan\n";
        assert_eq!(plan_verdict(c).0, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn nc_indented_yaml_comment_after_description_is_not_a_continuation() {
        let (o, _) = skill_verdict("description: Use when x\n  # a comment");
        assert_eq!(o, cadence_hooks_core::Outcome::Allow);
        let (o, _) = skill_verdict("description: Use when x\n  # a comment\n  real continuation");
        assert_eq!(o, cadence_hooks_core::Outcome::Block);
    }

    // ---- third delta review: parser locates code, raw text is scanned ----

    #[test]
    fn i1_constructs_without_text_events_are_still_scanned() {
        for doc in [
            "<details>\n@skills/x/SKILL.md\n</details>",
            "<!-- @skills/x/SKILL.md -->",
            "<a href=\"@skills/x/SKILL.md\">t</a>",
            "[ref]: @skills/x/SKILL.md",
            "[^1]: @skills/x/SKILL.md",
            "[a](  @skills/x/SKILL.md  )",
            "[a](b \"@skills/x/SKILL.md\")",
            "![img](b.png \"@skills/x/SKILL.md\")",
        ] {
            assert_eq!(force_load_refs(doc), vec!["@skills/x/SKILL.md"], "{doc:?}");
        }
    }

    #[test]
    fn n4_escaped_entity_and_non_path_forms_are_not_references() {
        for doc in [
            "&#64;skills/x/SKILL.md",
            "\\@skills/x/SKILL.md",
            "@skills/*x*/SKILL.md",
            "@skills/",
        ] {
            assert!(force_load_refs(doc).is_empty(), "{doc:?}");
        }
    }

    #[test]
    fn i2_frontmatter_is_not_parsed_as_markdown() {
        let block =
            |fm: &str| format!("---\nname: s\ndescription: >-\n{fm}\n---\n@skills/x/SKILL.md\n");
        for fm in ["   <!--", "   ```", "   plain"] {
            assert_eq!(
                force_load_refs(&block(fm)),
                vec!["@skills/x/SKILL.md"],
                "{fm:?}"
            );
        }
        // The old on-disk document is read the same way.
        assert_eq!(body_after_frontmatter("---\na: b\n---\nbody\n"), "body\n");
        assert_eq!(
            body_after_frontmatter("no frontmatter\n"),
            "no frontmatter\n"
        );
    }

    #[test]
    fn n3_heading_inside_a_blockquote_is_not_the_first_heading() {
        let doc = "---\nstatus: p\n---\n> # quoted\n\n```yaml\nprovenance:\n  d: 1\n```\n";
        assert_eq!(plan_verdict(doc).0, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn n5_trailing_angle_bracket_is_trimmed() {
        assert_eq!(force_load_refs("<@skills/x>"), vec!["@skills/x"]);
    }

    #[test]
    fn claude_code_lazy_frontmatter_end_is_scanned_as_body() {
        let skill = |fm: &str| {
            format!("---\nname: probe\ndescription: {fm}\nLoad @skills/x/SKILL.md\n---\n")
        };
        let cases = [
            skill("Use when probing---"),
            skill("Use when probing.\n--- "),
            "---\ndescription: x---\nLoad @skills/x/SKILL.md\n---\nbody\n".to_string(),
            "---\ndescription: x\n---\r \nLoad @skills/x/SKILL.md\n---\nbody\n".to_string(),
        ];
        for doc in &cases {
            assert_eq!(force_load_refs(doc), vec!["@skills/x/SKILL.md"], "{doc:?}");
        }
        // Through the check itself, as skill and as command.
        let r = ValidateSkillFrontmatter.run(&make_write_input(SKILL_PATH, &cases[0]));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Block);
        let r = ValidateSkillFrontmatter
            .run(&make_write_input("/repo/.claude/commands/c.md", &cases[2]));
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn second_frontmatter_search_stops_at_the_first_heading() {
        let doc = "---\nstatus: p\n---\n---\nContext: we need a plan.\n\n# Plan\n\nstuff\n\n---\n\nmore\n";
        assert_eq!(plan_verdict(doc).0, cadence_hooks_core::Outcome::Allow);
    }
}
