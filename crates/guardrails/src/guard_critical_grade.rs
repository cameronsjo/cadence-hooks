//! Refuse applying the human-only Critical grades (`impact:critical`,
//! `likelihood:critical`) from a Bash `gh` call (cameronsjo/cadence-hooks#895).
//!
//! Agents run under the operator's token, so GitHub permissions cannot tell an
//! agent from the operator; this guard is the preventive control on managed
//! paths. It is not a human boundary. The corrective layer is the `labeled`
//! workflow (#896).
//!
//! **The ruling.** The issue leaves the "human ruling" open, so it is the
//! operator's environment: `CADENCE_ALLOW_CRITICAL_GRADE=1` in the hook
//! process env. It is read from the process env only, never from the command
//! text, so `CADENCE_ALLOW_CRITICAL_GRADE=1 gh …` (or an `export` earlier in the
//! same command) still blocks.
//!
//! **Allowlist shape.** Only label-carrying inputs of an applying command are
//! read: `--label`/`-l`/`--add-label` on `gh issue|pr create|edit`, and
//! `labels…` fields (or a body the guard cannot read) on a `gh api` write to
//! an issue or PR endpoint. Removals, reads, `gh label create`, and label
//! names appearing in titles or bodies pass. A label value the shell computes
//! (`$x`, backticks) cannot be read and blocks.

use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, gh_command_path, skip_transparent_prefixes,
    unescape_word,
};
use cadence_hooks_core::{BlockMetadata, BypassProvenance, Check, CheckResult, HookInput};

/// The human-only labels, lowercase (GitHub matches label names case-insensitively).
const CRITICAL_LABELS: &[&str] = &["impact:critical", "likelihood:critical"];

/// The process-env switch that carries the operator's ruling.
const RULING_ENV: &str = "CADENCE_ALLOW_CRITICAL_GRADE";

/// Short flags of `gh issue|pr create|edit` that take a value: the rest of a
/// cluster (`-tfoo`) belongs to them, so it is not scanned for `l`.
const VALUE_SHORTS: &[char] = &['t', 'b', 'F', 'R', 'a', 'm', 'p', 'T', 'B', 'H', 'r', 'e'];

/// Why a segment was refused.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    /// What the command applies, for the message.
    what: String,
    /// True when the label could not be read (shell-computed or unreadable body).
    unreadable: bool,
}

/// Whether a word carries any shell expansion (`$…` or a backtick): its value
/// is not readable from the command text, so ambiguity keeps blocking.
fn computed(word: &str) -> bool {
    word.contains(['$', '`'])
}

/// Whether one comma-separated label value applies a critical grade.
fn label_value_finding(value: &str) -> Option<Finding> {
    if computed(value) {
        return Some(Finding {
            what: format!("a shell-computed label value `{value}`"),
            unreadable: true,
        });
    }
    let hit = value
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .find(|p| CRITICAL_LABELS.contains(&p.as_str()))?;
    Some(Finding {
        what: format!("`{hit}`"),
        unreadable: false,
    })
}

/// Label values of a `gh issue|pr create|edit` argv.
fn issue_pr_finding(argv: &[String]) -> Option<Finding> {
    let mut i = 1;
    while i < argv.len() {
        let raw = argv[i].as_str();
        if raw == "--" {
            break;
        }
        let u = unescape_word(raw);
        let u: &str = u.as_ref();
        let mut value: Option<String> = None;
        if let Some(long) = u.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            if name == "label" || name == "add-label" {
                value = match inline {
                    Some(v) => Some(v),
                    None => {
                        i += 1;
                        argv.get(i).cloned()
                    }
                };
            }
        } else if let Some(cluster) = u.strip_prefix('-') {
            for (idx, c) in cluster.char_indices() {
                if c == 'l' {
                    let rest = &cluster[idx + 1..];
                    value = if rest.is_empty() {
                        i += 1;
                        argv.get(i).cloned()
                    } else {
                        Some(rest.strip_prefix('=').unwrap_or(rest).to_string())
                    };
                    break;
                }
                if VALUE_SHORTS.contains(&c) {
                    break;
                }
            }
        }
        if let Some(f) = value.as_deref().and_then(label_value_finding) {
            return Some(f);
        }
        i += 1;
    }
    None
}

/// Whether a `gh api` endpoint can carry a label-apply body: an issue or PR
/// resource itself, or its `labels` collection. Comments, reviews and the
/// like are not.
fn endpoint_can_apply_labels(endpoint: &str) -> bool {
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some(pos) = segs.iter().position(|s| *s == "issues" || *s == "pulls") else {
        return false;
    };
    matches!(&segs[pos + 1..], [] | [_] | [_, "labels"])
}

/// A `-f`/`-F` field value, read from a file for the `@path` form.
fn field_text(value: &str) -> Result<String, ()> {
    match value.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).map_err(|_| ()),
        None => Ok(value.to_string()),
    }
}

/// Labels applied by a `gh api` argv (`argv[0]` is `gh`).
fn api_finding(argv: &[String]) -> Option<Finding> {
    let mut endpoint: Option<&str> = None;
    let mut explicit_get = false;
    let mut input: Option<String> = None;
    let mut fields: Vec<String> = Vec::new();
    let mut seen_api = false;
    let mut i = 1;
    while i < argv.len() {
        let raw = argv[i].as_str();
        let u = unescape_word(raw);
        let u: &str = u.as_ref();
        let take = |i: &mut usize, inline: Option<&str>| -> Option<String> {
            match inline {
                Some(v) => Some(v.to_string()),
                None => {
                    *i += 1;
                    argv.get(*i).cloned()
                }
            }
        };
        if let Some(long) = u.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            match name {
                "field" | "raw-field" => fields.extend(take(&mut i, inline)),
                "input" => input = take(&mut i, inline),
                "method" => {
                    explicit_get =
                        take(&mut i, inline).is_some_and(|m| m.eq_ignore_ascii_case("GET"));
                }
                "header" | "jq" | "template" | "hostname" | "cache" | "preview" => {
                    take(&mut i, inline);
                }
                _ => {}
            }
        } else if let Some(cluster) = u.strip_prefix('-').filter(|c| !c.is_empty()) {
            let mut chars = cluster.char_indices();
            if let Some((_, c)) = chars.next() {
                let rest = &cluster[c.len_utf8()..];
                let inline = (!rest.is_empty()).then(|| rest.strip_prefix('=').unwrap_or(rest));
                match c {
                    'f' | 'F' => fields.extend(take(&mut i, inline)),
                    'X' => {
                        explicit_get =
                            take(&mut i, inline).is_some_and(|m| m.eq_ignore_ascii_case("GET"));
                    }
                    'H' | 'q' | 't' => {
                        take(&mut i, inline);
                    }
                    _ => {}
                }
            }
        } else if !seen_api {
            seen_api = true; // the `api` word itself
        } else if endpoint.is_none() {
            endpoint = Some(raw);
        }
        i += 1;
    }
    if explicit_get {
        return None;
    }
    for field in &fields {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if key != "labels" && !key.starts_with("labels[") {
            continue;
        }
        match field_text(value) {
            Ok(text) => {
                let lower = text.to_ascii_lowercase();
                if computed(&text) {
                    return Some(Finding {
                        what: format!("a shell-computed `{key}` value"),
                        unreadable: true,
                    });
                }
                if let Some(hit) = CRITICAL_LABELS.iter().find(|l| lower.contains(*l)) {
                    return Some(Finding {
                        what: format!("`{hit}`"),
                        unreadable: false,
                    });
                }
            }
            Err(()) => {
                return Some(Finding {
                    what: format!("an unreadable `{key}` file"),
                    unreadable: true,
                });
            }
        }
    }
    if let Some(path) = input
        && endpoint.is_some_and(endpoint_can_apply_labels)
    {
        let text = if path == "-" {
            None
        } else {
            std::fs::read_to_string(&path).ok()
        };
        return match text {
            Some(t) => {
                let lower = t.to_ascii_lowercase();
                CRITICAL_LABELS
                    .iter()
                    .find(|l| lower.contains(*l))
                    .map(|hit| Finding {
                        what: format!("`{hit}`"),
                        unreadable: false,
                    })
            }
            None => Some(Finding {
                what: "a request body the guard cannot read (`--input`)".to_string(),
                unreadable: true,
            }),
        };
    }
    None
}

/// The finding in one segment, or `None` for anything that is not a critical
/// grade being applied.
fn segment_finding(segment: &str) -> Option<Finding> {
    let tokens = executable_tokens(segment);
    let rest = skip_transparent_prefixes(&tokens);
    let head = rest.first()?;
    if command_word(head).as_ref() != "gh" {
        return None;
    }
    let path = gh_command_path(rest, 2);
    match path.as_slice() {
        ["issue" | "pr", "create" | "edit"] => issue_pr_finding(rest),
        ["api", ..] => api_finding(rest),
        _ => None,
    }
}

/// Judge a command; `ruling` is whether the operator's env switch is set.
fn judge(command: &str, ruling: bool) -> Option<Finding> {
    if ruling {
        return None;
    }
    command_segments(command)
        .iter()
        .find_map(|s| segment_finding(s))
}

/// Block `gh` calls that apply `impact:critical` / `likelihood:critical`.
pub struct GuardCriticalGrade;

impl Check for GuardCriticalGrade {
    fn name(&self) -> &str {
        "guard-critical-grade"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        // Cheap prefilter: nothing to judge without a `gh`.
        if !command.to_ascii_lowercase().contains("gh") {
            return CheckResult::allow();
        }
        let ruling = std::env::var(RULING_ENV).is_ok_and(|v| v == "1");
        let Some(finding) = judge(command, ruling) else {
            // The ruling let a Critical grade through: record it (#223).
            if ruling && judge(command, false).is_some() {
                return CheckResult::allow_bypassed(BypassProvenance::env_switch(RULING_ENV));
            }
            return CheckResult::allow();
        };
        let fix =
            "file at `impact:high` / `likelihood:high` and ask the operator to apply Critical"
                .to_string();
        let why = if finding.unreadable {
            "The guard cannot tell whether it is a Critical grade, so it treats it as one; \
             name the label literally."
        } else {
            "Critical grades are human-only."
        };
        CheckResult::block_structured(
            format!(
                "🚫 critical-grade: this command applies {}\n   \
                 {why} A human must apply `impact:critical` and `likelihood:critical` \
                 (the-estate `wiki/doctrine/issue-labels.md`, \"The Critical gate\").\n   \
                 Fix: {fix}.\n   \
                 An inline `{RULING_ENV}=1` prefix does not count: the ruling is the operator's \
                 own environment.",
                finding.what
            ),
            BlockMetadata {
                rule_id: "critical-grade-human-only".to_string(),
                fix,
                allowed_owners: Vec::new(),
                severity: "error",
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    fn blocks(command: &str) -> bool {
        judge(command, false).is_some()
    }

    #[test]
    fn applying_a_critical_grade_blocks() {
        for cmd in [
            "gh issue edit 12 --add-label impact:critical",
            "gh issue edit 12 --add-label impact:high,likelihood:critical",
            "gh issue edit 12 --add-label=likelihood:critical",
            "gh issue edit 12 --add-label 'kind:bug, Impact:Critical'",
            "gh pr edit 3 --add-label impact:critical",
            "gh issue create --title x --label impact:critical",
            "gh issue create --label kind:bug --label likelihood:critical",
            "gh issue create -l impact:critical",
            "gh issue create -limpact:critical",
            "gh issue create -wl impact:critical",
            "gh issue new --label impact:critical",
            "gh pr create --label impact:critical --fill",
            "gh -R o/r issue edit 12 --add-label impact:critical",
            "gh --repo o/r issue edit 12 --add-label impact:critical",
            "gh issue edit 12 --add\\-label impact:critical",
            "/usr/bin/gh issue edit 12 --add-label impact:critical",
            "env FOO=1 gh issue edit 12 --add-label impact:critical",
            "true && gh issue edit 12 --add-label impact:critical",
            "bash -c 'gh issue edit 12 --add-label impact:critical'",
            "gh issue edit 12 --add-label \"$(echo impact:critical)\"",
            "gh issue edit 12 --add-label \"impact:crit$X\"",
            "gh api repos/o/r/issues/12/labels -f 'labels[]=likelihood:critical'",
            "gh api repos/o/r/issues/12/labels -f labels[]=impact:critical -f labels[]=x",
            "gh api repos/o/r/issues/12/labels --field 'labels[]=impact:critical'",
            "gh api repos/o/r/issues/12/labels -X POST -F 'labels[]=impact:critical'",
            "gh api repos/o/r/issues/12 -X PATCH -f 'labels[]=impact:critical'",
            "gh api repos/o/r/issues -f title=x -f 'labels[]=impact:critical'",
            "gh api repos/o/r/issues/12/labels -f labels='[\"Impact:Critical\"]'",
            "gh api repos/o/r/issues/12/labels --input -",
            "gh api repos/o/r/issues/12/labels --input /nonexistent/body.json",
            "CADENCE_ALLOW_CRITICAL_GRADE=1 gh issue edit 12 --add-label impact:critical",
            "export CADENCE_ALLOW_CRITICAL_GRADE=1 && gh issue edit 12 --add-label impact:critical",
        ] {
            assert!(blocks(cmd), "must block: {cmd}");
        }
    }

    #[test]
    fn everything_else_passes() {
        for cmd in [
            "gh issue create --label kind:bug --label impact:high",
            "gh issue edit 12 --add-label impact:high,likelihood:high",
            "gh label create impact:critical",
            "gh label create impact:critical --color ff0000 --description x",
            "gh issue edit 12 --remove-label impact:critical",
            "gh pr edit 3 --remove-label likelihood:critical",
            "gh issue list --label impact:critical",
            "gh pr list -l likelihood:critical",
            "gh issue view 12",
            "gh issue create --title 'mentions impact:critical' --body 'likelihood:critical is human-only'",
            "gh issue comment 12 --body 'impact:critical'",
            "gh issue edit 12 --add-label kind:bug",
            "gh api repos/o/r/issues/12/labels/impact:critical -X DELETE",
            "gh api repos/o/r/issues/12/labels",
            "gh api repos/o/r/issues -X GET -f labels=impact:critical",
            "gh api repos/o/r/issues/12/comments -f body=impact:critical",
            "gh api repos/o/r/issues/12/comments --input -",
            "gh api repos/o/r/issues/12/labels -f 'labels[]=impact:high'",
            "gh api repos/o/r/labels -f name=impact:critical -f color=ff0000",
            "echo gh issue edit 12 --add-label impact:critical",
            "git commit -m 'gh issue edit --add-label impact:critical'",
            "grep -r impact:critical .",
        ] {
            assert!(!blocks(cmd), "must pass: {cmd}");
        }
    }

    #[test]
    fn the_ruling_lets_the_first_case_through() {
        let cmd = "gh issue edit 12 --add-label impact:critical";
        assert!(judge(cmd, true).is_none());
        assert!(judge(cmd, false).is_some());
    }

    #[test]
    fn run_reads_the_ruling_from_process_env_only() {
        use crate::with_env;
        let inline = make_bash(
            "CADENCE_ALLOW_CRITICAL_GRADE=1 gh issue edit 12 --add-label impact:critical",
        );
        let plain = make_bash("gh issue edit 12 --add-label impact:critical");
        let mut got = Vec::new();
        for (env, input) in [
            (None, &plain),
            (Some("1"), &plain),
            (Some("yes"), &plain),
            (None, &inline),
            (Some("1"), &inline),
        ] {
            with_env(&[(RULING_ENV, env), ("CADENCE_DISABLE", None)], || {
                got.push(GuardCriticalGrade.run(input).outcome);
            });
        }
        assert_eq!(
            got,
            [
                Outcome::Block,
                Outcome::Allow,
                Outcome::Block,
                Outcome::Block,
                Outcome::Allow
            ]
        );
    }

    #[test]
    fn the_message_says_a_human_applies_it() {
        let r = GuardCriticalGrade.run(&make_bash("gh issue edit 12 --add-label impact:critical"));
        let m = r.message.unwrap_or_default();
        assert!(m.contains("impact:critical") && m.contains("human"), "{m}");
        assert!(m.contains("issue-labels.md"), "{m}");
    }

    #[test]
    fn a_large_adversarial_command_stays_fast() {
        let cmd = format!(
            "gh issue edit 1 --add-label kind:bug {}",
            "-l x ".repeat(40_000)
        );
        let t = std::time::Instant::now();
        let _ = judge(&cmd, false);
        assert!(t.elapsed().as_secs_f64() < 5.0);
    }
}
