//! Warn on an Agent/Task dispatch that trips a known dispatch trap.
//!
//! Advisory only: every arm nudges, none blocks (ADR-0001). Four arms:
//!
//! 1. **Omit-model** (cadence-hooks#606): a non-fork dispatch with no `model`
//!    silently inherits the session's most expensive tier.
//! 2. **Fork-model** (#606): a `model` override on a fork dispatch is ignored
//!    by the platform. A fork is `subagent_type: "fork"` or, per
//!    [`cadence_hooks_core::ToolInput::subagent_type`], an omitted type.
//! 3. **Execution oracle** (#837, option a): a brief that asks the subagent to
//!    run or execute candidate commands without naming a scrubbed or isolated
//!    HOME/env. On 2026-09-04 a reviewer ran a corpus containing `rm -rf ~`
//!    against the real HOME. This is a nudge naming the requirement, not the
//!    structural control the issue asks for.
//!
//! 4. **Dark teammate** (#606): a teammate spawn — an Agent call carrying a
//!    `name` (or the deprecated `team_name`), which under agent teams launches
//!    a teammate — whose agent definition grants a `tools:` list without
//!    `SendMessage`, or lists it under `disallowedTools`. A teammate's result
//!    never returns as a tool result, so without `SendMessage` it can never
//!    report or answer a `shutdown_request`. The definition is resolved by
//!    its `name:` frontmatter, as the platform does: a plugin agent
//!    (`plugin:agent`) in the newest cached copy of that plugin, any other in
//!    the project's `.claude/agents/` (`CLAUDE_PROJECT_DIR`, then the payload
//!    `cwd` and its ancestors) before the user's `<config>/agents/`. A
//!    definition that cannot be found, or whose `tools:` is absent or empty
//!    (it inherits every tool), stays silent.
//!
//! The prompt is untrusted free text: it is scanned, never echoed. So is the
//! teammate's name and the `subagent_type`.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};

/// Phrases that say the subagent is to execute candidate commands. Lowercase
/// substrings, deliberately narrow: "run the tests" must stay silent.
const EXEC_PHRASES: &[&str] = &[
    "execution oracle",
    "run each command",
    "execute each command",
    "run every command",
    "execute every command",
    "run the corpus",
    "execute the corpus",
    "run the candidate",
    "execute the candidate",
    "run these commands",
    "execute these commands",
    "run the commands",
    "execute the commands",
    "in a real shell",
    "what bash would do",
    "what the shell would do",
];

/// Phrases showing the brief already names containment. Any one silences arm 3.
const ISOLATION_PHRASES: &[&str] = &[
    "scratch home",
    "scrubbed",
    "isolated home",
    "isolated env",
    "temp home",
    "fake home",
    "throwaway home",
    "sandbox",
    "container",
    "env -i",
    "home=",
    "empty path",
    "bash -n",
    "do not execute",
    "do not run",
    "never execute",
    "never run",
];

fn is_fork(subagent_type: Option<&str>) -> bool {
    match subagent_type.map(str::trim) {
        None | Some("") => true,
        Some(t) => t.eq_ignore_ascii_case("fork"),
    }
}

/// Pure: does the prompt ask for execution with no containment named?
fn is_uncontained_execution(prompt: &str) -> bool {
    let p = prompt.to_ascii_lowercase();
    EXEC_PHRASES.iter().any(|x| p.contains(x)) && !ISOLATION_PHRASES.iter().any(|x| p.contains(x))
}

/// Pure decision over the four dispatch fields.
fn assess(
    subagent_type: Option<&str>,
    model: Option<&str>,
    prompt: Option<&str>,
) -> Vec<&'static str> {
    let mut notes = Vec::new();
    let has_model = model.is_some_and(|m| !m.trim().is_empty());
    let fork = is_fork(subagent_type);
    if !fork && !has_model {
        notes.push(
            "This dispatch sets no `model`, so it inherits the session's most expensive tier. \
             Pass `model` explicitly (or confirm the agent definition pins one).",
        );
    }
    if fork && has_model {
        notes.push(
            "A `model` override on a fork dispatch is ignored by the platform. Drop it, or \
             dispatch a named `subagent_type` if you need a different model.",
        );
    }
    if prompt.is_some_and(is_uncontained_execution) {
        notes.push(
            "The brief asks the subagent to execute commands but names no scrubbed or isolated \
             HOME/env. Executing candidate input against the real HOME can destroy it (`rm -rf ~` \
             incident, 2026-09-04). Require a scratch HOME and a deny-by-default PATH, or parse \
             with `bash -n` instead of executing.",
        );
    }
    notes
}

/// The note for a teammate spawn whose definition cannot use `SendMessage`.
const DARK_TEAMMATE: &str = "This dispatch names a teammate, but its agent definition does not \
    grant `SendMessage` (its `tools:` list omits it, or `disallowedTools` names it). A teammate's \
    result never returns as a tool result, so it can never report back or answer a \
    `shutdown_request`. Add `SendMessage` to the definition's `tools:`, or dispatch it unnamed.";

/// Is this Agent call a teammate spawn? A non-blank `name`, or the deprecated
/// `team_name` the platform still accepts.
fn is_teammate_spawn(input: &HookInput) -> bool {
    input.tool_input.as_ref().is_some_and(|ti| {
        ["name", "team_name"].iter().any(|key| {
            ti.extra
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        })
    })
}

/// Where agent definitions are looked up, in precedence order.
struct AgentRoots {
    /// `.claude/agents/` directories of the project, nearest first.
    project: Vec<PathBuf>,
    /// The user's `<config>/agents/`.
    user: PathBuf,
    /// `<config>/plugins/cache/`, laid out `<marketplace>/<plugin>/<version>/`.
    plugin_cache: PathBuf,
}

impl AgentRoots {
    fn for_input(input: &HookInput) -> Self {
        let mut project = Vec::new();
        if let Some(dir) = std::env::var_os("CLAUDE_PROJECT_DIR").filter(|dir| !dir.is_empty()) {
            project.push(PathBuf::from(dir).join(".claude/agents"));
        }
        if let Some(cwd) = input.cwd.as_deref() {
            for dir in Path::new(cwd).ancestors() {
                let agents = dir.join(".claude/agents");
                if !project.contains(&agents) {
                    project.push(agents);
                }
            }
        }
        let config = cadence_hooks_core::paths::claude_config_dir();
        Self {
            project,
            user: config.join("agents"),
            plugin_cache: config.join("plugins").join("cache"),
        }
    }
}

/// Most `.md` files read from one agents directory, and most bytes of each.
const MAX_AGENT_FILES: usize = 256;
const MAX_AGENT_BYTES: u64 = 64 * 1024;

/// The text of the agent definition `subagent_type` names, if one is found.
fn resolve_definition(subagent_type: &str, roots: &AgentRoots) -> Option<String> {
    if let Some((plugin, agent)) = subagent_type.split_once(':') {
        let dir = newest_plugin_copy(&roots.plugin_cache, plugin)?;
        return definition_in(&dir.join("agents"), agent);
    }
    roots
        .project
        .iter()
        .chain(std::iter::once(&roots.user))
        .find_map(|dir| definition_in(dir, subagent_type))
}

/// The most recently modified `<marketplace>/<plugin>/<version>/` directory
/// under `cache` — the copy the newest install or update wrote.
fn newest_plugin_copy(cache: &Path, plugin: &str) -> Option<PathBuf> {
    if plugin.is_empty() || plugin.contains(['/', '\\']) || plugin.starts_with('.') {
        return None;
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for marketplace in std::fs::read_dir(cache).ok()?.flatten() {
        let Ok(versions) = std::fs::read_dir(marketplace.path().join(plugin)) else {
            continue;
        };
        for version in versions.flatten() {
            let path = version.path();
            let Ok(modified) = version.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            if path.is_dir() && best.as_ref().is_none_or(|(newest, _)| modified > *newest) {
                best = Some((modified, path));
            }
        }
    }
    best.map(|(_, path)| path)
}

/// The definition in `dir` whose frontmatter `name:` is `agent` (or, with no
/// `name:`, whose file stem is), read from `<agent>.md` first.
fn definition_in(dir: &Path, agent: &str) -> Option<String> {
    let read = |path: &Path| -> Option<String> {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open(path)
            .ok()?
            .take(MAX_AGENT_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    };
    let names = |text: &str, stem: &str| match frontmatter_value(text, "name") {
        Some(FieldValue::Scalar(name)) => unquote(&name) == agent,
        _ => stem == agent,
    };
    if !agent.contains(['/', '\\']) && !agent.starts_with('.') {
        let direct = dir.join(format!("{agent}.md"));
        if let Some(text) = read(&direct).filter(|text| names(text, agent)) {
            return Some(text);
        }
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten().take(MAX_AGENT_FILES) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(text) = read(&path).filter(|text| names(text, stem)) {
            return Some(text);
        }
    }
    None
}

/// A top-level frontmatter field's value.
#[derive(Debug, PartialEq, Eq)]
enum FieldValue {
    /// `key: value` on one line (possibly empty).
    Scalar(String),
    /// `key:` followed by indented `- item` lines.
    Block(Vec<String>),
}

/// The value of top-level `key` in `text`'s `---` frontmatter.
fn frontmatter_value(text: &str, key: &str) -> Option<FieldValue> {
    let mut lines = text.lines();
    if lines.next()?.trim_end() != "---" {
        return None;
    }
    let body: Vec<&str> = lines.take_while(|line| line.trim_end() != "---").collect();
    let at = body.iter().position(|line| {
        line.strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })?;
    let value = body[at][key.len()..].trim_start()[1..].trim().to_string();
    if !value.is_empty() {
        return Some(FieldValue::Scalar(value));
    }
    let items: Vec<String> = body[at + 1..]
        .iter()
        .map_while(|line| {
            let trimmed = line.trim_start();
            (trimmed.len() < line.len() || trimmed.starts_with('-'))
                .then(|| {
                    trimmed
                        .strip_prefix('-')
                        .map(|item| unquote(item.trim()).to_string())
                })
                .flatten()
        })
        .collect();
    Some(if items.is_empty() {
        FieldValue::Scalar(String::new())
    } else {
        FieldValue::Block(items)
    })
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// The tools a list-valued field names — an inline `A, B`, a `[A, B]` array,
/// or a block sequence — or `None` when it is absent or empty. Parsed as
/// `cadence`'s `scripts/lint-agent-tools.py` does: quotes unwrap first, then
/// an unquoted ` #` comment is dropped.
fn tool_list(text: &str, key: &str) -> Option<Vec<String>> {
    let items = match frontmatter_value(text, key)? {
        FieldValue::Block(items) => items,
        FieldValue::Scalar(value) => {
            let value = value.trim();
            let unquoted = unquote(value);
            let scalar = if unquoted.len() < value.len() {
                unquoted
            } else {
                value.split(" #").next().unwrap_or("")
            };
            scalar
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|tool| unquote(tool).to_string())
                .collect()
        }
    };
    let items: Vec<String> = items.into_iter().filter(|tool| !tool.is_empty()).collect();
    (!items.is_empty()).then_some(items)
}

/// Pure: does this agent definition leave its agent without `SendMessage`?
/// An absent or empty `tools:` inherits every tool, and `*` grants them all.
fn denies_send_message(definition: &str) -> bool {
    let names_it = |tools: &[String]| tools.iter().any(|tool| tool == "SendMessage");
    let omitted = tool_list(definition, "tools")
        .is_some_and(|tools| !names_it(&tools) && !tools.iter().any(|tool| tool == "*"));
    let disallowed = tool_list(definition, "disallowedTools").is_some_and(|tools| names_it(&tools));
    omitted || disallowed
}

/// The dark-teammate arm: a teammate spawn whose resolved definition cannot
/// use `SendMessage`.
fn dark_teammate(input: &HookInput, roots: &AgentRoots) -> bool {
    if !is_teammate_spawn(input) {
        return false;
    }
    let Some(subagent_type) = input.subagent_type().map(str::trim) else {
        return false;
    };
    if is_fork(Some(subagent_type)) {
        return false;
    }
    resolve_definition(subagent_type, roots).is_some_and(|text| denies_send_message(&text))
}

/// Warns on Agent/Task dispatch traps. Never blocks.
pub struct WarnAgentDispatch;

impl Check for WarnAgentDispatch {
    fn name(&self) -> &str {
        "warn-agent-dispatch"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if !matches!(input.normalized_tool_name(), Some("Agent" | "Task")) {
            return CheckResult::allow();
        }
        let mut notes = assess(
            input.subagent_type(),
            input.agent_model(),
            input.agent_prompt(),
        );
        if dark_teammate(input, &AgentRoots::for_input(input)) {
            notes.push(DARK_TEAMMATE);
        }
        if notes.is_empty() {
            return CheckResult::allow();
        }
        CheckResult::nudge(notes.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn omit_and_fork_arms() {
        // (subagent_type, model, expected substring or None)
        let table: &[(Option<&str>, Option<&str>, Option<&str>)] = &[
            (Some("general-purpose"), None, Some("no `model`")),
            (Some("general-purpose"), Some("  "), Some("no `model`")),
            (Some("general-purpose"), Some("haiku"), None),
            (Some("cadence:explorer"), None, Some("no `model`")),
            (Some("fork"), None, None),
            (Some("Fork"), Some("haiku"), Some("ignored by the platform")),
            (None, None, None),
            (None, Some("haiku"), Some("ignored by the platform")),
            (Some(""), Some("opus"), Some("ignored by the platform")),
        ];
        for (ty, model, want) in table {
            let notes = assess(*ty, *model, None).join(" ");
            match want {
                Some(w) => assert!(notes.contains(w), "{ty:?} {model:?}: {notes}"),
                None => assert!(notes.is_empty(), "{ty:?} {model:?}: {notes}"),
            }
        }
    }

    #[test]
    fn execution_oracle_arm() {
        let table: &[(&str, bool)] = &[
            (
                "Run each command in the corpus and report what bash does",
                true,
            ),
            ("Use the shell as an execution oracle for these rows", true),
            ("Execute the candidate strings in a real shell", true),
            ("RUN THE CORPUS and compare", true),
            // Containment named: silent.
            ("Run each command with HOME=$(mktemp -d) and env -i", false),
            ("Execute the commands inside a scratch home", false),
            ("Run the corpus in a container", false),
            ("Do not execute the commands; use bash -n to parse", false),
            // Ordinary work: silent.
            ("Run the tests and report failures", false),
            ("Review the diff for correctness", false),
            ("", false),
        ];
        for (prompt, want) in table {
            assert_eq!(is_uncontained_execution(prompt), *want, "{prompt}");
        }
    }

    #[test]
    fn oracle_message_never_echoes_the_prompt() {
        let prompt = "Run each command: rm -rf ~ SECRET-MARKER";
        let notes = assess(Some("fork"), None, Some(prompt)).join(" ");
        assert!(notes.contains("HOME"), "{notes}");
        assert!(!notes.contains("SECRET-MARKER") && !notes.contains("rm -rf ~ S"));
    }

    #[test]
    fn all_arms_combine_in_one_nudge() {
        let notes = assess(Some("general-purpose"), None, Some("run the corpus"));
        assert_eq!(notes.len(), 2);
    }

    fn agent(json_tool_input: &str, tool: &str) -> HookInput {
        HookInput::from_json(&format!(
            r#"{{"tool_name":"{tool}","tool_input":{json_tool_input}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn run_is_advisory_and_tool_scoped() {
        let check = WarnAgentDispatch;
        let table: &[(&str, &str, Outcome)] = &[
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","prompt":"x"}"#,
                Outcome::Nudge,
            ),
            (
                "Task",
                r#"{"subagent_type":"general-purpose","prompt":"x"}"#,
                Outcome::Nudge,
            ),
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","model":"haiku","prompt":"x"}"#,
                Outcome::Allow,
            ),
            (
                "Agent",
                r#"{"subagent_type":"fork","model":"opus"}"#,
                Outcome::Nudge,
            ),
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","model":"haiku","prompt":"run the corpus"}"#,
                Outcome::Nudge,
            ),
        ];
        for (tool, ti, want) in table {
            assert_eq!(check.run(&agent(ti, tool)).outcome, *want, "{tool} {ti}");
        }
        assert_eq!(check.run(&make_bash("ls")).outcome, Outcome::Allow);
    }

    #[test]
    fn denies_send_message_reads_every_tools_spelling() {
        let def =
            |frontmatter: &str| format!("---\nname: a\n{frontmatter}\n---\nbody tools: Read\n");
        for (frontmatter, want) in [
            ("tools: Read, Grep", true),
            ("tools: Read, Grep, SendMessage", false),
            ("tools: [Read, \"SendMessage\"]", false),
            ("tools: [Read, Grep]", true),
            ("tools: \"Read, SendMessage\"", false),
            ("tools: Read, Grep # SendMessage later", true),
            ("tools:\n  - Read\n  - SendMessage", false),
            ("tools:\n  - Read\n  - Grep", true),
            ("tools: SendMessageX, Read", true),
            ("tools: '*'", false),
            // Absent or empty: the agent inherits every tool.
            ("model: haiku", false),
            ("tools:", false),
            ("tools: \"\"", false),
            // Denied outright, whatever `tools:` grants.
            ("disallowedTools: SendMessage", true),
            (
                "tools: Read, SendMessage\ndisallowedTools: [SendMessage]",
                true,
            ),
            ("disallowedTools: Write", false),
        ] {
            assert_eq!(
                denies_send_message(&def(frontmatter)),
                want,
                "{frontmatter:?}"
            );
        }
        assert!(!denies_send_message("no frontmatter\ntools: Read\n"));
    }

    /// A scratch layout with project, user and plugin-cache roots.
    struct Roots {
        _dir: tempfile::TempDir,
        roots: AgentRoots,
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn scratch_roots() -> Roots {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let project = root.join("repo/.claude/agents");
        let user = root.join("home/agents");
        let cache = root.join("home/plugins/cache");
        write(
            &project.join("dark.md"),
            "---\nname: dark\ntools: Read, Grep\n---\n",
        );
        write(
            &project.join("lit.md"),
            "---\nname: lit\ntools: Read, SendMessage\n---\n",
        );
        // Named by frontmatter, not by file name.
        write(
            &project.join("renamed-file.md"),
            "---\nname: renamed\ntools: Read\n---\n",
        );
        write(
            &project.join("inherits.md"),
            "---\nname: inherits\nmodel: haiku\n---\n",
        );
        // Project overrides user.
        write(&user.join("lit.md"), "---\nname: lit\ntools: Read\n---\n");
        write(
            &user.join("user-dark.md"),
            "---\nname: user-dark\ntools: Read\n---\n",
        );
        let old = cache.join("mkt/plug/0000old/agents/rev.md");
        let new = cache.join("mkt/plug/1111new/agents/rev.md");
        write(&old, "---\nname: rev\ntools: Read, SendMessage\n---\n");
        std::thread::sleep(std::time::Duration::from_millis(20));
        write(&new, "---\nname: rev\ntools: Read\n---\n");
        write(
            &cache.join("mkt/plug/1111new/agents/ok.md"),
            "---\nname: ok\ntools: SendMessage\n---\n",
        );
        Roots {
            roots: AgentRoots {
                project: vec![project],
                user,
                plugin_cache: cache,
            },
            _dir: dir,
        }
    }

    #[test]
    fn dark_teammate_arm() {
        let scratch = scratch_roots();
        // (tool_input, dark)
        for (tool_input, want) in [
            (
                r#"{"subagent_type":"dark","name":"w1","model":"haiku"}"#,
                true,
            ),
            (
                r#"{"subagent_type":"dark","team_name":"t","model":"haiku"}"#,
                true,
            ),
            (r#"{"subagent_type":"renamed","name":"w1"}"#, true),
            (r#"{"subagent_type":"user-dark","name":"w1"}"#, true),
            (r#"{"subagent_type":"plug:rev","name":"w1"}"#, true),
            // The project's `lit` grants it, though the user's does not.
            (r#"{"subagent_type":"lit","name":"w1"}"#, false),
            (r#"{"subagent_type":"plug:ok","name":"w1"}"#, false),
            (r#"{"subagent_type":"inherits","name":"w1"}"#, false),
            // Not found, or no definition to read: silent.
            (r#"{"subagent_type":"missing","name":"w1"}"#, false),
            (r#"{"subagent_type":"other:rev","name":"w1"}"#, false),
            (r#"{"subagent_type":"general-purpose","name":"w1"}"#, false),
            (r#"{"subagent_type":"fork","name":"w1"}"#, false),
            (r#"{"name":"w1"}"#, false),
            (r#"{"subagent_type":"../dark","name":"w1"}"#, false),
            // Not a teammate spawn.
            (r#"{"subagent_type":"dark"}"#, false),
            (r#"{"subagent_type":"dark","name":"  "}"#, false),
            (r#"{"subagent_type":"dark","name":7}"#, false),
        ] {
            let input = agent(tool_input, "Agent");
            assert_eq!(dark_teammate(&input, &scratch.roots), want, "{tool_input}");
        }
    }

    #[test]
    fn dark_teammate_nudges_from_the_payload_cwd_and_never_echoes() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join(".claude/agents/gambit-dark-fixture.md"),
            "---\nname: gambit-dark-fixture\ntools: Read\n---\n",
        );
        let cwd = dir.path().join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        let input = HookInput::from_json(
            &serde_json::json!({
                "tool_name": "Agent",
                "cwd": cwd,
                "tool_input": {
                    "subagent_type": "gambit-dark-fixture",
                    "name": "NAME-MARKER",
                    "model": "haiku",
                    "prompt": "x"
                }
            })
            .to_string(),
        )
        .unwrap();
        let result = WarnAgentDispatch.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge, "{:?}", result.message);
        let message = result.message.unwrap_or_default();
        assert!(message.contains("SendMessage"), "{message}");
        assert!(!message.contains("NAME-MARKER") && !message.contains("gambit-dark-fixture"));
    }
}
