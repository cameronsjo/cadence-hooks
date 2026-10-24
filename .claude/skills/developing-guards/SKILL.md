---
name: developing-guards
description: Use when writing, testing, or improving Rust guardrail checks in cadence-hooks, or negative-testing any guard or lint by mutating its input until every detector goes red. Triggers on 'write a guard', 'add hook check', 'develop guardrail', 'cadence-hooks check', 'guard testing', 'can this check go red'.
license: Apache-2.0 WITH Commons-Clause
metadata:
  author: cameronsjo
  version: "1.0"
---

# Developing Guards

Guards are **stateless pure functions**: they read JSON from stdin describing a tool invocation, decide whether to allow/nudge/block, and exit. Every guard implements the `Check` trait from `cadence_hooks_core`.

## The binary

`cadence-hooks` dispatches to guards via `clap` subcommands in four namespaces: `cadence` (`crates/cadence/`, plugin-specific checks: terminology, secrets, memory), `guardrails` (`crates/guardrails/`, git/GitHub safety), `rules` (`crates/rules/`, code standards), and `obsidian` (`crates/obsidian/`, vault guards). Shared infrastructure lives in `crates/core/` — the `Check` trait, `HookInput` parsing, output protocol, shell parsing, loop analysis, and config utilities.

## Guard anatomy

Every guard follows a 4-phase pipeline:

```text
stdin JSON ──► Early exit ──► Structural analysis ──► Config checks ──► Result
               (tool match)    (parse, inspect)       (allowlists)     (block/nudge/allow)
```

**Phase 1 — Early exit.** Return `CheckResult::allow()` immediately if the tool or content doesn't match this guard's scope. Check `input.tool_name()`, `input.command()`, or `input.file_path()` and bail early. This is the most common exit path — keep it fast.

**Phase 2 — Structural analysis.** Parse the command or content to understand what's happening. Use `shell::strip_quotes()` to expose command structure, `loop_analysis::analyze_gh_loops()` or `analyze_push_loops()` for loop safety, and regex patterns for content matching. When the AST parser fails (`ParseFailed`), **fall back to regex** — never block on parse failure alone.

**Phase 3 — Config checks.** For guards that use allowlists (push-remote, gh-write), read env vars via `config::env_allow_entries()` and check with `config::is_allowed()`. Guards without config (terminology, secrets) skip this phase.

**Phase 4 — Result construction.** Return `CheckResult::block(msg)`, `CheckResult::nudge(msg)`, or `CheckResult::allow()`.

### Decision table

| Condition | Result | Exit code | Output |
|---|---|---|---|
| Not this guard's tool/content | `allow()` | 0 | Silent |
| Violation of a policy with no legitimate exceptions | `block(msg)` | 2 | **stderr only** (Claude sees it) — never JSON on stdout |
| Concern the user may legitimately ignore | `nudge(msg)` | 0 | JSON `additionalContext` (a **string**) to stdout |
| Parse failed | `allow()` | 0 | Silent — fail open per ADR-0001 |
| Config allows it | `allow()` | 0 | Silent |

> **Fail-open principle (ADR-0001):** A bug in a guard must never block the user's operation. Parse failures, panics, and unknown subcommands all exit 0 or 1, never 2.
>
> **Exit 2 emits nothing on stdout.** A block feeds Claude *only* stderr; stdout (including any JSON) is discarded. So never `println!` a JSON envelope on the block path — it delivers nothing, and a schema-invalid one (e.g. an object-valued `additionalContext` where the schema wants a string) still counts as an output-schema validation failure in telemetry. Deliver a block's structured hint via **stderr** (fold it into the message, e.g. a `Fix:` line); reserve JSON-on-stdout for exit-0 nudges. Every `hookSpecificOutput` field must match the schema type — `additionalContext` is a **string**, never a struct/object.

### Choosing block vs nudge

**Block vs nudge is a policy question, not a detection question.** Before reaching for `block()`, ask: *can you name a routine, intentional workflow that violates this?*

- **Yes → nudge**, no matter how cleanly detectable the condition is (PR without an issue link, editing on main, commit without a ticket ref)
- **No, violations are never legitimate → block**, fail open (pushing to someone else's repo, leaking secrets, `gh repo delete`)

Detection certainty ≠ policy certainty: a check can detect its condition perfectly and still be the wrong severity. A PR without a linked issue is a routine workflow, so that check is `warn-pr-issue-link`, a nudge. Porting an existing blocking check or enforcing a CLAUDE.md "MUST" rule does not exempt the check from this question.

**The friction budget: a fail-open guard spends it on false-*allows*, not false-*blocks*.** Fail-open (ADR-0001) resolves *uncertainty* toward allow; this is its policy companion — when the block-vs-allow line is genuinely in question, lean allow. The two errors aren't symmetric: a false block is friction on legitimate work (anti-cadence — the exact cost the methodology exists to remove), while a false allow is a missed nudge, cheap and backstopped elsewhere (a discipline guard is not a security boundary). So *hardening* a guard against evasions is nearly free — no real workflow types `(git commit)` to sneak past — but *broadening* a block spends the budget every time it misfires. Scope each block to its load-bearing core, give it a returnable escape, and at the margin, allow.

Naming follows severity: `guard-*` blocks, `warn-*` nudges.

See [references/guard-anatomy.md](${CLAUDE_SKILL_DIR}/references/guard-anatomy.md) for the full `Check` trait, `CheckResult`, `HookInput`, and `run_check` API.

## Block message standard

Block messages go to stderr and Claude reads them as error context. Use the **Found/Fix/Allowed** format:

```text
BLOCKED: <guard-name>
Found: <what was detected — include specifics from AST/content analysis>
Fix: <actionable instruction the user or Claude can follow>
Allowed: <if config-driven, show what IS allowed>
```

### When to include each line

- **Found** — Include when you have concrete data from analysis (the matched term, the parsed URL, the detected remote). Omit only when the block reason is self-evident from context (e.g., "command would read .env file").
- **Fix** — Always include. Must be actionable: a command to run, a pattern to use, a config to set. Never "contact an administrator."
- **Allowed** — Include when the guard checks against a config-driven allowlist. Show what IS allowed so Claude can self-correct. Omit for guards without configurable allowlists (terminology, secrets).

### Real examples from the codebase

**Config-driven guard (push-remote):**

```text
BLOCKED: git-guardrails: Push target is not yours
   Would push to: https://github.com/other/repo.git
   Directory:     /home/user/project
   Allowed:       cameronsjo gitea.internal/cameron

   Fix tracking:  git branch -u origin/main
   Push explicit: git push origin main
```

**Content-scanning guard (terminology):**

```text
BLOCKED: Inclusive terminology violation
Found: "whitelist" (line contains prohibited term)
Fix: Use "allowlist" instead
```

**Nudge (JSON additionalContext, not stderr):**

```text
You're editing files directly on 'main'. Ask the user: should this work be on a feature branch instead?
```

Nudges emit JSON to stdout via `run_check()` — you return `CheckResult::nudge(msg)` and the protocol handles formatting:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"<your message>"}}
```

> **Do NOT emit bare text to stdout.** Per Claude Code's hook contract, stdout on exit 0 is only visible in verbose mode. The JSON `additionalContext` path is the only way to inject nudge context that Claude actually sees.

## Core utilities

Key modules in `crates/core/src/`. See [references/core-utilities.md](${CLAUDE_SKILL_DIR}/references/core-utilities.md) for full API.

| Module | Key exports | Use when |
|---|---|---|
| `shell` | `strip_quotes()`, `parse_work_dir()`, `git_command()`, `host_and_repo_from_url()`, `LOOP_PATTERN` | Parsing Bash commands, resolving git context |
| `loop_analysis` | `analyze_gh_loops()`, `analyze_push_loops()`, `analyze_push_chain()` | Detecting dangerous patterns in loops and chains |
| `config` | `AllowEntry`, `env_allow_entries()`, `is_allowed()`, `parse_env_list()` | Reading and matching owner/repo allowlists |

### Common patterns

**Strip quotes before substring matching** — `strip_quotes("echo 'git push' && git push origin main")` removes the quoted `git push` so you don't false-positive on it.

**Resolve working directory from `cd` chains** — `parse_work_dir("cd /project && git push", cwd)` returns `/project`. Pass the result to `git_command()` for git operations in the correct repo.

**Four-format allowlist entries** — `AllowEntry` handles bare owner (`cameronsjo`), host/owner (`gitea.internal/cameron`), owner/repo (`cameronsjo/cadence`), and host/owner/repo (`gitea.internal/cameron/cadence`). The dot-in-first-segment heuristic disambiguates host/owner from owner/repo.

## Writing tests

Every guard has inline `#[cfg(test)]` tests built on a `make_bash()` / `HookInput` helper; the helper and the test scaffolding are [references/testing-patterns.md](${CLAUDE_SKILL_DIR}/references/testing-patterns.md).

### Test categories

Write tests in these four categories:

1. **Guard clause** — Wrong tool name, non-matching command, allowed path. These MUST return `allow()`. Verifies the early-exit phase doesn't over-match.

2. **Happy path** — Known violations that should block or nudge. Test each violation variant with a minimal reproducing input.

3. **Edge cases** — Quote variants (`"cmd"`, `'cmd'`), chained commands (`&&`, `;`, `||`), pipes, subshells. These test structural analysis robustness.

4. **Evasion** — Variable expansion (`$CMD`), command substitution (`$(echo cmd)`), encoding tricks, path traversal. Document what the guard CAN'T catch and why that's acceptable.

A guard that has never gone red has not been tested. For any guard or lint, including repo and policy checks outside cadence-hooks, the mutate-and-demand-red loop, its harness, and its traps are [references/negative-testing.md](${CLAUDE_SKILL_DIR}/references/negative-testing.md).

## Registration

Adding a new guard takes four changes and one verification run:

### 1. Implement the Check trait

Create a new file in the appropriate crate (`crates/guardrails/src/new_guard.rs`) with a unit struct implementing `Check` (`name()` and `run()`, the four phases above); the trait and `CheckResult` constructors are [references/guard-anatomy.md](${CLAUDE_SKILL_DIR}/references/guard-anatomy.md).

### 2. Register the module

Add `pub mod new_guard;` to the crate's `lib.rs`.

### 3. Add the clap subcommand

In `src/main.rs`, add a doc-commented variant to the namespace's enum and a match arm that calls `run_check_from_stdin(&crate_name::new_guard::NewGuard)`.

### 4. Wire into hooks.json

Add an entry in the consuming plugin's `hooks.json` with a proper `if` filter:

```json
{
  "type": "command",
  "event": "PreToolUse",
  "command": "cadence-hooks guardrails new-guard",
  "if": "Bash(*git*)"
}
```

**Always add an `if` filter for Bash-matcher hooks.** Without it, the binary spawns on every Bash command — hundreds of times per session — just to exit 0 immediately. Even with `if` in place, the entry still spawns its own process on a match and stacks with sibling entries on the same matcher — glob narrowly: `cadence:writing-hooks` § The `if` Field.

### 5. Verify audit tests pass

Run `cargo test --test hook_registration_audit` to verify:
- `all_binary_subcommands_are_registered` — your new subcommand has a hooks.json entry
- `bash_hooks_have_if_filter` — your Bash-matcher hook has an `if` field

If either fails, fix the registration and rerun until both pass.

## Anti-patterns

| Anti-pattern | Why it's wrong | Fix |
|---|---|---|
| Blocking on `ParseFailed` | Violates fail-open (ADR-0001). Parse bugs block the user. | Fall back to regex detection, or `allow()` |
| Not stripping quotes | `"git push"` in an echo matches `git push` substring | Use `strip_quotes()` before substring/regex matching |
| Hardcoding hosts | Breaks for self-hosted forges (gitea, gitlab) | Use `config::default_host()` and `AllowEntry` matching |
| Missing `if` filter | Spawns process on every Bash command for nothing | Add `"if": "Bash(*keyword*)"` in hooks.json |
| Bare stdout for nudges | Invisible — stdout on exit 0 is verbose-mode only | Return `CheckResult::nudge()` — `run_check()` handles JSON |
| Duplicating patterns | Copy-pasting constants/functions across guards | Extract to a shared module (see `secret_patterns.rs` precedent) |
| Using `exit 1` for blocks | Exit 1 is a non-blocking error, visible only in verbose mode | Use `CheckResult::block()` which exits 2 with stderr |
| JSON envelope on stdout while exiting 2 | Discarded (block feeds only stderr); a wrong-shaped one still logs an output-schema validation failure | Fold the structured hint into stderr text; JSON-on-stdout only on exit 0 |
| Object-valued `additionalContext` | Schema requires a **string** (~10k cap); a struct/object fails validation | Serialize the hint to a string; keep every `hookSpecificOutput` field schema-typed |
| Panicking on unexpected input | Default panic exit code (101) is not in the hook protocol | The binary's panic hook converts to exit 1, but prefer graceful handling |

## References

- [Guard anatomy](${CLAUDE_SKILL_DIR}/references/guard-anatomy.md) — `Check` trait, `CheckResult`, `HookInput`, `Outcome`, `run_check` flow
- [Testing patterns](${CLAUDE_SKILL_DIR}/references/testing-patterns.md) — Test scaffolding, edge case categories, evasion scenario design
- [Negative testing](${CLAUDE_SKILL_DIR}/references/negative-testing.md) — mutate the input, demand red per detector: baseline first, mutate a copy, prove the mutation applied, traps
- [Core utilities](${CLAUDE_SKILL_DIR}/references/core-utilities.md) — `loop_analysis`, `shell`, `config` module API reference
