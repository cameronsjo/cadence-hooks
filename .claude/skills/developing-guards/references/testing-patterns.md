---
license: Apache-2.0 WITH Commons-Clause
---

# Testing Patterns Reference

## Contents

- [Test scaffolding](#test-scaffolding)
- [Test category checklist](#test-category-checklist)
- [Environment variable testing](#environment-variable-testing)
- [Integration test: hook registration audit](#integration-test-hook-registration-audit)

Test scaffolding, edge case categories, and evasion scenario design for cadence-hooks guards.

## Test scaffolding

### make_bash() — Bash command input

```rust
fn make_bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            file_path: None,
            path: None,
            command: Some(cmd.into()),
            content: None,
            new_string: None,
            old_string: None,
        }),
        cwd: None,
    }
}
```

### make_write() — Write tool input

```rust
fn make_write(path: &str, content: &str) -> HookInput {
    HookInput {
        tool_name: Some("Write".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            path: None,
            command: None,
            content: Some(content.into()),
            new_string: None,
            old_string: None,
        }),
        cwd: None,
    }
}
```

### make_edit() — Edit tool input

```rust
fn make_edit(path: &str, old: &str, new: &str) -> HookInput {
    HookInput {
        tool_name: Some("Edit".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            path: None,
            command: None,
            content: None,
            new_string: Some(new.into()),
            old_string: Some(old.into()),
        }),
        cwd: None,
    }
}
```

### make_read() — Read tool input

```rust
fn make_read(path: &str) -> HookInput {
    HookInput {
        tool_name: Some("Read".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            path: None,
            command: None,
            content: None,
            new_string: None,
            old_string: None,
        }),
        cwd: None,
    }
}
```

### make_input() — Full control (used in core tests)

```rust
fn make_input(
    tool_name: Option<&str>,
    file_path: Option<&str>,
    path: Option<&str>,
    command: Option<&str>,
    content: Option<&str>,
    new_string: Option<&str>,
) -> HookInput {
    HookInput {
        tool_name: tool_name.map(String::from),
        tool_input: Some(ToolInput {
            file_path: file_path.map(String::from),
            path: path.map(String::from),
            command: command.map(String::from),
            content: content.map(String::from),
            new_string: new_string.map(String::from),
            old_string: None,
        }),
        cwd: None,
    }
}
```

> **Note:** `make_bash()` is duplicated across 5+ modules (cameronsjo/cadence-hooks#11). Copy the helper into your test module until the shared builder is extracted.

## Test category checklist

### 1. Guard clause tests

Verify the guard exits early for non-matching inputs. These prevent over-matching.

```rust
#[test]
fn non_push_command_allowed() {
    let result = PushRemoteGuard.run(&make_bash("git status"));
    assert_eq!(result.outcome, Outcome::Allow);
}

#[test]
fn no_command_allowed() {
    let input = HookInput {
        tool_name: Some("Bash".into()),
        tool_input: None,
        cwd: None,
    };
    let result = PushRemoteGuard.run(&input);
    assert_eq!(result.outcome, Outcome::Allow);
}

#[test]
fn wrong_tool_allowed() {
    let result = SecretLeaksGuard.run(&make_bash("cat .env"));
    // This guard checks Read/Grep, not Bash... wait, it checks Bash too.
    // Know your guard's tool scope before writing guard clause tests.
}
```

**Checklist:**
- [ ] Wrong tool name returns `allow()`
- [ ] Missing `tool_input` returns `allow()`
- [ ] Non-matching command/content returns `allow()`
- [ ] Allowed paths (safe templates, allowed owners) return `allow()`

### 2. Happy path tests

Each violation the guard detects gets at least one positive test.

```rust
#[test]
fn main_branch_warns() {
    let result = should_warn("main", false);
    assert_eq!(result.outcome, Outcome::Nudge);
    assert!(result.message.as_deref().unwrap().contains("main"));
}

#[test]
fn chained_pushes_different_remotes_blocked() {
    let result = PushRemoteGuard.run(
        &make_bash("git push origin main && git push upstream main")
    );
    assert_eq!(result.outcome, Outcome::Block);
    assert!(result.message.unwrap().contains("different remotes"));
}
```

**Checklist:**
- [ ] Each block condition has a test with `assert_eq!(outcome, Outcome::Block)`
- [ ] Each nudge condition has a test with `assert_eq!(outcome, Outcome::Nudge)`
- [ ] Block/nudge messages contain expected keywords (verify with `.contains()`)

### 3. Edge case tests

Test structural analysis robustness against real-world shell patterns.

```rust
// Quote variants
#[test]
fn multi_push_false_positive_in_quotes() {
    let result = PushRemoteGuard.run(
        &make_bash("echo 'do not git push this' && git push origin main")
    );
    let msg = result.message.as_deref().unwrap_or("");
    assert!(!msg.contains("multiple"), "false positive: quoted text counted");
}

// Chained commands
#[test]
fn semicolon_no_space() {
    assert_eq!(parse_work_dir("cd /project;git push", "/home"), "/project");
}

// Pipe chains
#[test]
fn push_with_pipe_counted_once() {
    let result = PushRemoteGuard.run(
        &make_bash("git push origin main 2>&1 | tee push.log")
    );
    let msg = result.message.as_deref().unwrap_or("");
    assert!(!msg.contains("multiple"));
}

// Subshells
#[test]
fn subshell_inside_loop() {
    let result = analyze_gh_loops("for i in 1 2; do (gh pr create); done"); // redaction-lint: allow — Rust fixture
    assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
}
```

**Checklist:**
- [ ] Single quotes, double quotes, unmatched quotes
- [ ] `&&`, `;`, `||` chain operators
- [ ] Pipes (`|`), redirects (`>`, `2>&1`)
- [ ] Subshells `()`, brace groups `{}`
- [ ] Nested structures (loops in loops, if in loops)

### 4. Evasion tests

Document what the guard can and can't catch. These tests set expectations.

```rust
// Variable expansion — guard CAN'T resolve this
#[test]
fn chain_variable_as_remote_treated_as_missing() {
    let result = analyze_push_chain("git push $REMOTE main && git push origin main");
    // $REMOTE is not resolvable at hook time — this is a known limitation
    assert!(!matches!(result, ChainAnalysis::SameRemote(_)));
}

// Command substitution — guard CAN'T resolve this
#[test]
fn chain_command_substitution_in_remote() {
    let result = analyze_push_chain(
        "git push origin main && git push $(echo upstream) main"
    );
    assert!(!matches!(result, ChainAnalysis::SameRemote(ref r) if r == "origin"));
}

// Quoted command names — guard correctly ignores
#[test]
fn chain_quoted_git_push_not_counted() {
    let result = analyze_push_chain(r#"echo "running git push" && git push origin main"#);
    assert!(matches!(result, ChainAnalysis::SingleOrNone));
}
```

**Accepted limitations to document:**
- Shell variable expansion (`$CMD`, `$REMOTE`) — values unknown at hook time
- Command substitution (`$(cmd)`, `` `cmd` ``) — requires execution to resolve
- Aliases and functions — the guard sees the raw command, not resolved aliases
- Encoded content (base64, hex) — would require execution to decode

### 5. Emitted-output-shape tests

Assert what each exit code writes to **stdout vs stderr** — the shape, not just the `Outcome`. A guard can return the right `Outcome` yet emit a schema-invalid envelope on the wrong stream, which passes every `assert_eq!(outcome, ...)` test while failing output-schema validation in production: a guard that blocks correctly (exit 2, stderr) but *also* `println!`s an object-valued `additionalContext` on the ignored stdout is the shape to catch.

Because `run_check` `process::exit`s, it can't be asserted directly — test the **pure render function** it delegates to (`render_output` in `crates/core/src/lib.rs`; see its `render_*` tests as the reference implementation):

```rust
// A block emits NOTHING on stdout — the key anti-regression assertion.
// (Real test: `render_block_emits_no_stdout`; `sample_metadata()` is the
// module's BlockMetadata builder.)
#[test]
fn render_block_emits_no_stdout() {
    let rendered = render_output(
        Outcome::Block, Some("🚫 blocked"), Some(&sample_metadata()),
        HookEvent::PreToolUse, None,
    );
    assert_eq!(rendered.stdout, None, "exit-2 block must not write stdout");
    assert!(rendered.stderr.expect("stderr").contains("blocked"));
}

// An exit-0 nudge's additionalContext is a STRING, never an object.
// (Real test: `render_nudge_stdout_additional_context_is_string`.)
#[test]
fn render_nudge_stdout_additional_context_is_string() {
    let rendered = render_output(
        Outcome::Nudge, Some("heads up"), None, HookEvent::PreToolUse, None,
    );
    let json: serde_json::Value =
        serde_json::from_str(&rendered.stdout.unwrap()).unwrap();
    assert!(json["hookSpecificOutput"]["additionalContext"].is_string());
}
```

**Assert for every output-producing guard:**

- Block ⇒ `stdout == None`; stderr carries the reason (and any folded `Fix:` hint)
- Exit-0 JSON ⇒ parses as JSON; `additionalContext` (and every field) is schema-typed — `additionalContext.is_string()`

## Environment variable testing

Guards that read env vars (via `config::env_allow_entries()`) need careful test isolation. **Do NOT use `std::env::set_var()` in parallel tests** — it's a global mutation that causes data races.

### Pattern: test the pure function, not the env reader

```rust
// GOOD: test check_owner() directly with constructed entries
#[test]
fn owner_check_passes() {
    let owners = vec![parse_allow_entry("cameronsjo")];
    assert!(check_owner("https://github.com/cameronsjo/repo.git", &owners, &[]));
}

// GOOD: test the guard's run() for scenarios that DON'T need env vars
#[test]
fn loop_missing_targets_blocked() {
    // Loops block BEFORE the env var check
    let result = PushRemoteGuard.run(&make_bash("for b in a b; do git push; done"));
    assert_eq!(result.outcome, Outcome::Block);
}

// AVOID: setting env vars in tests
#[test]
fn avoid_this_pattern() {
    std::env::set_var("GIT_GUARDRAILS_ALLOWED_OWNERS", "cameronsjo"); // DATA RACE
    let result = PushRemoteGuard.run(&make_bash("git push origin main"));
    // ...
}
```

### Pattern: extract pure decision functions

The `warn_main_branch` guard demonstrates this well — the `should_warn(branch, already_warned)` function is pure and testable without touching the filesystem or env:

```rust
fn should_warn(branch: &str, already_warned: bool) -> CheckResult {
    if !is_default_branch(branch) { return CheckResult::allow(); }
    if already_warned { return CheckResult::allow(); }
    CheckResult::nudge(format!("You're on '{branch}'..."))
}

// Tests hit the pure function directly:
#[test]
fn main_branch_warns() {
    let result = should_warn("main", false);
    assert_eq!(result.outcome, Outcome::Nudge);
}
```

## Integration test: hook registration audit

`tests/hook_registration_audit.rs` runs 6 cross-cutting tests that catch registration drift:

| Test | Catches |
|---|---|
| `all_registered_hooks_exist_in_binary` | hooks.json referencing nonexistent subcommands |
| `all_binary_subcommands_are_registered` | Subcommands built but never wired to hooks.json |
| `no_cross_plugin_hooks` | Plugin X dispatching plugin Y's subcommand |
| `bash_hooks_have_if_filter` | Bash-matcher hooks without pre-spawn filtering |
| `no_plugin_hooks_duplicated_in_settings_json` | User settings duplicating plugin hooks |
| `settings_json_shell_scripts_exist` | settings.json pointing to deleted scripts |

Run after adding any new guard: `cargo test --test hook_registration_audit`
