---
license: Apache-2.0 WITH Commons-Clause
---

# Guard Anatomy Reference

## Contents

- [Check trait](#check-trait)
- [HookInput](#hookinput)
- [CheckResult](#checkresult)
- [Outcome](#outcome)
- [run_check / run_check_from_stdin](#run_check--run_check_from_stdin)
- [Exit code contract](#exit-code-contract)
- [Bypass mechanism](#bypass-mechanism)
- [Panic handling](#panic-handling)
- [Clap error handling](#clap-error-handling)

Complete API reference for the core types that every guard uses.

## Check trait

```rust
/// A hook check that can be run against input.
pub trait Check {
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str;

    /// Run the check against the given input.
    fn run(&self, input: &HookInput) -> CheckResult;
}
```

Guards are stateless — `run()` takes `&self` (no mutation). All state comes from the `HookInput` and environment variables.

## HookInput

The JSON structure Claude Code sends on stdin:

```rust
pub struct HookInput {
    pub tool_name: Option<String>,   // "Bash", "Write", "Edit", "Read", "Grep", etc.
    pub tool_input: Option<ToolInput>,
    pub cwd: Option<String>,         // Working directory of the Claude Code session
}

pub struct ToolInput {
    pub file_path: Option<String>,   // Write, Edit, Read target
    pub path: Option<String>,        // Glob, Grep target (fallback for file_path)
    pub command: Option<String>,     // Bash command string
    pub content: Option<String>,     // Write content
    pub new_string: Option<String>,  // Edit replacement text
    pub old_string: Option<String>,  // Edit original text
}
```

### Accessor methods

Use these instead of reaching into `tool_input` directly:

| Method | Returns | Fallback logic |
|---|---|---|
| `input.tool_name()` | `Option<&str>` | Direct field access |
| `input.file_path()` | `Option<String>` | `file_path` first, then `path`. Normalizes the result. |
| `input.command()` | `Option<&str>` | `tool_input.command` |
| `input.content()` | `Option<&str>` | `content` first, then `new_string` |

**Path normalization** — `file_path()` automatically:
- Replaces backslashes with forward slashes (Windows compatibility)
- Strips null bytes (C string truncation attack prevention)
- Trims trailing slashes and whitespace

## CheckResult

```rust
pub struct CheckResult {
    pub outcome: Outcome,
    pub message: Option<String>,
}

impl CheckResult {
    pub fn allow() -> Self;                        // Outcome::Allow, no message
    pub fn nudge(message: impl Into<String>) -> Self;  // Outcome::Nudge + message
    pub fn block(message: impl Into<String>) -> Self;  // Outcome::Block + message
}
```

## Outcome

```rust
pub enum Outcome {
    Allow,  // exit 0, silent
    Nudge,  // exit 0, JSON additionalContext to stdout
    Block,  // exit 2, message to stderr
}
```

### Merging outcomes

`Outcome::merge()` keeps the more severe result:

```
Block + anything = Block
Nudge + Allow    = Nudge
Allow + Allow    = Allow
```

Use this when a guard checks multiple conditions and wants to report the worst one.

## run_check / run_check_from_stdin

Two entry points — guards don't call these directly (main.rs does), but understanding the flow helps debug output issues.

```rust
/// Run a single check, emit output, and exit.
pub fn run_check(check: &dyn Check, input: &HookInput) -> ! {
    let result = check.run(input);
    match result.outcome {
        Outcome::Nudge => {
            // JSON to stdout — Claude sees this as additionalContext
            println!(r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","additionalContext":"{msg}"}}}}"#);
        }
        Outcome::Block => {
            // Plain text to stderr — Claude sees this as an error
            eprint!("{msg}");
        }
        Outcome::Allow => {} // Silent
    }
    process::exit(result.outcome.code());
}

/// Convenience: read stdin, parse, run check. Fail open on parse errors.
pub fn run_check_from_stdin(check: &dyn Check) -> ! {
    match HookInput::from_stdin() {
        Ok(input) => run_check(check, &input),
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            process::exit(0); // Fail open
        }
    }
}
```

**Key detail:** `run_check_from_stdin` exits 0 on parse errors. This is the fail-open principle — if the hook can't understand the input, it must not block the user's operation.

## Exit code contract

| Code | Meaning | When |
|---|---|---|
| 0 | Allow (or nudge) | Operation proceeds. Stdout shown only in verbose mode UNLESS it's JSON `hookSpecificOutput`. |
| 1 | Non-blocking error | stderr visible only in verbose mode. Used for panics, unknown subcommands. |
| 2 | Block | Operation prevented. stderr fed back to Claude as error context. |

**Any other code** behaves like exit 1 (non-blocking, invisible).

**Exit 2 = stderr only. Never emit a JSON envelope on stdout while exiting 2.** On a block, Claude Code discards stdout entirely and feeds back *only* stderr — so a `println!`ed JSON envelope there delivers nothing, and a wrong-shaped one (e.g. an object where the schema wants a string) still registers as an output-schema validation failure in telemetry. To hand Claude a structured hint on a block, fold it into the **stderr** text (e.g. a `Fix:` line). Reserve JSON-on-stdout for exit-0 nudges — and there, every `hookSpecificOutput` field must match the schema type: `additionalContext` is a **string**, never a struct/object.

## Bypass mechanism

The binary checks `CADENCE_HOOKS_BYPASS=1` before parsing subcommands:

```rust
if std::env::var("CADENCE_HOOKS_BYPASS").as_deref() == Ok("1") {
    eprintln!("cadence-hooks: all enforcement bypassed (CADENCE_HOOKS_BYPASS=1)");
    process::exit(0);
}
```

Use this when editing hook source code that would trigger its own guards (e.g., terminology guard blocks writes containing prohibited terms as detection patterns).

## Panic handling

The binary installs a panic hook that converts panics to exit 1 (non-blocking) instead of the default exit 101:

```rust
std::panic::set_hook(Box::new(|info| {
    eprintln!("cadence-hooks: internal error (panic). This hook will not block your operation.");
    process::exit(1);
}));
```

This is defense-in-depth — guards should still handle errors gracefully rather than relying on the panic hook.

## Clap error handling

Unknown subcommands (plugin expects newer binary) exit 1 with an update hint, not exit 2. This prevents version mismatches from blocking operations (ADR-0009).
