# ADR-0001: Route Nudge Output Through stdout JSON Instead of stderr Exit-1

**Status:** Accepted
**Date:** 2026-04-05

## Context

The cadence-hooks binary originally had three outcome types: Allow (exit 0), Warn (exit 1, stderr), and Block (exit 2, stderr). The Warn outcome was designed for advisory messages -- things like "you're on the main branch" or "confirm the current date before scheduling a cron job."

However, Claude Code's hook protocol treats exit code 1 as a "non-blocking error" which is:

- Shown to the user in the UI as "hook error"
- But completely invisible to the model -- `hook_non_blocking_error` is normalized to an empty array in `messages.ts` before being sent to the API

This created a three-way mismatch:

1. **cadence-hooks** assumed exit 1 meant "advisory, show message"
2. **Claude Code UI** showed "hook error" (alarming to the user)
3. **Claude Code model** saw nothing (the message was stripped)

The result: users saw hook errors they couldn't explain, asked Claude about them, and Claude genuinely couldn't see any errors in its conversation context. This led to frustrating loops where Claude appeared to be dismissing or gaslighting the user about visible errors.

## Decision

Rename `Outcome::Warn` to `Outcome::Nudge`. Change the output channel:

- **Before:** Exit code 1, message on stderr
- **After:** Exit code 0, message on stdout as JSON with `hookSpecificOutput.additionalContext`

This routes through Claude Code's `hook_additional_context` normalization path, which IS sent to the model as a system reminder. The hook's advisory message now reaches both the user AND the model.

## Consequences

### Positive

- Nudge messages are visible to Claude, enabling it to act on advisory context (e.g., auto-injecting current date/time for cron scheduling)
- No more phantom "hook error" messages in the UI
- The three-way mismatch between hook, UI, and model is resolved
- Hook authors have a clear pattern: exit 0 + JSON for advisory, exit 2 + stderr for blocking

### Negative

- Breaking change for any downstream code that checked for exit code 1 from cadence-hooks (none known)
- JSON output format is more complex than plain text stderr
- Exit code 0 means the hook "succeeded" even when it's delivering a warning -- semantically less clear, but aligns with Claude Code's actual contract

## Alternatives Considered

1. **Keep exit 1, write to stdout instead of stderr** -- wouldn't work. Claude Code ignores stdout on non-zero exit codes.
2. **Use exit 2 for nudges** -- would block the tool execution entirely, which is wrong for advisory messages.
3. **Lobby Anthropic to change the protocol** -- exit 1 being invisible to the model appears intentional (avoiding noise), and the JSON additionalContext path exists as the designed solution.

## Related

- Claude Code source: `src/utils/hooks.ts:2670-2696` (non-blocking error handling)
- Claude Code source: `src/utils/messages.ts:4252-4261` (non-blocking error stripped from API)
- Claude Code source: `src/utils/messages.ts:4117-4127` (additionalContext IS sent to API)
- Commit: 68469a6 (the implementation)
