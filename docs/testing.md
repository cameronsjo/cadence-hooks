# Testing Hooks Manually

Hook subcommands expect piped stdin. Run one bare in a terminal and it prints
guidance instead of hanging:

```text
$ cadence-hooks guardrails inject-gh-write-context
cadence-hooks: 'inject-gh-write-context' is a Claude Code hook, not an interactive command.

It reads a JSON payload on stdin — Claude Code pipes this automatically on
PreToolUse. Nothing was piped and stdin is a terminal, so it would wait forever.
...
```

The fastest way to see what a hook does is `try` — it generates a sample
payload for the hook's event, runs the hook against it, and reports the outcome:

```bash
$ cadence-hooks try guardrails inject-gh-write-context
Hook:     guardrails inject-gh-write-context — Re-inject the gh-write allowlist + `-R` rule before an untargeted gh write
Event:    PreToolUse
Payload:  {"cwd":"...","tool_input":{"command":"git status"},"tool_name":"Bash"}

Outcome:  ALLOW (exit 0)
Stdout:   (none)
Stderr:   (none)
```

The generated sample is deliberately inert for most hooks; pass a payload that
trips the check to see a nudge rendered:

```bash
$ printf '%s' '{"tool_name":"Bash","tool_input":{"command":"gh pr create -t x"}}' \
    > /tmp/gh-write.json
$ cadence-hooks try guardrails inject-gh-write-context --payload /tmp/gh-write.json
...
Outcome:  NUDGE (exit 0)
Context injected (what Claude sees):

  git-guardrails: gh writes (pr/issue/release/repo/api mutations) are
  allowlist-policed. Always pass `-R owner/repo` on writes...

Stderr:   (none)
```

`try` decodes the hook protocol: nudge envelopes render their
`additionalContext` as readable text, re-prompt envelopes show the reason,
and the outcome line distinguishes `ALLOW` / `NUDGE` / `LOOP-BLOCK` / `BLOCK`.

Use `--payload <file>` to test with a real payload instead of the generated
sample, and `--show-payload` to echo a user-supplied payload in full (the
default is a bounded preview).

To pipe a payload by hand, match the shape to the hook's event
(`cadence-hooks list` shows each hook's event):

| Event | Minimal payload |
|---|---|
| PreToolUse | `{"tool_name":"Bash","tool_input":{"command":"git status"}}` |
| PostToolUse | `{"tool_name":"Edit","tool_input":{"file_path":"src/main.rs"},"tool_response":{"stdout":"ok"}}` |
| SessionStart | `{"session_id":"test","source":"startup"}` |
| Loggers (metrics, heartbeat) | `{"session_id":"test","hook_event_name":"PostToolUse","tool_input":{"command":"git status"}}` |

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | cadence-hooks guardrails guard-push-remote
```

Writing or debugging a check? See
[CONTRIBUTING.md → Reproducing a Check by Hand](../CONTRIBUTING.md#reproducing-a-check-by-hand)
for the check-author's debugging loop and the per-tool payload shapes
(Write/Edit/MultiEdit carry their content in different fields).

## Is a block the binary or the wrapper?

A guard firing is unambiguous — the `cadence-hooks` binary decided to block
and the tool call exits **2**. A silent allow is not: it can mean the binary
ran and chose to allow, or it can mean the `run-cadence-hooks.sh` wrapper
**failed open** (the binary is missing from `PATH`, or is stale enough that
the wrapper hands it a subcommand it no longer recognizes) and no guard ran
at all.

To tell them apart, isolate the binary from the wrapper — pipe the same
payload (or use `try`, above) straight to the subcommand and read the exit
code directly, bypassing `run-cadence-hooks.sh`:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | cadence-hooks guardrails guard-push-remote; echo "exit: $?"
```

A `2` there is a real block from the binary. If it's `0` with no output, the
binary allowed it — but if guards feel inert across the board, the wrapper is
the next suspect, not the binary. A failed-open wrapper now emits a once/day
stderr notice (`cameronsjo/cadence#223`) — that notice, not a silent `exit 0`,
is the signal that guards aren't running.
