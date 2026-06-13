# Testing Hooks Manually

Hook subcommands expect piped stdin. Run one bare in a terminal and it prints
guidance instead of hanging:

```text
$ cadence-hooks lab persona-nudge
cadence-hooks: 'persona-nudge' is a Claude Code hook, not an interactive command.

It reads a JSON payload on stdin — Claude Code pipes this automatically on
SessionStart. Nothing was piped and stdin is a terminal, so it would wait forever.
...
```

The fastest way to see what a hook does is `try` — it generates a sample
payload for the hook's event, runs the hook against it, and reports the outcome:

```bash
$ cadence-hooks try lab persona-nudge
Hook:     lab persona-nudge — Inject the self-representation contract on session start
Event:    SessionStart
Payload:  {"cwd":"...","session_id":"test","source":"startup"}

Outcome:  NUDGE (exit 0)
Context injected (what Claude sees):

  Before other work, record a self-representation as ONE JSON object.
  This is not creative writing. Report what is actually true for you...

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
