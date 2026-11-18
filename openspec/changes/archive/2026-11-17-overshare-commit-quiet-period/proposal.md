## Why

`warn-overshare` reminds on every commit, push and post. On one machine it fired more than 5,000 times in two weeks, and each firing adds text to the model's context (cameronsjo/cadence-hooks#1636). The owner decided on 2026-11-17: remind once per session on commits only, and shorten the reminder. Pushes and posts keep reminding every time.

An earlier attempt (cameronsjo/cadence-hooks#1629) keyed one marker per session, repo and agent and was pulled out: three review rounds each found an everyday command where a reminder for one repo silenced a later post to a different repo. This change silences only the one shape whose target is known exactly, and never a push or a post.

## What Changes

- `warn-overshare` reminds on the first plain `git commit` of a session and stays silent on later plain commits in the same session. A commit is plain only when the whole command is one `git commit` invocation: the text starts with `git commit`, and every later argument is a bare word, single-quoted text, or double-quoted text with no `$`, backtick, backslash or `!`. A global option before the subcommand, a `cd`, a variable prefix, a chain, a pipe, a substitution, a heredoc, a redirect or a trailing comment makes it not plain, and it reminds every time.
- Every push, every post (`gh` PR, issue, comment, review, release, `gh api` write, `gh repo create`/`edit`, `tea`), every file-edit trigger and every commit chained with a push or post reminds every time, whatever happened earlier in the session.
- The marker is keyed on the session id alone, through the shared session-marker helper. A subagent shares its parent's session id, so a plain commit by a subagent silences a later plain commit by its parent and the reverse; this was accepted. A missing or empty session id, or a marker directory that is not private, leaves the reminder in place.
- The reminder text is shorter. It keeps the `Pre-ship audit:` prefix, the word `overshare` and the `CADENCE_SKIP_OVERSHARE_AUDIT=1` switch.
- MODIFY "Overshare audit triggers" and ADD "Overshare commit quiet period".

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: one requirement modified, one added.

## Impact

- `cadence-hooks cadence warn-overshare` (PreToolUse, Bash, Write, Edit): exit 0 always. Fewer reminders on repeated plain commits; the same reminders on everything else.
- `crates/cadence/src/warn_overshare.rs`, `openspec/specs/external-content/spec.md`, `docs/hooks.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
