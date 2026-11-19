## Why

cameronsjo/cadence-hooks#1658: a hard block is the only strong outcome a guard has, and most block messages send the model to an escape that needs the operator at a computer ("run it manually outside Claude Code", "set this variable in a settings file"). The operator increasingly works from a phone, where neither is possible, so a reversible action he asked for stops the session until he is back at a keyboard. The owner's direction (2026-11-19): "assume a cooperative model, but ask 'are you sure'". ADR-0046 sets the threat model, accidents by a cooperative model, and has only two strengths, block and nudge.

## What Changes

- ADD a confirm tier to `hook-protocol`: a guard in it blocks the first attempt at an action with its reason plus an "Are you sure?" line, and passes the next attempt at the same action from the same session and agent within ten minutes, once. The pass writes a `bypasses.jsonl` `used` row with kind `confirmed` and mechanism `confirm-retry`. The pass is keyed by hook, `session_id`, `agent_id` and a normalized action the guard supplies, never the raw command text. A missing `session_id` or `tool_use_id`, a marker directory that is not private, or a failed marker write blocks with a line saying a retry will be blocked too, so the model is never told to retry into a wall.
- ADD the phone line to `hook-protocol`: the hard blocks whose escape needs a keyboard (`git-safety`, `prevent-secret-writes`, `prevent-secret-push`'s found block, `guard-sops-decrypt`, `guard-runbook-scrub`, `guard-gh-dangerous`'s repo delete, `guard-gh-write`'s URL-argument fix) end with one sentence: stop and tell the operator in chat what was blocked, why, and what they can approve. What they block is unchanged.
- ADD to `worktree-enforcement`: `enforce-worktree`'s primary-checkout block joins the tier, keyed by the judged repo and the file (Edit, Write) or the commit (Bash). A confirmed retry arms the same 30-minute snooze `dismiss-enforce-worktree --for 30m` writes, so one confirmation covers the edits that follow. Blocks about a command the guard could not read keep blocking.
- ADD to `secret-reads`: `guard-op-vault-scan` joins the tier, keyed by the scans it read (`op item list`, `op vault list`, and the `--vault` each names).
- ADD to `issue-guards`: `guard-held-close` joins the tier, keyed by the held entries the close would hit. The more-than-16-directories block keeps blocking.
- `guard-browser-device` does not move: its handshake opens the whole session after one block, and the tier is per action and single use, so moving it would block each new Chrome action once.
- `HookInput` gains `tool_use_id`, read leniently.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `hook-protocol`: two requirements added (confirm tier, phone line).
- `worktree-enforcement`: one requirement added.
- `secret-reads`: one requirement added.
- `issue-guards`: one requirement added.

## Impact

- New `crates/core/src/confirm.rs`; `BypassKind::Confirmed` (`"confirmed"`); `HookInput::tool_use_id`.
- `crates/guardrails/src/enforce_worktree.rs`, `dismiss_enforce_worktree.rs` (one shared snooze writer), `guard_op_vault_scan.rs`, `crates/cadence/src/guard_held_close.rs`.
- Message text only: `git_safety.rs`, `prevent_secret_writes.rs`, `prevent_secret_push.rs`, `guard_sops_decrypt.rs`, `guard_runbook_scrub.rs`, `messages.rs`, `guard_gh_write.rs`.
- Marker files `confirm-<sha256>` in the private per-user marker directory.
- `docs/hooks.md`, `docs/configuration.md`, `CHANGELOG.md`.
- cadence-ecosystem ADR-0046 needs a line for the new outcome (rule 2); drafted in the PR description, landed there separately.
