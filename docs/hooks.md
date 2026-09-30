# Hook Catalog

The full catalog of hooks shipped by the `cadence-hooks` binary, organized by
the plugin they serve. The binary is the single source of truth — run
`cadence-hooks list` for the live list with disable status, or `cadence-hooks
try <namespace> <hook>` to see any hook run against a sample payload (see
[docs/testing.md](testing.md)).

For how hooks communicate with Claude Code (stdin/stdout/exit codes), see
[Hook Protocol](../README.md#hook-protocol) in the README.

## Remote policy (cloud sessions)

Under `CLAUDE_CODE_REMOTE=true` (Claude Code on the web, routines) every hook
follows the **Remote** column of the tables below: `run` behaves as it does
locally; `self-disable` exits 0 with no output before reading stdin;
`block-with-reason` exits 2 (none use it yet). Declared per hook in
`src/registry.rs`, where each entry carries a one-line rationale; a hook without
one does not compile. `CADENCE_BYPASS` keeps its meaning. Two hooks also adapt
while running: `enforcement-status` emits one `cadence-hooks: ARMED vX.Y.Z` or
`cadence-hooks: INERT (allowed owners not configured)` line at SessionStart
(keyed on `CADENCE_ALLOWED_OWNERS`), and `warn-commit-provenance` stamps
`Machine: cloud`. `manifest --format json` exports the policy as `remote`.

## Wiring prefilters — what a hooks.json `if:` actually does

A plugin's `hooks.json` may gate a hook behind an `if:` filter (`"if": "Bash(*gh pr create*)"`). It is a **cost filter, not a correctness filter**: it decides whether the binary spawns, never what the binary decides. Every precision claim in this catalog belongs to the binary; assume the prefilter is wrong in both directions and write the check so that is safe.

What follows is a measurement of the **platform**, not a record of any plugin's registration: how an `if:` glob matches, with `rm`/`RM` as the illustrative verb because it is short and its two cases differ. The registrations themselves live in the plugin repo. Measured on Claude Code 2.1.273 (2026-09-15) with a throwaway `--settings` file whose hooks only logged which filters matched, against a catch-all hook that refused every command so nothing executed:

| `if:` filter | `echo confirm` | `rm -rf <path>` | `RM -rf <path>` | `chmod 644 <path>` |
|---|---|---|---|---|
| `Bash(*)` — control | fires | fires | fires | fires |
| `Bash(*zzqqxx*)` — control | - | - | - | - |
| `Bash(*rm*)` | **fires** | fires | - | - |
| `Bash(*RM*)` | - | - | fires | - |
| `Bash(*[rR][mM]*)` | - | - | - | - |
| `Bash(rm:*)` | - | fires | - | - |
| `Bash(*rm *)` | - | fires | - | - |

Four properties follow, and each one has burned someone:

1. **An `if:` value is a permission rule, not a raw glob over the command string.** The two forms match by different means, so read the form before predicting the match: `Bash(*x*)` behaves as a substring glob with no word boundary and no notion of a command head, while `Bash(cmd:*)` keys on the command head (property 4) — which is why `Bash(rm:*)` matched `rm -rf <path>`, a string in which the literal `rm:` never appears. In its substring form, `Bash(*rm*)` fires on `echo confirm`, `git format-patch`, `terraform apply`, `npm run warm-cache`, and `./perform-migration.sh` — every one of which contains the letters `rm` inside an ordinary word. (`chmod` does *not*; it has no `rm` in it. The word list in cadence-hooks#597 was partly guessed rather than measured.) Each false match spawns a process that parses the command, finds no deletion, and allows.
2. **Matching is ASCII case-sensitive.** The `*rm*` and `*RM*` rows differ only in case and select disjoint sets of commands, so a filter written in one case does not select the other spelling of the same verb. Any case folding the binary performs on a verb is therefore exercised only on what such a filter passes through — which is what cadence-hooks#577 asked and this table answers. `trash-guard` is registered with no `if:` at all, so nothing narrows what it sees, and its own case-folded verb match is the only filter.
3. **Character classes are not supported.** `Bash(*[rR][mM]*)` matched neither spelling, so case coverage cannot be bought with one cleverer glob. A two-letter verb would need four literal entries; a six-letter verb, sixty-four. The `matcher` field is a regex and does support classes — the two fields are different engines, and the regex spelling in a neighbouring `matcher` is not evidence about `if:`.
4. **`Bash(cmd:*)` keys on the command head**, unlike `Bash(*cmd*)`. It is the precise form, and precisely why it is the wrong tool for a guard: it reads only the leading word, so a verb appearing anywhere else in the command — after a shell operator, or invoked by another program — is not selected by it.

**The rule this leaves.** A guard whose job is to see every spelling of a dangerous command should carry **no `if:` at all** and let the binary filter — the pattern `trash-guard` has always used. A guard's binary must therefore stay a cheap, silent no-op on arbitrary input; `trash-guard` pins that with table tests over ordinary commands. Reserve `if:` for hooks whose subject genuinely is a literal substring (`Bash(*gh pr create*)`), and never read one as a safety boundary.

## Grouped wiring: several checks, one process

Claude Code starts one process per hooks.json entry, and on a Write that used to be a dozen processes. Each check decides in well under a millisecond, so process launch is nearly all the cost. `cadence-hooks group` runs several checks against one payload in one process:

```json
{ "type": "command", "timeout": 10,
  "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" group cadence/terminology cadence/orphaned-todos cadence/prevent-secret-writes" }
```

Each member keeps what its own process gave it:

- **Its own thread and git budget.** Members run in parallel, and each has the full `CADENCE_HOOK_DEADLINE_MS` budget. One slow member cannot use up another's budget.
- **Its own audit rows.** Every member writes the same `denials.jsonl`, `bypasses.jsonl`, and `hooks.jsonl` rows under its own name.
- **Its own switches.** `CADENCE_DISABLE` applies per member, protected guards still refuse it, and a panic is caught for that member alone. `CADENCE_BYPASS=1` still skips everything.

The results merge the way Claude Code combines separate processes:

- **Any block** exits 2 with every blocker's message on stderr, followed by any nudges that fired.
- **Otherwise** one exit-0 envelope carries the ask reasons and the nudges.

The group emits whatever has been decided once the git budget plus one second has passed (4 s by default). A member still running then fails open for that call and is logged as `group_deadline` in `failopen.jsonl`. Set the entry's hooks.json `timeout` above that; 10 is the convention.

Rules for wiring:

- **Members are `<namespace>/<hook>`** and must be PreToolUse or PostToolUse checks. Loggers, CLI actions, and SessionStart hooks are refused, and `doctor` reports them.
- **Only group hooks with the same matcher and no `if:`.** A group entry has one matcher and one `if:`, so a hook whose prefilter differs from the others keeps its own entry.
- **Keep a hook that starts a slow external tool in its own entry** (`markdown-lint` runs the Node `markdownlint` CLI). Grouping saves it nothing, and its own entry keeps its own timeout.
- **A binary older than `group`** is handled by `run-cadence-hooks.sh`: it replays the payload to each member in turn, so every guard still runs and still blocks until the binary is upgraded.

## cadence

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `terminology` | PreToolUse (Write, Edit) | Block inclusive terminology violations | run |
| `orphaned-todos` | PreToolUse (Write, Edit) | Require `MARKER(#issue):` format for TODO/FIXME/HACK | run |
| `prevent-secret-leaks` | PreToolUse (Read, Grep, Bash) | Block reading the dotenv family (`.env`, `.env.*`, minus templates; `<name>.env` too wherever the token is known to be a path), credentials, private keys (exempt: a **bare** `forgectl env keys\|set\|get\|check` naming its `--file` target — not a path-qualified or wrapped spelling, not another operand, not a redirection whose target is itself a secret file) | run |
| `prevent-secret-writes` | PreToolUse (Write, Edit, Bash) | Block writing/deleting the dotenv family (`.env`, `.env.*`, minus templates; `<name>.env` too wherever the token is known to be a path) and credential files | run |
| `prevent-secret-push` | PreToolUse (Bash) | Block a `git push` that would publish a secret: a commit adding a secret-named file or a credential token, a raw commit or annotated-tag object carrying one, or a pushed ref name carrying one (scans `git log -p` over the range not reachable from any remote-tracking ref, with replace refs off; fails closed on an unresolvable, over-cap or timed-out range, a non-commit source or tag, a submodule push in a repository with submodules, `git send-pack`/`git http-push`, a remote helper (`git remote-<transport>`), a dashed `git-push` or `exec -a git…`, a 40/64-hex source a ref is also named like, a commit `encoding` other than UTF-8/US-ASCII/ISO-8859-*, or a config alias, autocorrected guess or unreadable config that can push). Trusts as published: a commit on ANY remote (a private upstream's history pushed to a public fork), a remote-tracking ref written by an earlier command, and `pushurl`/`pushInsteadOf` redirects. Over-blocks: `--tags`, `--mirror` and `--follow-tags` re-read tags the remote may already have. Git LFS content is not scanned (pointer only), nor a push nested in another git command's exec string (`git rebase -x`, `bisect run`, `submodule foreach`, `filter-branch` filters); the autocorrect existence check uses the hook's `PATH`; a submodule-recursing push over an index of more than ~300k entries is refused as too large. Content in a repository whose top-level path has a `cadence-hooks` component is exempt, whole-repo. Escape: `CADENCE_ALLOW_SECRET_PUSH=1` | run |
| `memory-guard` | PreToolUse (Write, Edit) | Enforce MEMORY.md line limits | run |
| `git-safety` | PreToolUse (Bash) | Block force-push to main, reset --hard, etc. | run |
| `line-endings` | PreToolUse (Write) | Validate shell script line endings (LF, not CRLF) | run |
| `env-vars` | PreToolUse (Write, Edit) | Warn on generic env var names (DEBUG, PORT) | run |
| `warn-docs-update` | PreToolUse (Bash) | Nudge to review docs when creating a PR (`gh pr create`) | run |
| `warn-changelog-entry` | PreToolUse (Bash) | Nudge to add a CHANGELOG.md entry when shipping code changes | run |
| `warn-overshare` | PreToolUse (Bash, Write, Edit) | Nudge to audit about-to-ship content for personal-context overshare | run |
| `warn-instruction-narrative` | PreToolUse (Write, Edit, MultiEdit) | Nudge when an edit to `CLAUDE.md`/`CLAUDE.local.md`/`AGENTS.md` adds narrative: 3+ past-event markers (ISO date, `measured`, `incident`, …), or a paragraph past 8 sentences or 1200 characters (fences and table rows stripped) that carries a marker. A pointer phrase (`commit history`, `see`, …) clears both; length alone never fires. Judges only added lines | run |
| `warn-live-memory-write` | PreToolUse (Write, Edit, MultiEdit) | Nudge on a direct write to live auto-memory (`<config dir>/projects/<slug>/memory/`) while no fresh dream run lock (`<config dir>/cadence/dreams/<slug>/.dream-lock`, under 6 hours old) is held | run |
| `warn-plugin-root-cruft` | PreToolUse (Write, Edit, MultiEdit) | Nudge on a write under `plugins/<name>/docs/` or `plugins/<name>/scripts/` when the repo's `.claude-plugin/marketplace.json` declares `./plugins/<name>` (skill-nested `scripts/` never match) | run |
| `nudge-polish-before-pr` | PreToolUse (Bash) | Nudge to run `/polish` (cadence-forge:polish) before `gh pr create` | run |
| `markdown-lint` | PreToolUse (Write) | Run markdownlint on markdown files | run |
| `audit-runner-pool` | PostToolUse (Write, Edit, MultiEdit) | After an edit to `.github/workflows/*.yml`/`*.yaml`, run `cadence-forge:auditing-runner-pool-workflows`' `audit-workflows.py` (newest copy under `<config dir>/plugins/cache/*/cadence-forge/`; 3.5s cap) and return FAIL findings as a nudge. Never blocks: a missing script, no `python3`, a timeout or an unknown exit is silent; the audit's exit 2 ("could not run") becomes a one-line note | run |
| `guard-held-close` | PreToolUse (Bash) | Block `gh issue close` when a candidate target is on the HELD ledger (`--ledger <file>` of `owner/repo#N` entries; `CADENCE_DRAIN_HELD` overrides). Errs toward blocking: every issue-shaped operand counts, an unreadable repo matches the number anywhere on the ledger | run |
| `redact-external-content` | PreToolUse (Write, Edit, write-shaped `mcp__*` tools, Bash) | Nudge when an external post mentions internal harness vocabulary | run |
| `platform-drift` | SessionStart | Nudge when cadence-hooks or Claude Code has drifted behind the plugin-shipped platform baseline (`--baseline <file>`) | run |
| `model-posture` | SessionStart, PostModelSwitch (onto Fable) | Inject the Fable seat posture at session start and on a switch onto Fable | run |

`warn-overshare` does path triage only — it fires on commit/push/PR/issue Bash
commands and on Write/Edit to `docs/field-reports/`, then leaves the content
judgment to the model. It exempts writes under `$OBSIDIAN_VAULT`
(the safe home for personal context), and is silenced session-wide with
`CADENCE_SKIP_OVERSHARE_AUDIT=1`.

## guardrails (git-guardrails)

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `guard-push-remote` | PreToolUse (Bash) | Block git push to repos you don't own | run |
| `guard-gh-write` | PreToolUse (Bash) | Block gh write operations to non-owned repos | run |
| `guard-forge-write` | PreToolUse (Bash) | Block `tea`/`glab` write operations to non-owned repos (unwired until the plugin entry lands) | run |
| `guard-critical-grade` | PreToolUse (Bash) | Block applying `impact:critical` / `likelihood:critical` without a human ruling (unwired until the plugin entry lands) | run |
| `guard-gh-dangerous` | PreToolUse (Bash) | Block irreversible gh operations (repo delete) | run |
| `guard-git-init` | PostToolUse (Bash) | Nudge to scaffold and confirm license after `git init` or `gh repo create` | run |
| `warn-main-branch` | PreToolUse (Write, Edit) | Warn when editing on main/master branch | run |
| `enforce-worktree` | PreToolUse (Write, Edit, Bash) | Block mutations and `git commit` in a primary checkout of a branch-mode repo — work in a worktree instead (exempt: `CADENCE_ALLOW_MAIN` repos, temp/scratch repos, `.claude/` + `docs/plans/` paths) | self-disable |
| `warn-branch-base` | PreToolUse (Bash) | Warn when creating a branch from a non-main base | run |
| `warn-cron-datetime` | PreToolUse (CronCreate) | Inject current datetime before scheduling cron jobs | run |
| `warn-untracked` | PreToolUse (Bash) | Warn about untracked files during git commit | run |
| `warn-amend-pushed` | PreToolUse (Bash) | Warn when `git commit --amend` rewrites a commit the remote-tracking refs already carry | run |
| `nudge-upgrade-after-push` | PostToolUse (Bash) | Nudge to schedule a brew upgrade after pushing cadence-hooks to main | self-disable |
| `guard-dotfiles` | PreToolUse (Edit, Write) | Block direct edits to production dotfiles (opt-in via `CADENCE_GUARD_DOTFILES=1`) | run |
| `warn-pr-issue-link` | PreToolUse (Bash) | Nudge when `gh pr create` has no closing issue keyword (`Closes #N`) in the body | run |
| `warn-issue-tracker` | PreToolUse (Bash) | Nudge when `gh issue create` targets an owned repo that is not a known ecosystem tracker | run |
| `verify-pr-autoclose` | PostToolUse (Bash) | Verify issue auto-close refs after PR create; close stragglers after merge | run |
| `guard-op-vault-scan` | PreToolUse (Bash) | Block 1Password vault enumeration (`op item list`); single-item reads stay allowed | run |
| `guard-sops-decrypt` | PreToolUse (Bash) | Block a `sops` decrypt whose plaintext is not consumed by an allowed tool (key-name lister, `curl --config -`); `sops edit`/`set`/`-e` are untouched. Escape: `CADENCE_ALLOW_SOPS_DECRYPT=1` | run |
| `guard-runbook-scrub` | PreToolUse (Write, Edit, Bash) | When `CADENCE_RUNBOOKS_DIR` is set, block a Write/Edit/MultiEdit into that directory unless the resulting document's SHA-256 matches a marker from `cadence record-scrub`; block any Bash write into it outright (a redirect or writer verb — its content is unknowable before it runs). A Bash command that names the directory may only read it (any other write, or a program outside a read-only list, blocks). Paths are resolved through symlinks and `..`, case-insensitively. An Edit whose result cannot be simulated literally blocks, and so does any write into the scrub-marker directory. Inert when the variable is unset. Escape: `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK=1` | run |
| `warn-curl-alias` | PreToolUse (Bash) | Warn when bare `curl` (aliased to curlie) is used with custom headers | run |
| `warn-gh-merge-preflight` | PreToolUse (Bash) | Pre-flight checklist before `gh pr merge` (isDraft, worktree, mergedAt verification) | run |
| `warn-unreviewed-ready-flip` | PreToolUse (Bash) | Warn on `gh pr ready`/`gh pr merge` when the PR head has no reviewed signal (non-author human APPROVED, or a clean `cadence-review` marker), or a reviewer's latest decisive review is still `CHANGES_REQUESTED` (the warning names the dismissal command for the operator) | run |
| `warn-stale-pr-body` | PreToolUse (Bash) | Warn on `gh pr ready`/`gh pr merge` when the PR body was never edited since the PR was opened while the branch has gained commits since — the placeholder body is about to become the squash-merge record | run |
| `warn-stacked-base-delete` | PreToolUse (Bash) | Warn before `git push <remote> --delete <branch>` / `:<branch>` or `gh pr merge --delete-branch` when open PRs base on the branch (deleting it closes them, never retargets); names the PRs | run |
| `warn-entry-posture` | PreToolUse (Write, Edit) | Once per session per linked worktree, at the first write: warn when the branch has no upstream (`git push -u`) or no open PR (`gh pr create --draft`) | run |
| `warn-chezmoi-apply` | PreToolUse (Bash) | Warn when `chezmoi apply` would overwrite files `chezmoi status` shows drifted locally (`MM`/`MD`), narrowed to the apply's targets and `--include`/`--exclude`; an unscoped apply gets a scoping clause. Silent on a clean tree, a dry run, a relocated source/config, or no `chezmoi` | run |
| `warn-alias-parsing` | PreToolUse (Bash) | Warn when piping aliased-tool output (cat/find/ls/du/df/top) into parsers | run |
| `guard-browser-device` | PreToolUse (Claude-in-Chrome MCP) | Block the first claude-in-chrome action per session until the target device is confirmed | run |
| `inject-gh-write-context` | PreToolUse (Bash) | Re-inject the same allowlist + `-R owner/repo` rule just before a `gh` write that names no target | run |
| `warn-agent-dispatch` | PreToolUse (Agent, Task) | Advisory only. Warn on a non-fork dispatch with no `model`, a `model` on a fork dispatch (ignored by the platform), and a brief that asks the subagent to execute commands without naming a scrubbed/isolated HOME. Never echoes the prompt | run |
| `warn-subagent-worktree` | PreToolUse (Agent, Task) | Warn when dispatching a subagent from main while a sibling worktree exists | self-disable |
| `enforcement-status` | SessionStart | Report when `CADENCE_BYPASS=1` or `CADENCE_DISABLE` names a protected guard | run |
| `guard-read-model` | PreToolUse (Read, Grep, read-shaped `mcp__*` tools) | Block a read when the resolved session model is denied by policy (opt-in via `CADENCE_READ_MODEL_GUARD_MODELS`) | run |
| `guard-body-budget` | PreToolUse (Bash) | Measure `gh pr`/`gh issue` bodies against a per-surface word budget (nudge mode by default; `CADENCE_BODY_BUDGET_MODE=block` blocks) | run |
| `warn-going-public` | PreToolUse (Bash) | Nudge on repo create/publicize when the name or description telegraphs sensitive content | run |
| `warn-inline-body` | PreToolUse (Bash) | Nudge when `gh pr create`/`gh issue create` posts an inline `--body` longer than 200 characters instead of `--body-file` | run |

`guard-browser-device` is a deliberate block (not a nudge): a nudge is exit 0,
so the browser action would already have hit a device before the context
arrived. It blocks the first claude-in-chrome tool call of a session, writes a
per-session marker, and allows every subsequent call — forcing the
`list_connected_browsers` → `select_browser` handshake the MCP server only
advises.

## rules

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `validate-frontmatter` | PreToolUse (Write, Edit) | Validate SKILL.md, command, living-plan, and plugin-agent frontmatter | run |
| `security-patterns` | PostToolUse (Write, Edit) | Scan for security anti-patterns | run |
| `warn-recommended-option` | PreToolUse (`AskUserQuestion`) | Nudge to label a recommended option "(Recommended)" | run |
| `warn-empty-answers` | PostToolUse (`AskUserQuestion`) | Nudge to re-ask when `AskUserQuestion` returns empty auto-approve answers | run |

`security-patterns` is a **zero-config, no-API baseline** — a per-edit pattern
scan with no setup. For configurable patterns plus model-backed diff and commit
review, install the official `security-guidance` plugin
(`/plugin install security-guidance@claude-plugins-official`).

## obsidian (cadence-obsidian)

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `trash-guard` | PreToolUse (Bash, Edit, Write, destructive `mcp__*` tools) | Block destructive vault operations (`rm`, `git rm`, `unlink`, `shred`, `truncate`, `find -delete`, `coproc` of any of those, clobber redirects, and an empty or whitespace-only `Write` over an existing vault file); use `.trash/` instead | run |
| `trash-guard-liveness` | SessionStart | Nudge when `OBSIDIAN_VAULT` is set but is not a directory, or a trash-guard route no longer judges as contracted | self-disable |

A verb counts only where the shell runs an executable, and there are two such
positions: the head of a segment, and a `find` exec-family action
(`-exec`/`-execdir`/`-ok`/`-okdir`). Both are read the same way — past the
scaffolding of a compound statement (reserved words like `do`/`then`, the `( )`
and `{ }` of a group, a `case` arm's pattern label, a function definition
header), past transparent wrappers, past a command runner's own flags (`sudo`,
`xargs`, `nice`, `stdbuf`, `timeout`, `env`), and past git's global options to
its subcommand — so `git -C . rm x` and `find . -exec nice -n 10 rm {} \;` both
count. An operand a command re-executes (`eval …`, `find … -exec sh -c '…'`) is
scanned as a command in its own right, including behind those same runner flags
— `nice -n 10 sh -c 'rm x'` and `find … -exec env -i sh -c 'rm x' \;` are read,
not just the unflagged spellings. A command substitution runs in the parent
shell before any wrapper is spawned, so `bash -c '…' "$(rm x)"` is scanned on
both halves.

**The two combine.** Scaffolding and a re-executed operand are read by one
model, so `if true; then bash -c 'rm x'; fi`, `for f in a; do sh -c 'rm x'; done`
and `(bash -c 'rm x')` are scanned exactly as `bash -c 'rm x'` is. Until 0.70.0
they were not: the verb gate stripped the keyword and the hunt for a wrapper did
not, so the combination was the one spelling that escaped.

That is narrower than a scan of the whole command line, which is what this guard
used before 0.70.0 — `echo rm` and `npm run format` no longer match, and neither
does a verb reached by a spelling not listed above: one built by substitution
(`` `echo rm` x ``, `$(echo rm) x`), one carried in a body this model does not
treat as executed (a `trap` handler, a `coproc`), a deleting binary outside the
verb list (`srm x`), or one behind a runner option the grammar does not model
(`env -S 'rm x'`). A runner option the grammar cannot classify stops the scan
rather than being guessed past, so an unmodelled spelling costs a block here and
never creates a spurious one.

## metrics (cadence-metrics)

These are **loggers**, not guards: they append JSONL event records and always
exit 0. They never block a tool call (see
[Hook Protocol](../README.md#hook-protocol)).

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `snapshot` | PreToolUse (Bash, `git commit`) | Snapshot HEAD before a commit, so `log-commit` can tell whether it landed | self-disable |
| `log-commit` | PostToolUse (Bash, `git commit`) | Scan the transcript for tokens since the last commit, compute cost, append to `commits.jsonl` | self-disable |
| `log-subagent` | SubagentStart / SubagentStop | Append a subagent lifecycle record to `subagents.jsonl` | self-disable |
| `log-session` | SessionEnd | Scan the whole session log at session end, compute per-model cost, append to `sessions.jsonl` | self-disable |
| `log-session-start` | SessionStart | Stamp the session start timestamp, so `log-session` can compute `durationMs` at `SessionEnd` | self-disable |
| `log-polish-nudge` | PostToolUse (Bash, `gh pr create`) | Record every nudged PR and whether `/polish` ran earlier this session, append to `polish_nudges.jsonl` | self-disable |
| `log-ask-user-question` | PreToolUse (`AskUserQuestion`) | Record each call's stance (recommended / declared-no-rec / silent) and shape (multiSelect, question/option counts), append to `askuserquestion.jsonl` | self-disable |
| `log-skill` | PostToolUse (`Skill`) | Append each Skill invocation to `skills.jsonl` | self-disable |
| `warn-stale` | SessionStart | Warn when metrics telemetry has gone stale (a nudge, never a block) | self-disable |

`metrics grade` is a **CLI action, not a hook** — it has no `hooks.json` wiring,
reads no stdin payload, and is not subject to `CADENCE_DISABLE`. It grades one
transcript deterministically and prints the JSON:

```bash
cadence-hooks metrics grade --transcript path/to/transcript.jsonl
cadence-hooks metrics grade --session-id <uuid>   # searches every projects/* dir
cadence-hooks metrics grade                        # defaults to $CLAUDE_CODE_SESSION_ID
```

The same grading is written to every `sessions.jsonl` row under a `grading` key.
Unlike a guard, `grade` fails closed: a transcript it cannot identify or read
exits 1 with the reason on stderr rather than printing a partial grading.

`log-commit` and `log-session` both read the price table from the embedded
default, overridable with `--prices <path>` (or `CADENCE_METRICS_PRICES`). Set
`CADENCE_METRICS_DEBUG=1` to add a `_keys` array of raw payload keys to
subagent records — useful for spotting schema additions across Claude Code
releases.

Cost is computed **per model**: when a commit range spans multiple models
(opus → sonnet handoffs, fast-mode toggles), each model's tokens are priced at
its own rates and summed. Records carry the breakdown in a `byModel` array
(`[{model, tokens, costUsd}]`); rows written before this field existed are
single-model by definition.

Cache writes are priced **per TTL**: a 1-hour write costs 2x base input against
1.25x for the 5-minute default, so records carry `cacheCreate1h` alongside
`cacheCreate` and each slice is billed at its own rate. `cacheCreate` stays the
grand total of all cache writes, so a TTL bucket the scanner does not name is
still counted — it simply bills at the 5-minute rate.

## session (cadence)

Multi-session coordination for the **cadence** plugin (issue #54). Concurrent
Claude Code sessions sharing one repo checkout cannot see each other — these hooks
give sessions *identity* within a repo via a registry at `<repo>/.claude/sessions/`
(one `<session-id>.json` per session, mtime is the liveness heartbeat, auto-excluded
from git via `.git/info/exclude`). Sessions are displayed by the first 8 characters
of that id, which is a display convenience — ownership is always decided on the full
id.

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `start` | SessionStart | Register this session, sweep stale entries, and disclose the live-peer count in one line (`cadence-hooks session status` for the detail) | self-disable |
| `heartbeat` | — (unwired) | Touch this session's registry file; refresh the recorded branch so peers see branch drift. The beat now rides `persist-plan-approval`'s PostToolUse process, throttled (#902) | self-disable |
| `guard` | PreToolUse (Bash, Edit, Write) | Warn — never block — on branch switches, blanket staging (`git add -A`, `git commit -a`), and writes inside a peer's declared paths | self-disable |
| `warn-branch-drift` | PreToolUse (Bash, `git commit`) | Warn when HEAD drifted from the session's recorded branch at commit time | run |
| `warn-branch-intent` | PreToolUse (Edit, Write) | Nudge once per session when new work starts on a stale feature branch whose name shares nothing with the declared intent | run |
| `warn-commit-provenance` | PreToolUse (Bash, `git commit`) | Nudge with a computed `Session-Id:` trailer block when a Claude-composed commit message lacks one | run |
| `persist-plan-approval` | PostToolUse (every tool) | On `ExitPlanMode`, persist the approved plan into the repo's plans dir, merging its frontmatter and nudging when it carries no settled `Panel:` line (`CADENCE_NO_PERSIST_PLAN` opts out); on every call, refresh this session's liveness heartbeat, throttled | self-disable |
| `backstop-warn` | SessionStart | Warn once when the last session left loose ends, then clear the marker | self-disable |
| `backstop-record` | SessionEnd | Record loose ends (uncommitted changes, unpushed commits, stashes, other worktrees with unpushed work) for the next `session start` to surface, only when no live peer remains in the checkout | self-disable |
| `end` | SessionEnd | Deregister this session's registry file | self-disable |

Liveness is mtime-based: a session that crashes or closes simply stops heartbeating
and is presumed dead after 30 minutes (`CADENCE_SESSION_STALE_MINUTES`). No
deregistration ceremony. Stale entries are swept on the next `session start`.

### Living-plan guards

Four more `session` hooks serve the living-plan lifecycle (ADR-0038) rather than
multi-session identity. They are wired by the **cadence** plugin. The first three
bind to the plan doc for the current branch; `plan-driver` binds first by the plan's
frontmatter `approved_session_id`, then by `branch:`.

| Hook | Event | What it does | Remote |
|------|-------|--------------|--------|
| `nudge-plan-tick` | PostToolUse (Bash, `git commit`) | Nudge once per session when a successful commit left the branch's in-flight plan untouched | run |
| `warn-plan-ready-flip` | PreToolUse (Bash, `gh pr ready`/`merge`) | Warn when the branch's plan still reads `status: in-flight` or carries unticked boxes at the PR-ready flip; quiet when the flip names another repo (`-R`, `GH_REPO=`, a PR URL) or another branch | run |
| `lint-plan-shape` | PreToolUse (ExitPlanMode) | Block when the plan carries no settled `Panel:` line (escape: `Panel: none — <reason>`); nudge when other template stanzas are missing; every judged outcome carries the presentation reminders (subagents stopped, operator asked to see the plan) | run |
| `plan-driver` | PreModelSwitch (`source` `command`/`picker`, attended TUI) | Ask the operator to confirm a `/model` switch whose target family differs from the in-flight plan's `## Orchestrator` → `Driver:`; silent unless the hook env shows `CLAUDE_CODE_ENTRYPOINT=cli` and `CLAUDE_CODE_SESSION_ATTENDED=1` with no `CLAUDE_CODE_REMOTE` (with no human attached — SDK, `claude -p`, stream-json — an `ask` refuses the switch outright), on disagreeing or driverless plans, and on an unrecognized model | run |

`nudge-plan-tick` and `warn-plan-ready-flip` only ever warn; `plan-driver` only ever
asks, and only where a human can answer. `lint-plan-shape` is the
one plan guard that blocks, and only on the `Panel:` line; subagent-originated calls
(`agent_id` present) and every internal failure allow (ADR-0001).

### CLI actions (not hooks)

A few `cadence-hooks` subcommands are operator commands, not hooks — they take
no stdin payload, have no `hooks.json` wiring, and are not subject to
`CADENCE_DISABLE`. They are exempt from `CADENCE_BYPASS` so they keep working
during maintenance.

| Command | What it does |
|---------|--------------|
| `session declare` | Declare what this session is working on (`--intent`, `--touching`) so peers can assess collision risk |
| `session status` | List live and stale sessions registered in this repo: the current checkout and every worktree `git worktree list` names, with a footer counting the worktrees checked (exit 1 outside a git repository) |
| `session plans` | List every in-flight and blocked plan in `docs/plans/` with its next step, branch, and PR — the detail behind the SessionStart plan pointer, with no cap on the file count. Exit 2 outside a git repository, or when an entry in `docs/plans/` could not be listed or read (each named on stderr) |
| `cadence record-scrub --file <path>` | Record that a runbook draft passed the secret scrub: writes a marker keyed on the SHA-256 of the file's bytes (line endings ignored: `\r\n` hashes as `\n`) into the private marker directory, which `guard-runbook-scrub` honors for a write of that same content. It trusts its caller — run it only after `scrub.py --apply` and a check-mode `scrub.py` exit 0. Exit 0 recorded, 1 nothing recorded (unreadable or non-regular file, non-private marker dir), 2 usage |
| `guardrails dismiss-main-branch-warn` | Snooze `warn-main-branch` for this repo for a bounded window (`--for 2h`, capped at 24h) — see [Snoozing warn-main-branch](configuration.md#snoozing-warn-main-branch) |
| `guardrails dismiss-enforce-worktree` | Snooze the `enforce-worktree` block for this repo for a bounded window (`--for 30m`, capped at 24h) — the one-off escape for a legitimate primary-checkout mutation |
