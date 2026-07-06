# Configuration & Operations

How to wire `cadence-hooks` into Claude Code, the environment variables that
tune behavior, the `doctor` audit, and the `warn-main-branch` snooze.

## Configuring in Claude Code

Reference the binary in your plugin's `hooks.json`:

```json
{
  "hooks": [
    {
      "type": "preToolUse",
      "matcher": "Write|Edit",
      "command": "cadence-hooks cadence terminology"
    },
    {
      "type": "preToolUse",
      "matcher": "Bash",
      "command": "cadence-hooks guardrails guard-push-remote"
    }
  ]
}
```

Each hook is a subcommand; `cadence-hooks list` shows every hook with its event
and disable status, and `cadence-hooks <namespace> --help` lists a namespace's
subcommands.

## Per-repo terminology exemptions

The `terminology` guard hard-**blocks** a small set of dated terms on every
`Write`/`Edit` (`whitelist`, `blacklist`, `master branch`/`master node`,
`slave`, `sanity check`, `dummy value`; `grandfathered` is a softer nudge). That
block is the right default everywhere. But some files legitimately carry these
words — a vendor ACL format named `whitelist`, an existing API field, a config
schema whose key *is* the dated term. A per-repo `<git-root>/.claude/terminology.json`
softens the block for named files and terms.

It can only ever **remove or demote** a violation — never add one. It cannot
introduce new blocked terms, and it cannot turn the block on for a path the
built-in baseline already exempts (this repo's own source, `CLAUDE.md`,
`.claude/hooks`/`rules`). Missing, unreadable, or invalid JSON is ignored and the
block stands (fail-open, ADR-0001).

```jsonc
{
  "exemptions": [
    {
      "paths": ["config/acl.yml", "**/firewall-*.yaml", "vendor-list.yml"],
      "terms": ["whitelist", "blacklist"],
      "mode": "allow"
    },
    { "paths": ["vendor/**"] }
  ]
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `paths` | yes | Glob patterns. A pattern containing `/` matches the **repo-relative** path (`**` spans separators, `*` does not); a bare pattern (no `/`, e.g. `vendor-list.yml`) matches the **basename** in any directory. |
| `terms` | no | Which flagged terms to exempt at those paths, matched case-insensitively against the guard's display term (the block labels plus `grandfathered`). **Omit to exempt every flagged term** at the matched path. An unknown string simply never matches. |
| `mode` | no | `"allow"` (default) drops the violation silently; `"nudge"` demotes a hard block to an advisory nudge (never blocks) so a visible reminder remains. |

**Matching & precedence.** For each `(file, term)` pair, the **first** exemption
entry in document order that matches both the path and the term decides. An entry
matches the term when `terms` is omitted/empty or contains it.

## Environment Variables

All cadence-hooks config lives under the `CADENCE_*` prefix. `OBSIDIAN_VAULT` is
kept unprefixed because it's a cross-tool convention.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CADENCE_DISABLE` | all hooks | Comma-separated hook names to skip (e.g., `git-safety,warn-main-branch`) |
| `CADENCE_BYPASS` | all hooks | Set to `1` to skip all enforcement (maintenance bypass); CLI actions stay available |
| `CADENCE_NO_FEEDBACK_FOOTER` | all hooks | Set to any non-empty value to suppress the `If this fired in error: /cadence:feedback` footer appended to hard blocks |
| `CADENCE_ALLOWED_OWNERS` | `guard-push-remote`, `guard-gh-write` | Space- or comma-separated usernames |
| `CADENCE_ALLOWED_REPOS` | `guard-gh-write` | Space- or comma-separated `owner/repo` pairs |
| `CADENCE_EXTRA_HOSTS` | `guard-push-remote`, `guard-gh-write` | Self-hosted forge hosts that bare entries (`cameron`) should match in addition to the default host |
| `CADENCE_GH_STRICT_LOOPS` | `guard-gh-write` | Set to `1` to block all looped gh writes lacking `-R`, even provably deterministic ones |
| `CADENCE_ISSUE_TRACKERS` | `warn-issue-tracker` | Comma-separated set of known ecosystem trackers (`owner/repo`) — replaces the default set (`cameronsjo/cadence`, `cameronsjo/cadence-hooks`, `cameronsjo/forgectl`, `cameronsjo/claude-configurations`); the nudge fires only when an owned target is none of them |
| `CADENCE_ISSUE_TRACKER` | `warn-issue-tracker` | Legacy singular override — sets a single known tracker (`owner/repo`), replacing the default set. Superseded by `CADENCE_ISSUE_TRACKERS`; still honored when the plural is unset |
| `CADENCE_GUARD_DOTFILES` | `guard-dotfiles` | Set to `1` to block direct edits to production dotfiles (clean no-op otherwise) |
| `CADENCE_ALLOW_MAIN` | `warn-main-branch`, `enforce-worktree` | Set truthy (`1`/`true`/`yes`) in a repo's `.claude/settings.json` `env` block to mark a repo where `main` is the working branch by design (dotfiles, vaults, scratchpads) — silences the main-branch warning and exempts the repo from worktree enforcement. `enforce-worktree` resolves this from process env OR the *target* repo's own tracked `.claude/settings.json`/`settings.local.json` (`settings.local` overriding `settings`) — so a cross-repo mutation into a by-design-main repo is exempt even when that repo isn't the session root |
| `CADENCE_NO_ENFORCE_WORKTREE` | `enforce-worktree` | Set truthy (`1`/`true`/`yes`) to disable the primary-checkout block everywhere — the kill switch for the proving period; prefer `CADENCE_ALLOW_MAIN` per repo |
| `CADENCE_SKIP_OVERSHARE_AUDIT` | `warn-overshare` | Set to `1` for a session-scoped bypass in repos that legitimately hold personal context |
| `CADENCE_METRICS_PRICES` | `log-commit` | Path to a model price-table JSON; takes precedence over the `--prices` flag and the embedded default |
| `CADENCE_METRICS_DIR` | metrics loggers | When set non-empty, the metrics root (JSONL files and the `state/` subdir live directly inside it); otherwise `<config_dir>/metrics` (honoring `CLAUDE_CONFIG_DIR`) |
| `CADENCE_METRICS_DEBUG` | `log-subagent` | Set to `1` to append a `_keys` array of the raw payload's top-level keys to subagent records — surfaces schema additions across Claude Code releases |
| `CADENCE_METRICS_STALE_DAYS` | `warn-stale` | Days of metrics-write silence before the SessionStart alarm fires and `doctor` reports staleness (default 4); zero or unparseable falls back to the default |
| `CADENCE_SESSION_STALE_MINUTES` | `session` hooks | Minutes of heartbeat silence before a session is presumed dead (default 10) |
| `GH_AUTOCLOSE_WAIT_SECONDS` | `verify-pr-autoclose` | Seconds to wait after `gh pr merge` before checking for straggler issues (default 10) |
| `OBSIDIAN_VAULT` | `trash-guard`, `warn-overshare` | Absolute path to Obsidian vault — the trash guard scopes `rm` blocking to it, and the overshare audit treats it as the safe destination for personal context |

### Allowlist host scoping

Bare entries in `CADENCE_ALLOWED_OWNERS` and `CADENCE_ALLOWED_REPOS` match only the default host (`github.com`, or `GH_HOST` if set). For self-hosted forges (Gitea, Forgejo, GitLab CE, Bitbucket Server), use one of:

- **Host-qualified entries** — `git.sjo.lol/cameron` matches only that host
- **`CADENCE_EXTRA_HOSTS`** — opt additional hosts into the bare-entry flow when you reuse the same username across forges you control

```bash
# Match `cameron` on github.com AND git.sjo.lol
export CADENCE_ALLOWED_OWNERS="cameron"
export CADENCE_EXTRA_HOSTS="git.sjo.lol"

# Or scope the entry explicitly without widening
export CADENCE_ALLOWED_OWNERS="cameron git.sjo.lol/cameron"
```

### How guard-gh-write resolves targets

For a single `gh` write, the target resolves in order: explicit `-R`/`--repo` flag (all four forms: `-R x`, `-Rx`, `--repo x`, `--repo=x`) → positional `owner/repo` argument → `gh api repos/...` path → the working directory's git remotes. A resolved target is checked against the allowlists; an owned target proceeds without any flag.

**Forks** (a repo with both `origin` and `upstream` remotes) are allowed when **both** remotes belong to allowed owners — each judged against its own host. When either side is unowned, the write blocks and asks for an explicit `-R`.

**Loops** containing gh writes without `-R` follow a *relaxed-when-deterministic* policy: the write is allowed when the loop body provably never changes directory (no `cd`/`pushd`/`popd`/`eval`/`source`) **and** the working directory resolves to a single owned, non-fork repo. Under those conditions every iteration targets the same repo the guard verified — the same trust extended to single commands. Anything the analyzer cannot prove (directory changes inside the body, parse failures, forks, unowned directories) still blocks.

Set `CADENCE_GH_STRICT_LOOPS=1` to disable the relaxation and block every looped gh write that lacks `-R` (the pre-0.12 behavior). Block messages include the resolved `-R owner/repo` fix when the working directory is owned.

### The `configure` subcommand under Claude Code

Under Claude Code (detected via `CLAUDECODE=1`), the `configure` subcommand is hidden from `--help` and refuses to run interactively — it edits `settings.json` and could silently disable guardrails. `configure --list` remains available. Run `configure` from a real terminal to change hook state.

## Auditing installed plugins

`doctor` scans every installed plugin's `hooks.json` for two classes of problems:

- **Shell-expansion bugs** (exit 2): single-quoted `'${CLAUDE_PLUGIN_ROOT}'` won't expand in `/bin/sh` — the harness reports a silent non-blocking failure and nothing surfaces to the user.
- **Subcommand skew** (exit 1): a hook references a subcommand this binary doesn't have — typically a plugin built for a newer version of cadence-hooks.

By default the scan is driven by `~/.claude/plugins/installed_plugins.json`, so only **active** installs are checked (the cache keeps stale plugin versions around — scanning those would report skew in code that no longer runs). With `--root`, the given tree is walked recursively, so both flat layouts (`<root>/<plugin>/hooks/hooks.json`) and the real cache layout (`<root>/<marketplace>/<plugin>/<sha>/hooks/hooks.json`) work.

```bash
# Scan active installs from ~/.claude/plugins/installed_plugins.json
cadence-hooks doctor

# Audit a specific tree (handy in CI before publishing a plugin)
cadence-hooks doctor --root ./plugins

# Preflight mode for SessionStart hooks — one summary line, non-zero only on errors
cadence-hooks doctor --quiet
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Warnings only — subcommand skew (version mismatch between plugin and binary) |
| 2 | Errors — shell-expansion bugs that will silently break hooks at runtime, or configuration/internal errors (`$HOME` unset, nonexistent `--root`) |

**Sample output (skew warning):**

```text
warning [cadence@workbench] ~/.claude/plugins/cache/workbench/cadence/174e3eb0def9/hooks/hooks.json:12: subcommand 'cadence future-hook' is not present in this binary (v0.11.0)
  command: "${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence future-hook
  fix: brew upgrade cadence-hooks (or downgrade the plugin)

cadence-hooks doctor: 0 error(s), 1 warning(s)
```

**`--quiet` mode** is suitable for SessionStart preflight wiring. When clean it produces no output and exits 0; on warnings it prints one summary line to stdout and exits 0 (so a `set -euo pipefail` script won't abort); on errors it writes one line to stderr and exits 2.

The stream split is deliberate: warnings go to **stdout** (a caller capturing stdout gets the skew nudge to inject), errors go to **stderr** (a caller redirecting stderr to `/dev/null` still fails on the exit code). Redirect accordingly — `>/dev/null` silences the skew nudge, `2>/dev/null` silences error detail but not the failure.

```bash
# In a SessionStart hook — detect skew without blocking on warnings
if msg=$(cadence-hooks doctor --quiet 2>/dev/null); [ -n "$msg" ]; then
  echo "$msg" >&2
fi
```

## Snoozing warn-main-branch

`warn-main-branch` fires once per session — but during quick wrap-up edits on a repo that's intentionally on `main`, even one nudge per session is noise. Silence it for a time-bound window per-repo:

```bash
# Default: 30 minutes
cadence-hooks guardrails dismiss-main-branch-warn

# Explicit duration: 2h, 1d, 45s, etc. Capped at 24h.
cadence-hooks guardrails dismiss-main-branch-warn --for 2h

# Longer dismissals must say why (recorded in the bypass log):
cadence-hooks guardrails dismiss-main-branch-warn --for 4h --reason "wrap-up edits on dotfiles"
```

The snooze marker lives at `<repo>/.git/cadence-hooks/main-branch-snoozed-until`, so it's per-repo and ignored by default (`.git/` is never committed). The hook's own warn output also points at the command, so it's discoverable when the warning fires.

`--reason` is **required for a dismissal longer than 1h** and nudged (but optional) at or under it. The reason, the arming session, and the expiry are written to a provenance sidecar next to the marker and recorded in the bypass log (see [Bypass provenance](#bypass-provenance) below).

For a repo where `main` is the working branch by design, set `CADENCE_ALLOW_MAIN=true` in `.claude/settings.json` to silence the warning permanently instead.

## Snoozing enforce-worktree

`enforce-worktree` hard-blocks mutations in a primary checkout of a branch-mode repo. For the legitimate one-off — committing an approved plan doc on the default branch, a hotfix the user explicitly wants in the primary tree — snooze it per-repo:

```bash
# Default: 30 minutes
cadence-hooks guardrails dismiss-enforce-worktree

# Explicit duration: 2h, 1d, 45s, etc. Capped at 24h.
cadence-hooks guardrails dismiss-enforce-worktree --for 2h

# Longer dismissals must say why (recorded in the repo-visible bypass log):
cadence-hooks guardrails dismiss-enforce-worktree --for 4h --reason "committing approved plan doc on main"
```

The marker lives at `<repo>/.git/cadence-hooks/enforce-worktree-snoozed-until` — independent of the `warn-main-branch` snooze, so unblocking the guard doesn't also silence the nudge. For a repo where `main` is the working branch by design, `CADENCE_ALLOW_MAIN=true` exempts it permanently; `CADENCE_NO_ENFORCE_WORKTREE=1` (user-global) disables the guard everywhere. The guard reads `CADENCE_ALLOW_MAIN` from the *target* repo's own tracked settings directly (`settings.local.json` overriding `settings.json`), so it applies even when the mutation crosses in from another session's repo.

This dismissal is **repo-scoped** — on a shared checkout it lowers the guard for every session, not just yours — so `--reason` is **required over 1h** (nudged at or under). The reason, arming session, and expiry land in a provenance sidecar (`enforce-worktree-snoozed-meta.json`, next to the marker) and in the bypass log below.

## Bypass provenance

Every guard bypass — a `dismiss-*` snooze being **armed**, and an operation later **riding through** an active dismissal or env switch — is recorded to `<metrics_dir>/bypasses.jsonl`, one JSON line per event. This answers *who / why / how long / which guard* for the times a guardrail was stepped outside of, which the denial log (`denials.jsonl`) can't see because a bypass is an allow.

Each line carries `event` (`armed` | `used`), the `hook` (guard) and `mechanism` (`dismiss-enforce-worktree`, `CADENCE_ALLOW_MAIN`, …), the `kind` (`dismissal` | `env_switch`), the `sessionId`, the repo **basename**, the user-authored `reason`, and the expiry. Following the denial log's **privacy-by-construction** contract, it never records a command, file path, or edited content — only which guard was bypassed, how, and why.

Writes are fully fail-open (ADR-0001): an unwritable metrics dir degrades to a no-op and never perturbs the operation or its exit code. The log lives under the metrics directory (`CADENCE_METRICS_DIR`, else `<config_dir>/metrics`).
