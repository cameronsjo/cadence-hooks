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

## Per-repo guard config: `.claude/cadence.json`

Per-repo guard softening lives in a single `<git-root>/.claude/cadence.json`,
each guard reading its own top-level section (`terminology`, `redaction`) under a
`version: 1` envelope. Unknown top-level keys are ignored, so the file tolerates
sections a newer binary hasn't shipped yet.

> **Migrating from the pre-unification files.** Earlier versions read separate
> `.claude/terminology.json` and `.claude/redaction.json` files. Those are **no
> longer read** — run `cadence-hooks migrate-config` in the repo to merge them
> into `cadence.json` (it renames each consumed file to `*.json.migrated`), or
> hand-author `cadence.json`. `cadence-hooks doctor` warns when an orphaned
> legacy file is still present or when `cadence.json` fails to parse.

### `terminology` — soften the inclusive-terminology block

The `terminology` guard hard-**blocks** a small set of dated terms on every
`Write`/`Edit` (`whitelist`, `blacklist`, `master branch`/`master node`,
`slave`, `sanity check`, `dummy value`; `grandfathered` is a softer nudge). That
block is the right default everywhere. But some files legitimately carry these
words — a vendor ACL format named `whitelist`, an existing API field, a config
schema whose key *is* the dated term. The `terminology` section softens the
block for named files and terms.

It can only ever **remove or demote** a violation — never add one. It cannot
introduce new blocked terms, and it cannot turn the block on for a path the
built-in baseline already exempts (this repo's own source, `CLAUDE.md`,
`.claude/hooks`/`rules`). A missing file, unreadable/oversized/special file, or
invalid JSON is ignored and the block stands (fail-open, ADR-0001).

```jsonc
{
  "version": 1,
  "terminology": {
    "exemptions": [
      {
        "paths": ["config/acl.yml", "**/firewall-*.yaml", "vendor-list.yml"],
        "terms": ["whitelist", "blacklist"],
        "mode": "allow"
      },
      { "paths": ["vendor/**"] }
    ]
  }
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

### `redaction` — tune the shaped tier of `redact-external-content`

`redact-external-content` scans the body of an external post (`gh pr`/`issue`/
`release`/`gist`/`discussion` create/comment/edit, `git commit`, `tea pr`/`issue`)
for harness-internal vocabulary in four categories: `skill-id`
(`cadence:attune`), `marketplace` (plugin-cache paths), `local-path`
(`/Users/…`, `~/.claude/…`), and `harness-noun` (`tool_input`,
`tool_response`). A hit **nudges**; it never blocks. The `redaction` section
tunes this shaped tier only. The identity tier, which blocks on terms from
`~/.config/cadence/redaction.toml`, reads no repo config and cannot be softened
here.

A hit is reported when the post's destination tier is wider than the hit's
ceiling. The tiers, narrow to wide: `owned-internal`, `private-external`,
`public`. The ceiling `always` reports at every destination.

```jsonc
{
  "version": 1,
  "redaction": {
    "originAudience": "private-external",
    "categories": { "local-path": { "ceiling": "private-external" } },
    "additionalPatterns": [
      { "pattern": "Project Falcon", "replacement": "the project", "ceiling": "always" }
    ],
    "allowlist": ["cadence:writing-skills", "cadence-forge", "tool_input"]
  }
}
```

| Field | Default | Meaning |
|-------|---------|---------|
| `originAudience` | `public` | The destination tier of posts from this repo. `CADENCE_AUDIENCE` overrides it. An unknown value means `public`, which reports the most. |
| `categories` | every category at `owned-internal` | Per-category ceiling, keyed by category name: `{ "<name>": { "ceiling": "<tier>" } }`. Raising a ceiling reports that category at fewer destinations. An unknown ceiling means `owned-internal`. |
| `additionalPatterns` | none | Extra regexes to report, as `category: custom`. Each entry takes `pattern` (required), `replacement` (shown in the nudge), and `ceiling` (default `owned-internal`; `always` for a term that must never ship). A pattern that fails to compile is skipped. |
| `allowlist` | none | Entries that suppress a hit. An entry containing `:` suppresses only that exact text. A bare entry suppresses a whole skill namespace for `skill-id` hits (`cadence-forge` matches `cadence-forge:*`, not `cadence-forge-x:*`), and the exact text for every other category (`tool_input`). |

A malformed field is dropped and named in the nudge; the rest of the section
still applies. A missing, unreadable or invalid file applies no tuning.

### `body_budget` — size the gh body budgets

`guard-body-budget` measures the body a `gh` posting command would send and
compares it with a per-surface word budget. Three surfaces, each with a soft
budget (nudge), a hard budget (block), and a header cap:

| Surface | Commands | Soft | Hard | Header cap |
|---------|----------|-----:|-----:|-----------:|
| PR | `gh pr create`, `gh pr edit` | 150 | 300 | 4 |
| Comment | `gh pr review`, `gh pr comment`, `gh issue comment` | 100 | 200 | 2 |
| Issue | `gh issue create`, `gh issue edit` | 200 | 400 | 5 |

Budgets are written `[soft, hard]` in the config section and `soft:hard` in the
environment. Environment wins over config, config over the default.

```jsonc
{
  "version": 1,
  "body_budget": {
    "pr": [200, 400],
    "comment": [100, 200],
    "issue": [300, 600],
    "mode": "nudge"
  }
}
```

**Mode.** `nudge` (the default this release ships with) produces the block text
and exits 0, saying it would block once the mode flips. `block` makes the hard
ceiling a real block.

**What is measured.** Fenced code blocks, HTML comments, the `Session-Id` /
`Model` / `Harness` / `Machine` / `Co-Authored-By` trailers, the
`🤖 Generated with [Claude Code]` line, markdown link targets and inline code
spans are all stripped before counting, and cost nothing. A finding bullet — a
line like `- crates/core/src/lib.rs:42 — this is never validated` — costs no
words either; more than 15 of them nudges toward inline comments instead. Four
things nudge on any surface regardless of length: headers over the cap, session
narration (`this run`, `this session`, `round <n>`, `gate <n>`, `tranche`,
`altitude`, `receipt`, `fold in` / `folded in`, `slated`, `ground truth`), more
than 15 finding bullets, and a title over 72 characters. Em-dashes and emoji are
not measured.

A fence opens only at the start of a line, so a backtick-triple written
mid-sentence starts no code block; an unclosed fence strips to the end of the
body. A finding bullet needs a path-like token before the line number — a file
extension (`y.rs:42`) or a path separator (`src/main:12`) — so an ordinary
bullet mentioning a time (`- deploy at 09:00`) counts its words like any other.

**The escape hatch.** A body file carrying

```text
<!-- body-budget: <reason, at least five words> -->
```

downgrades a hard-ceiling block to a nudge that echoes the reason, and silences
the narration and header advisories for that call. The line is stripped before
counting. It must live in the **body file**, never in the command line: a
command string that could arm its own bypass is not a hatch. It must also live
in the body's own prose — an escape line quoted **inside a code fence** grants
nothing, so a PR or issue that shows the example does not bypass itself. The
ride-through is recorded in `bypasses.jsonl`. A command posting more than one
body records the most severe segment's mechanism and names the others in the
row's reason.

**Bounded override.** A configured hard ceiling is clamped to twice the default
(PR 600, comment 400, issue 800). A larger value — from either channel — is
refused with `(budget setting ignored: above the configured ceiling)` and the
default applies. When a raised ceiling lets through a body the *default* ceiling
would have blocked, that is recorded in `bypasses.jsonl` too, naming
`CADENCE_BODY_BUDGET_*` or `body_budget config` as the mechanism.

**Malformed values.** `soft >= hard`, a one-sided `150:`, a non-numeric value, a
zero, or a config array of the wrong length all fall back to the **default**
(not to the next tier down — quietly applying a different budget the operator
also wrote would hide the typo). Every verdict for that call downgrades to a
nudge whose first line is the parse error:

```text
CADENCE_BODY_BUDGET_PR: expected soft:hard, e.g. 150:300; got "600" — budget not applied this call
```

The same goes for a malformed `CADENCE_BODY_BUDGET_MODE`. When that downgrade
turns what would have been a **block** into a nudge, it is recorded in
`bypasses.jsonl` naming the malformed setting as the mechanism — a typo that
lets a body through is a bypass, not a footnote.

A non-default budget in effect is named in every message with its source, e.g.
`(budget 400:800 from .claude/cadence.json)`.

**Every posting segment is measured, behind any prefix.** A command that posts
more than once — `gh pr comment 1 --body ok && gh pr create --body-file long.md`
— has every body measured, and the most severe verdict decides; a segment with
no body flag is logged and the scan continues past it. Transparent prefixes
(`command`, `builtin`, `exec`, `time`, `nice`, `nohup`, `env`, a leading
`NAME=value`, and their backslash spellings) and leading shell keywords
(`if true; then gh pr create …; fi`) are peeled before the `gh` check.

**Accepted gaps.** The guard measures what the command carries, so it is silent
where there is nothing to measure — and each of these appends an `unmeasured`
row to `failopen.jsonl` rather than blocking:

- `gh pr create` with **no body flag** opens an editor; there is no body at hook time.
- An **unreadable** or **non-UTF-8** body file (a write/hook race, a permission, a binary file).
- A body assembled by a command substitution the guard cannot resolve to a literal.
- A **`gh` alias** (`gh alias set prc 'pr create'`) — the expansion lives in `gh`'s own config, which the hook does not read.
- A **`gh api`** body on **standard input** (`-F body=@-`, `--input -`), or an `--input` file that is not JSON or carries no `body` field. Every other `gh api` write to a PR, issue, comment or review endpoint (`repos/O/R/pulls[/N]`, `issues[/N]`, `…/comments`, `…/reviews`) is measured on the surface its path names: `-f`/`-F body=…`, `-F body=@file`, and `--input file.json`'s `body` field. `graphql` mutations are not read.
- A body reached through **`xargs`** (`echo x | xargs -I{} gh pr create --body …`) — the `gh` argv is assembled by another process at run time. Write the body to a regular file and call `gh` directly if you want it measured.

Two shapes are **not** silent. Each produces the block text rather than an
allow, because the content exists and `gh` will post it. Both bind only at
`mode: "block"` — under the shipping `nudge` default they print the refusal and
exit 0, so the command still reaches `gh`:

- A body file **over 1 MiB** is not read at all: `body not measured: file exceeds 1 MiB`.
- A `--body-file` path that exists but is **not a regular file** — a FIFO, or a `/dev/fd/N` process substitution such as `--body-file <(cat big.md)`: `body not measured: body file is not a regular file (FIFO or process substitution); write the body to a regular file`. Reading one would consume the stream `gh` is about to post, and a FIFO can block forever. A **missing** path is still an ordinary fail-open allow.

**Measuring a file by hand.** `cadence-hooks guardrails guard-body-budget
--measure <file> --surface pr|comment|issue` prints one JSON line — the counts,
the effective budget, and the verdict tier — reading the same environment and
per-repo config a real run does. It measures a **file**, not a command, so it
judges no title: `title_len` is always `null` and the 72-character advisory
never appears there.

**Turning it off.** `CADENCE_DISABLE=guard-body-budget` in the repo's
`.claude/settings.json` `env` block. `cadence-hooks list` shows what is
disabled.

## Environment Variables

All cadence-hooks config lives under the `CADENCE_*` prefix. `OBSIDIAN_VAULT` is
kept unprefixed because it's a cross-tool convention.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CADENCE_DISABLE` | all hooks | Comma-separated hook names to skip (e.g., `warn-main-branch,warn-overshare`). Not every name is honoured — see [What a disable request resolves to](#what-a-disable-request-resolves-to) |
| `CADENCE_BYPASS` | all hooks | Set to `1` to skip all enforcement (maintenance bypass); CLI actions stay available, and so does the status check `enforcement-status` — see [What a disable request resolves to](#what-a-disable-request-resolves-to) |
| `CADENCE_NO_FEEDBACK_FOOTER` | all hooks | Set to any non-empty value to suppress the `If this fired in error: /cadence:feedback` footer appended to hard blocks |
| `CADENCE_ALLOWED_OWNERS` | `guard-push-remote`, `guard-gh-write` | Space- or comma-separated usernames; any entry the operator did not intend widens what counts as theirs. **Weakens a protected guard** |
| `CADENCE_ALLOWED_REPOS` | `guard-gh-write` | Space- or comma-separated `owner/repo` pairs. **Weakens a protected guard** |
| `CADENCE_EXTRA_HOSTS` | `guard-push-remote`, `guard-gh-write` | Self-hosted forge hosts that bare entries (`cameron`) should match in addition to the default host. **Weakens a protected guard** |
| `CADENCE_GH_STRICT_LOOPS` | `guard-gh-write` | Set to `1` to block all looped gh writes lacking `-R`, even provably deterministic ones |
| `CADENCE_ISSUE_TRACKERS` | `warn-issue-tracker` | Comma-separated set of known ecosystem trackers (`owner/repo`) — replaces the default set (`cameronsjo/cadence`, `cameronsjo/cadence-hooks`, `cameronsjo/forgectl`, `cameronsjo/cadence-ecosystem`, plus its pre-rename alias `cameronsjo/claude-configurations`); the nudge fires only when an owned target is none of them, scoped to owners that appear in this set |
| `CADENCE_ISSUE_TRACKER` | `warn-issue-tracker` | Legacy singular override — sets a single known tracker (`owner/repo`), replacing the default set. Superseded by `CADENCE_ISSUE_TRACKERS`; still honored when the plural is unset. Also moves the owner-scope for the nudge |
| `CADENCE_BODY_BUDGET_PR` | `guard-body-budget` | `soft:hard` word budget for a PR body (default `150:300`). Hard ceiling clamped to `600`; a malformed or over-ceiling value falls back to the default and nudges — see [`body_budget`](#body_budget--size-the-gh-body-budgets) |
| `CADENCE_BODY_BUDGET_COMMENT` | `guard-body-budget` | `soft:hard` word budget for a review or comment body (default `100:200`, ceiling `400`) |
| `CADENCE_BODY_BUDGET_ISSUE` | `guard-body-budget` | `soft:hard` word budget for an issue body (default `200:400`, ceiling `800`) |
| `CADENCE_BODY_BUDGET_MODE` | `guard-body-budget` | `nudge` (default) or `block`. In `nudge` a hard-ceiling hit produces the block text and exits 0 |
| `CADENCE_GUARD_DOTFILES` | `guard-dotfiles` | Set to `1` to block direct edits to production dotfiles (clean no-op otherwise) |
| `CADENCE_ALLOW_MAIN` | `warn-main-branch`, `enforce-worktree` | Set truthy (`1`/`true`/`yes`) in a repo's `.claude/settings.json` `env` block to mark a repo where `main` is the working branch by design (dotfiles, vaults, scratchpads) — silences the main-branch warning and exempts the repo from worktree enforcement. `enforce-worktree` resolves this from process env OR the *target* repo's own tracked `.claude/settings.json`/`settings.local.json` (`settings.local` overriding `settings`) — so a cross-repo mutation into a by-design-main repo is exempt even when that repo isn't the session root |
| `CADENCE_NO_ENFORCE_WORKTREE` | `enforce-worktree` | Set truthy (`1`/`true`/`yes`) to disable the primary-checkout block everywhere — the kill switch for the proving period; prefer `CADENCE_ALLOW_MAIN` per repo |
| `CADENCE_SKIP_OVERSHARE_AUDIT` | `warn-overshare` | Set to `1` to skip the audit in repos that legitimately hold personal context (settable from any settings `env` block, like every other switch here) |
| `CADENCE_NO_DAILY_GATE` | daily-gated nudges (`platform-drift`) | Set to any non-empty value to disable the once-per-calendar-day gate so a gated nudge fires every session again — for debugging a nudge you would otherwise have to wait until tomorrow to see. The gate keys on the nudge's *content*, not just the date, so a genuinely changed state (a partial upgrade) already re-fires the same day without this |
| `CADENCE_METRICS_PRICES` | `log-commit`, `log-session`, `grade` | Path to a model price-table JSON; takes precedence over the `--prices` flag and the embedded default. Each model entry takes `inputPerMTok`, `outputPerMTok`, `cacheWritePerMTok` (5-minute TTL), `cacheReadPerMTok`, and the optional `cacheWrite1hPerMTok` (1-hour TTL) — omitting the last one falls back to `inputPerMTok * 2`, which is right only for models on the standard multiplier. An unreadable or unparseable file degrades silently to the embedded table |
| `CADENCE_METRICS_DIR` | metrics loggers | When set non-empty, the metrics root (JSONL files and the `state/` subdir live directly inside it); otherwise `<config_dir>/metrics` (honoring `CLAUDE_CONFIG_DIR`). Moving it also moves the bypass and fail-open ledgers away from where `doctor` and your tooling read them |
| `CADENCE_METRICS_DEBUG` | `log-subagent` | Set to `1` to append a `_keys` array of the raw payload's top-level keys to subagent records — surfaces schema additions across Claude Code releases |
| `CADENCE_LOG_NUDGES` | denial log | Nudge-fire rows in `denials.jsonl` are ON by default (#420); set `0`/`false`/`off` (case-insensitive) or set-but-empty to opt out. Any other value, including the legacy opt-in `1`, keeps them on. Deny/Ask rows are unconditional either way |
| `CADENCE_METRICS_STALE_DAYS` | `warn-stale` | Days of metrics-write silence before the SessionStart alarm fires and `doctor` reports staleness (default 4); zero or unparseable falls back to the default |
| `CADENCE_SESSION_STALE_MINUTES` | `session` hooks | Minutes of heartbeat silence before a session is presumed dead (default 30). The `doctor --prune` gate never reads sessions on a window shorter than the default, since peers refresh on the default cadence |
| `CADENCE_DOCTOR_PRUNE_FORCE` | `doctor --prune` | Set to `1` or `true` to bypass the live-session gate and let `doctor --prune --apply` delete orphaned plugin-cache version dirs even while peer sessions are running. The gate's refusal message names this override. For a machine that is never quiet, `--keep-newest N` and `--older-than <age>` (e.g. `7d`) bound the prune instead: they delete a dir only when it was orphaned before every live session started, and keep everything while any live session cannot say when it started (one registered or re-registered by `/clear`, `/compact`, resume or fork, or by an older binary). They see only registered sessions: one idle at the prompt past the staleness window, or one whose cwd is outside any git repo, is invisible to them, so close those first. With either bound, this override drops only the live-session check; the bounds still apply |
| `GH_AUTOCLOSE_WAIT_SECONDS` | `verify-pr-autoclose` | Maximum seconds to wait after `gh pr merge` before checking for straggler issues; returns early after 2 s once every referenced issue is closed (default 10) |
| `OBSIDIAN_VAULT` | `trash-guard`, `warn-overshare` | Absolute path to Obsidian vault — the trash guard scopes `rm` blocking to it, and the overshare audit treats it as the safe destination for personal context |
| `CADENCE_ALLOW_SOPS_DECRYPT` | `guard-sops-decrypt` | Set truthy (`1`/`true`/`yes`) to let a decrypt through; the allow is recorded as a bypass row. **Weakens a protected guard** |
| `CADENCE_ALLOW_SENSITIVE_TERMS` | `redact-external-content`, `redact-scan` | Any value except empty or `0` downgrades the identity-tier block to a nudge. **Weakens a protected guard** |
| `CADENCE_AUDIENCE` | `redact-external-content` | `owned-internal`, `private-external`, or `public` (unknown values mean `public`); a lower tier redacts less in the advisory tier |
| `CADENCE_READ_MODEL_GUARD_MODELS` | `guard-read-model` | Model list that turns the opt-in guard on; empty means off |
| `CADENCE_READ_MODEL_GUARD_MODE` | `guard-read-model` | `allow` treats the list as an allowlist; anything else denies the listed models |
| `CADENCE_READ_MODEL_GUARD_ON_UNKNOWN` | `guard-read-model` | `block` refuses reads when the session model is unknown; anything else allows |
| `CADENCE_HOOK_DEADLINE_MS` | every guard that runs git | Time budget for a guard's git probes, clamped to 1000–4500; `0` disables the deadline. A probe that times out fails open |
| `CADENCE_MARKER_DIR` | marker-keyed checks, `guard-browser-device` | Where one-time markers live. Pointing it at a directory that already holds a marker makes `guard-browser-device` allow without its first-use block. **Weakens a protected guard** |
| `CADENCE_ALLOW_SUBAGENT_FROM_MAIN` | `warn-subagent-worktree` | Set to `1`/`true`/`yes` to silence the nudge for a repo |
| `CADENCE_ALLOW_BRANCH_INTENT` | `warn-branch-intent` | Set to `1`/`true`/`yes` to silence the stale-branch nudge |
| `CADENCE_GOING_PUBLIC_TERMS` / `CADENCE_GOING_PUBLIC_IGNORE` | `warn-going-public` | Extra terms to flag, and terms to ignore, when a repo is created or made public. The work-identifiable terms in `~/.config/cadence/redaction.toml` are flagged here too, without being listed again; the ignore list cannot relieve those, only the term source's own `allow` entries can. Both are read from the session environment; an inline `VAR=… gh repo create` prefix reaches `gh`, not the hook |
| `CADENCE_NO_OUTRO_BACKSTOP` | `backstop-record`, `backstop-warn` | Set to turn off the loose-ends backstop |
| `CADENCE_NO_PERSIST_PLAN` | `persist-plan-approval` | Set to stop writing approved plans to disk |
| `CADENCE_PLANS_DIR` | `persist-plan-approval` | Read from a repo's (or a non-repo session root's) `.claude/settings*.json` `env` block, never the process env. A relative path for approved plans, default `docs/plans`; it must stay inside the checkout, and `\`, `..` or a `.git` component is refused. Empty stops the persist. A session root outside any repo, a repo with a remote outside `CADENCE_ALLOWED_OWNERS`, or a dir that escapes the checkout sends the plan to `<config_dir>/cadence/plans` instead |
| `CADENCE_HOOKS_BIN` | plugin wrapper (`run-cadence-hooks.sh`) | Absolute path to the binary the wrapper runs, instead of `cadence-hooks` on `PATH`. Whatever it names runs every hook; any value that is not an absolute path to an executable makes the wrapper inert (every hook exits 0, one notice per day) — see [Folder trust is the boundary](#folder-trust-is-the-boundary) |
| `CLAUDE_EFFORT` | every hook (latent) | A check can skip itself at a given effort level; no check does today |
| `CADENCE_FAILOPEN_DISCLOSE_MIN` | `session start` fail-open disclosure | How many fail-open events before the session-start disclosure fires; a large value hides it |
| `GH_HOST` | `guard-push-remote`, `guard-gh-write` | The host bare allowlist entries match; changing it moves which forge counts as the operator's own. **Weakens a protected guard** |

### Folder trust is the boundary

A trusted repository's `.claude/settings.json` `env` block reaches every hook process and can set any variable above. Some of those weaken a protected guard (marked **Weakens a protected guard**), and `CADENCE_BYPASS=1` switches every guard off. `CADENCE_HOOKS_BIN` or `PATH` can replace the binary itself, so no check inside it runs to report the change. A `CADENCE_HOOKS_BIN` that is not an absolute path to an executable makes the wrapper inert: every hook exits 0. `HOME`, `CLAUDE_CONFIG_DIR` and child-process variables such as `GIT_CONFIG_*`, `GIT_DIR`, `XDG_CONFIG_HOME` and `GH_CONFIG_DIR` also change what the guards see.

The control is Claude Code's folder-trust prompt: trusting a repository lets it turn these guards off. `enforcement-status` reports `CADENCE_BYPASS=1` and a refused `CADENCE_DISABLE` at session start so those two are visible, but it is not a defence against a hostile trusted repository. Decided 2026-09-28 (cameronsjo/cadence-hooks#1031, closed not planned).

### What a disable request resolves to

A name in `CADENCE_DISABLE` is not automatically honoured. Every name resolves to exactly one of three verdicts, and `cadence-hooks list`, `cadence-hooks doctor` and `cadence-hooks configure --list` all report the same partition — honoured, refused, and names matching no hook. The wording differs slightly by surface, but `configure --list` describes the **live session** too, not only what is written in the settings file: it reads both `CADENCE_DISABLE` sources — the settings file it writes and the environment it does not — plus `CADENCE_BYPASS`, and attributes each entry to the source(s) that named it (`via settings.json`, `via environment`, or `via settings.json and environment`), since only one of those two is something a reader can fix by editing a file (cameronsjo/cadence-hooks#929).

- **Disabled via CADENCE_DISABLE** (`configure --list`: `Disabled hooks:`) — honoured. The hook does not run.
- **Protected — disable refused, these still run** (`configure --list`: `Refused (protected) — named in CADENCE_DISABLE, these still run:`) — the name is a guard against irreversible harm (secret exposure, data loss, destructive git/gh/remote/vault operations), **or the detector that reports such a guard's own state**. A detector prevents no harm by itself; what it prevents is the harm happening unobserved, and switching it off does nothing except hide the report. `CADENCE_DISABLE` cannot switch either class off, because it is selective and persistent and can be set in a repository's committed `settings.json`. The hook runs anyway. Use `CADENCE_BYPASS=1` as the maintenance escape — except for the hooks named below, which it does not switch off either. Note that a repository's committed `settings.json` `env` block can set `CADENCE_BYPASS` too, and from there it switches off even this protected class, because the resolver checks the bypass before the protected refusal; the binary cannot tell a project-scope value from a user-scope one. The bypass resolver's module docs (`crates/core/src/bypass.rs`) record that channel and the other `CADENCE_*` variables it reaches.
- **Named in CADENCE_DISABLE but not a hook, so nothing was disabled** — the name matches no registered hook. Matching is exact and case-sensitive, so `Enforce-Worktree`, `enforce_worktree` and `enforce-work` are near-misses, not fuzzy matches, and they disable nothing. Run `cadence-hooks list` for the canonical names. A longer name that is itself registered (`log-session-start`) names that hook, not the shorter one.

`configure --list` now also reports `CADENCE_BYPASS`, the same way `list` and `doctor` do — the moot/bypass-exempt paragraph below applies to all three surfaces. The wizard itself still reads and writes `settings.json` only; pre-selecting an environment-sourced name in the interactive picker would let one confirmation persist a session variable into a committed file, so it deliberately consults only what is already written there.

With `CADENCE_BYPASS=1` also set, a named hook is reported as **moot** instead: the blanket bypass has already switched it off, so neither "disabled" nor "still runs" would be a true statement about it. A **bypass-exempt** hook is the exception at both ends — `CADENCE_BYPASS=1` does not switch it off, so it is reported as refused and still running, never moot.

**Bypass-exempt hooks.** `CADENCE_BYPASS=1` skips every enforcement hook except the SessionStart status check `enforcement-status`. Its entire job is to report that guards have been switched off, and `CADENCE_BYPASS=1` is a switch it reports on — bypassing it would suppress the report of the bypass itself. It reports the bypass, and any `CADENCE_DISABLE` naming a protected guard other than itself, at session start. `cadence-hooks list` and `cadence-hooks doctor` both name the exception in their bypass banner. Disabling the `cadence-guardrails` plugin is the remaining way to stop it.

`doctor` reports all four outcomes. `doctor --quiet`, the session-start route, prints only what is really off: the `CADENCE_BYPASS=1` banner and the `Disabled via CADENCE_DISABLE` line, to stdout. It stays silent when enforcement is on, so a session running with guards switched off cannot look like a clean one. Refused, moot, and unrecognized entries switch nothing off, so they appear only in the full report; `guardrails enforcement-status` reports refused protected-guard disables at session start.

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

The target host follows the command itself, on any subcommand, in two spellings:
an explicit `--hostname` (separate or `=` form) overrides an inline
`GH_HOST=... gh ...` assignment prefixed to the same command, which overrides the
hook process's `GH_HOST` and finally the `github.com` default. Host comparisons
are case-insensitive.

Below those two, an `export GH_HOST=...` in an earlier segment of the same
command string (`export GH_HOST=... && gh ...`) replaces the hook process's
`GH_HOST`. The guard cannot tell whether an earlier segment actually ran
(`false && export ...`), so every host the command may have left in place is a
candidate, and the write must be owned on each. An `unset GH_HOST` therefore adds
the default host back as a candidate rather than removing the exported one. A bare
`GH_HOST=...; gh ...` changes nothing: without `export` it stays a shell variable
that gh never sees. It does count once the variable is exported: after an earlier
`export GH_HOST`, after `set -a`, or when the hook process already carries
`GH_HOST`. An `export` inside `eval` counts like one outside it. Other forms that
can set the variable resolve to an unknown host that matches no allowlist entry,
so the write blocks:

- `declare`, `typeset`, `readonly`, or `local` naming `GH_HOST`, any nameref
  (`declare -n`), and `export -n`.
- `read`, `printf -v`, `mapfile`/`readarray`, or `getopts` writing `GH_HOST`
  or a variable whose name is not a plain literal.
- An `eval` nested more than three levels deep.
- Inside a subshell, function body, or case arm, a declaring or name-writing
  builtin next to a `GH_HOST` mention or a non-literal `NAME=`. This rule
  fails closed wherever the command position is not recognized.
- A `trap` action or an `eval` string that sets it. Both are read like a
  command. An `eval` or `trap` whose command word comes from an expansion is
  text the guard cannot read, so it also blocks: `eval "$X"`, `eval "$(…)"`,
  `` eval `…` ``. That includes `eval "$(direnv export bash)"` and
  `eval "$(ssh-agent -s)"` in front of a `-R` write.
- A `source` or `.` fed by a heredoc, stdin, or `<(…)`, when the command text
  names `GH_HOST` or declares a non-literal name.
- An `env -S`/`--split-string` prefix before gh, or a `BASH_ENV=`/`ENV=`
  assignment anywhere in the command.
- Any of those builtins, `export` included, or an `env`-style prefix before gh,
  naming a variable whose name the shell builds at expansion time
  (`GH_HOS${X}T=...`, `GH_HOS{T,}=...`).
- A value that is still a `$` expansion.
- An assignment inside `${GH_HOST:=...}` or `$((GH_HOST=...))`.

A plain mention changes nothing: `rg GH_HOST`, a commit message, or a gh
command's own `--title` or `--body`. A gh segment runs as a child process, so it
is never read for changes. A `source`d file is not read. That includes a file
written earlier in the same command, the same class as `source
.venv/bin/activate`.

**Forks** (a repo with both `origin` and `upstream` remotes) are allowed when **both** remotes belong to allowed owners — each judged against its own host. When either side is unowned, the write blocks and asks for an explicit `-R`. It offers `-R` only for an owned remote; an unowned upstream is left for the user to write to themselves.

**Loops** containing gh writes without `-R` follow a *relaxed-when-deterministic* policy: the write is allowed when the loop body provably never changes directory (no `cd`/`pushd`/`popd`/`eval`/`source`) **and** the working directory resolves to a single owned, non-fork repo. Under those conditions every iteration targets the same repo the guard verified — the same trust extended to single commands. Anything the analyzer cannot prove (directory changes inside the body, parse failures, forks, unowned directories) still blocks.

Looped `gh api` calls use the API-specific verdict rather than the generic
missing-`-R` message. GraphQL reads and the safe review-thread metadata
mutations remain allowed; other GraphQL or non-repository API mutations block
when their target cannot be ownership-verified.

Set `CADENCE_GH_STRICT_LOOPS=1` to disable the relaxation and block every looped gh write that lacks `-R` (the pre-0.12 behavior). Block messages include the resolved `-R owner/repo` fix when the working directory is owned.

### The `configure` subcommand under Claude Code

Under Claude Code (detected via `CLAUDECODE=1`), the `configure` subcommand is hidden from `--help` and refuses to run interactively — it edits `settings.json` and could silently disable guardrails. `configure --list` remains available. Run `configure` from a real terminal to change hook state.

## Auditing installed plugins

`doctor` checks the installed plugins for problems, including:

- **Shell-expansion bugs** (exit 2): single-quoted `'${CLAUDE_PLUGIN_ROOT}'` in a `hooks.json` won't expand in `/bin/sh` — the harness reports a silent non-blocking failure and nothing surfaces to the user.
- **Subcommand skew** (exit 1): a `hooks.json` hook references a subcommand this binary doesn't have — typically a plugin built for a newer version of cadence-hooks.
- **Rules drift** (exit 1): the deployed `<config dir>/rules/cadence/cadence-rules.md` differs from the pinned `cadence` plugin's `rules/cadence-rules.md`. The fix names both paths so you can `diff` them first. Removing the `managed by cadence` line from the deployed copy marks it as yours and silences the check.
- **Inert permission rows** (warning): a `Bash(...)` row in `permissions.deny` or `permissions.ask` (user `settings.json` and `settings.local.json`, and the current project's `.claude/` pair) that can never match. Two classes measured on Claude Code 2.1.273: a `*` before a trailing `:*` (`Bash(rm /var/log/*:*)`) is not a glob (a `*` in the space-wildcard form, `Bash(git * main)`, is); and a row starting with a redirect (`Bash(> path)`) never fires, because redirect targets are checked against `Edit` rules. The fix is to spell the literal forms or move a redirect to an `Edit(...)` row. `allow` rows are not reported. The lint only reads. A row it does not report is not thereby known to fire on a compound command (`cd x && rm -rf y`): that behavior is unverified and needs a live-session probe (#578).

By default the scan is driven by `~/.claude/plugins/installed_plugins.json`, so only **active** installs are checked (the cache keeps stale plugin versions around — scanning those would report skew in code that no longer runs). With `--root`, the given tree is walked recursively, so both flat layouts (`<root>/<plugin>/hooks/hooks.json`) and the real cache layout (`<root>/<marketplace>/<plugin>/<sha>/hooks/hooks.json`) work.

```bash
# Scan active installs from ~/.claude/plugins/installed_plugins.json
cadence-hooks doctor

# Audit a specific tree (handy in CI before publishing a plugin)
cadence-hooks doctor --root ./plugins

# Preflight mode for SessionStart hooks — blockers only, non-zero only on errors
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

**`--quiet` mode** is the SessionStart preflight shape. It reports only **blockers**: findings that mean a wired hook is not running. Those are shell-expansion errors, a wiring that names a subcommand or namespace this binary does not have (in a plugin `hooks.json`, in `settings.json`, or in a plugin removed upstream), a `group` entry the binary cannot parse or run, a hook whose CLI dependency is not on `PATH`, a plugin that ships hooks but has no `enabledPlugins` entry, and a pinned plugin cache dir that is missing or empty. A plugin set to `false` in `enabledPlugins` never blocks. Everything else — hook latency, stale telemetry, orphaned cache dirs, identity — waits for a full `cadence-hooks doctor` run, which `cadence:outro` makes at session end.

- **No blockers:** no output, exit 0.
- **Blockers:** one fixed `<cadence-system-message>` envelope on stdout, with counts only (`N error(s) and M inert hook wiring(s)`) and the upgrade hint when a subcommand is missing. It prints at most once a day per distinct blocker set. Exit 2 when any blocker is an error, else 0 (so a `set -euo pipefail` script won't abort on inert wiring alone).
- **Configuration errors** (`$HOME` unset, no manifest and no plugin cache): the same envelope as one error on stdout, the detail on stderr, exit 2.
- **Enforcement really off:** the `CADENCE_BYPASS=1` banner and the `Disabled via CADENCE_DISABLE` line ([What a disable request resolves to](#what-a-disable-request-resolves-to)) go to stdout ahead of everything above and do not affect the exit code.

Everything the session must see goes to **stdout**, because the documented wiring below discards stderr. The envelope never carries plugin-supplied text: finding specifics stay in the full report.

```bash
# In a SessionStart hook — surface blockers without failing the hook
# stdout at exit 0 becomes session context; stderr does not reach the model.
if msg=$(cadence-hooks doctor --quiet 2>/dev/null); [ -n "$msg" ]; then
  printf '%s\n' "$msg"
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

`enforce-worktree` hard-blocks mutations in a primary checkout of a branch-mode repo — but only the **session's own** checkout. A file write (`Edit`/`Write`/`MultiEdit`) into a *different* repo than the session's cwd is a foreign artifact-drop (a note into an Obsidian vault, a field report into `~/Documents`, a file in a sibling repo) and is out of scope — allowed (#238). The `git commit` arm is not so scoped: committing into a foreign primary still blocks (#224), so you can drop a file into another repo but not persist it to that repo's `main` without an escape hatch. For the legitimate one-off in your own checkout — committing an approved plan doc on the default branch, a hotfix the user explicitly wants in the primary tree — snooze it per-repo:

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
