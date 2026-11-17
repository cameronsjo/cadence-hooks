## Why

`guard-gh-write` blocked every `gh` write whose target it could not read: no remote, an unreadable or ambiguous `-R`, an unexpanded variable or host, a directory it could not follow, a GraphQL mutation, a `gh api` endpoint outside `repos/<owner>/<repo>`, a loop it could not prove safe, and a command too large or nested to read. Under cadence-ecosystem ADR-0046 rule 3 a guard judges what it read and allows the rest, and under rule 5 the guard was past its false-block budget (cameronsjo/cadence-hooks#1491, #1503). This is the guard-gh-write item of the phase 2 narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- A write blocks only when the guard read its target exactly and the allowlists reject it: a literal `-R`/`--repo`, a PR or issue URL argument, a literal `gh repo` positional, an inline `GH_REPO=`, a `gh api repos/<owner>/<repo>/…` path, or the remotes of the directory the write runs in (a fork included). A literal unowned owner with an expanded name (`-R "evil/$r"`) still blocks.
- Every "cannot determine target" block becomes an allow: no readable remote, an unreadable or ambiguous `-R`, an expansion in the target or host (`$GH_HOST`, #1503), an unknown directory, a runner option the guard does not model, and a command too large or too deeply nested to read.
- A `gh api` write to any endpoint other than `repos/<owner>/<repo>/…` and `orgs/<org>/…` (GraphQL, `user/…`) is allowed; the GraphQL mutation classifier goes. A `repos/…` or `orgs/…` path is read relative or behind one of these literal URL prefixes, each host compared whole: `https://api.github.com/`, `https://uploads.github.com/`, `https://<known host>/api/v3/`, `https://<known host>/api/uploads/`, and `https://api.<tenant>.ghe.com/` for a known `<tenant>.ghe.com`. gh's `{owner}`/`{repo}` placeholders are judged on the checkout's own repo, on the host the command names if it names one.
- The loop gate goes, with `CADENCE_GH_STRICT_LOOPS`. Each write in a loop body is judged as a single command.
- A `GH_HOST` the command sets other than inline on the gh word (`export GH_HOST`, a bare reassignment of an inherited one, `unset GH_HOST`, a `GH_HOST=` on a wrapper in front of a shell) is no longer read. The hook's own `GH_HOST` and `GH_REPO` still are, and so is a literal `export GH_REPO=owner/repo` the command runs in its own shell before the write: it names the target exactly and replaces the inherited value, and `unset GH_REPO` clears it. Every source of `GH_REPO` is judged only on a command gh reads it for (not the `gh repo` verbs that take an argument, and in `gh api` only for a placeholder). Other export spellings (`GH_REPO=x; export GH_REPO`, `declare -x`, `set -a`) are an accepted gap.
- A command-substitution owner with a literal name (`-R "$(cat o)/x"`) is an expansion and allows. A `cd` to a leading `$HOME` bash expands is followed as `cd ~` is. gh's `:owner`/`:repo` placeholders are judged as `{owner}`/`{repo}` are.
- A fork remote the guard cannot parse names no repo to judge; a parsed unowned remote still blocks.

Surfaces: `guard-gh-write` (PreToolUse, Bash) exit codes (2 to 0 for the shapes above), the `gh-write-target-unresolvable`, `gh-write-api-unverifiable` and `gh-write-loop-missing-repo` rule ids (no longer emitted), the loop nudge, and `CADENCE_GH_STRICT_LOOPS` (removed). No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "gh writes the guard cannot place" now allows; the loop requirements and the strict-loops switch are removed; one requirement says loop writes are judged one by one; four say which `GH_REPO` and `GH_HOST` a write inherits, which `GH_REPO` spellings are not read, and that a `$HOME` `cd` is followed.

## Impact

`crates/guardrails/src/guard_gh_write.rs`, `crates/guardrails/src/lib.rs`, `crates/core/src/shell.rs` (the directory walk reads a `$HOME` `cd` target), `openspec/specs/repo-ownership/spec.md`, `tests/failopen_telemetry.rs`, `tests/gh_host_env.rs`, `tests/deadline_failopen.rs`, `docs/configuration.md`, `CHANGELOG.md`.
