## Why

`guard-gh-write` blocked every `gh` write whose target it could not read: no remote, an unreadable or ambiguous `-R`, an unexpanded variable or host, a directory it could not follow, a GraphQL mutation, a `gh api` endpoint outside `repos/<owner>/<repo>`, a loop it could not prove safe, and a command too large or nested to read. Under cadence-ecosystem ADR-0046 rule 3 a guard judges what it read and allows the rest, and under rule 5 the guard was past its false-block budget (cameronsjo/cadence-hooks#1491, #1503). This is the guard-gh-write item of the phase 2 narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- A write blocks only when the guard read its target exactly and the allowlists reject it: a literal `-R`/`--repo`, a PR or issue URL argument, a literal `gh repo` positional, an inline `GH_REPO=`, a `gh api repos/<owner>/<repo>/…` path, or the remotes of the directory the write runs in (a fork included). A literal unowned owner with an expanded name (`-R "evil/$r"`) still blocks.
- Every "cannot determine target" block becomes an allow: no readable remote, an unreadable or ambiguous `-R`, an expansion in the target or host (`$GH_HOST`, #1503), an unknown directory, a runner option the guard does not model, and a command too large or too deeply nested to read.
- A `gh api` write to any endpoint other than `repos/<owner>/<repo>/…` (GraphQL, `orgs/…`, `user/…`) is allowed; the GraphQL mutation classifier goes.
- The loop gate goes, with `CADENCE_GH_STRICT_LOOPS`. Each write in a loop body is judged as a single command.
- `export GH_HOST`/`export GH_REPO` earlier in the command, and a `GH_HOST=` on a wrapper in front of a shell, are no longer read. The hook's own `GH_HOST` and `GH_REPO` still are.
- A fork remote the guard cannot parse names no repo to judge; a parsed unowned remote still blocks.

Surfaces: `guard-gh-write` (PreToolUse, Bash) exit codes (2 to 0 for the shapes above), the `gh-write-target-unresolvable`, `gh-write-api-unverifiable` and `gh-write-loop-missing-repo` rule ids (no longer emitted), the loop nudge, and `CADENCE_GH_STRICT_LOOPS` (removed). No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "gh writes the guard cannot place" now allows; the loop requirements and the strict-loops switch are removed; one requirement says loop writes are judged one by one.

## Impact

`crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
