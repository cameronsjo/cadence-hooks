## Why

`guard-gh-write`'s loop gate blocked `for r in alpha beta; do gh repo archive "cameronsjo/$r" --yes; done` from any directory that does not resolve to an owned repository, and asked for `-R`. `gh repo archive` has no `-R` flag: it takes the repository as its argument, as `delete`, `edit` and `create` do. The only way through was to unroll the loop. The same command outside a loop was allowed, because the per-segment check already reads that argument and judges its owner (cameronsjo/cadence-hooks#1491).

## What Changes

- In a loop the parser reads, a `gh repo archive`, `delete`, `edit` or `create` whose repository argument spells out its owner (and any host) names its target, as `-R` does. The loop gate no longer holds it to the directory rule, so the directory, a `cd` in the loop body and `CADENCE_GH_STRICT_LOOPS=1` do not matter for it. The per-segment check still judges its owner against the allowlist, so `gh repo archive "evil/$r"` still blocks.
- A variable owner (`"$o/$r"`), a bare name, a URL or no argument keeps today's verdict.
- Under `gh repo create` (and `new`), `--template` and `-p` take a value, the template. The argument scan stepped over no value for them, so it took the template for the target: `gh repo create --template cameronsjo/tpl work-org/x` judged `cameronsjo/tpl` and allowed, and a loop of them would now have allowed from any directory. The scan now steps over that value under `create` only; under `gh repo edit`, `--template` stays a boolean.
- For those four verbs, the loop block and the single-command fixes name the repository argument (`gh repo archive owner/<repo>`) instead of `-R`. `gh repo rename` keeps `-R`: its argument is the new name.

The everyday corpus scored at head against `origin/main` shows no new block outside the template rows: `gh repo create --template cameronsjo/tpl work-org/x` moves to block, and `gh repo create --template work-org/tpl cameronsjo/x` to allow.

Surfaces: `guard-gh-write` (PreToolUse, Bash), its exit code (2 to 0 for the loops above), the loop block text and its structured `fix`, and the single-command `fix` for those four verbs. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "gh writes allowed without an ownership check" and "gh writes in a loop the parser reads" count a literal-owner repository argument on those four `gh repo` verbs as a target, and the reason names the argument for them. "gh write to a repository the operator does not own" gains a scenario for a repository created from a template.

## Impact

`crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
