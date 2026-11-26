## Why

cameronsjo/cadence-hooks#1636: `warn-overshare` fires too often. The quiet period from cameronsjo/cadence-hooks#1648 (one reminder per session on a plain `git commit`) cut only 0.1% to 0.5% of firings, because almost every commit carries a substitution, a `cd`, a `git -C` or a chain. Commits that are not chained with a push or a post are 16% to 36% of all firings. A commit leaves the machine only when it is pushed, and the push still reminds, so the commit reminder adds nothing a later reminder does not already give.

## What Changes

- MODIFY "Overshare audit triggers": a `git commit` is no longer a trigger. A Bash command that holds a commit and also a push or a post still reminds, for the push or the post. The requirement text stays under the strict validator's 500-character limit, so the commit rule itself sits in a new requirement. OpenSpec refuses a MODIFIED block that drops a scenario, so the old "Commit nudges" scenario stays by name and now describes a commit chained with a push.
- ADD "Overshare commit exemption": a commit stays silent in every form when its command text never contains the word `push`; with a push or a post it still reminds.
- ADD "Overshare push recognition": the push trigger has two arms and either fires. The parsed arm reads a `git` command whose subcommand is `push`, past git's global options, separators, groups, subshells and `sh -c`/`eval`/substitution bodies, using the shared reader the push guards use (the reader itself is not widened: it serves blocking guards). The word-pair arm is `main`'s match on the two words `git push` side by side, with no trimming. The parsed arm adds the pushes the word pair never saw (`git -C dir push`, `git push;`, a subshell), which on `main` reminded only through the commit in the same command.
- ADD "Overshare commit that spells push": a commit reminds whenever its command text contains the substring `push` anywhere (case-sensitive, raw text, no parsing), using `main`'s own per-segment commit match. This is what makes the guarantee: every command that reminded on `main` and is silent now is a commit that never spells `push`, so a push after a commit that spells the word (a quoted remote command, a runner, a heredoc, `make push`) still reminds in any shape. The one boundary: a push that never spells the word (a make target with another name, a script file) after a commit is silent. A commit whose message or path contains `push` reminds, as on `main`. Earlier drafts listed push shapes and then trimmed punctuation off the word pair; each left another shape that reminded on `main` and went silent, so the shape list and the trim are gone.
- REMOVE the four quiet-period requirements from #1648 (the quiet period, its spending, the plain-commit shape, its key). A commit that never reminds has no reminder to spend.
- No change to which posts or file edits remind. No change to the reminder text. The leak scan (`redact-external-content`) keeps treating `git commit` as a posting command.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: one requirement modified, three added (commit exemption, push recognition, commit that spells push), four removed.

## Impact

- `cadence-hooks cadence warn-overshare`: a commit-only command exits 0 with no output; the session marker `overshare-commit-warned` is no longer read or written.
- `crates/cadence/src/warn_overshare.rs`, `crates/cadence/src/redact_external_content.rs` (a posting-gate variant without the commit arm), `src/dispatch.rs`, `docs/hooks.md`, `CHANGELOG.md`, `openspec/specs/external-content/spec.md`.
- `tests/overshare_quiet_period.rs` is deleted.
