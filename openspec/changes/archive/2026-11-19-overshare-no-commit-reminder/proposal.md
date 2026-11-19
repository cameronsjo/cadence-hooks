## Why

cameronsjo/cadence-hooks#1636: `warn-overshare` fires too often. The quiet period from cameronsjo/cadence-hooks#1648 (one reminder per session on a plain `git commit`) cut only 0.1% to 0.5% of firings, because almost every commit carries a substitution, a `cd`, a `git -C` or a chain. Commits that are not chained with a push or a post are 16% to 36% of all firings. A commit leaves the machine only when it is pushed, and the push still reminds, so the commit reminder adds nothing a later reminder does not already give.

## What Changes

- MODIFY "Overshare audit triggers": a `git commit` is no longer a trigger. A Bash command that holds a commit and also a push or a post still reminds, for the push or the post. The requirement text stays under the strict validator's 500-character limit, so the commit rule itself sits in a new requirement. OpenSpec refuses a MODIFIED block that drops a scenario, so the old "Commit nudges" scenario stays by name and now describes a commit chained with a push.
- ADD "Overshare commit exemption": a commit alone stays silent in every form unless its text spells the two words `git push` side by side (the word-pair arm of the push trigger reads them); with a push or a post it still reminds.
- ADD "Overshare push recognition": the push trigger has two arms and either one fires. The parsed arm reads a `git` command whose subcommand is `push`, past git's global options, separators, groups, subshells and `sh -c`/`eval`/substitution bodies, using the shared reader the push guards use (the reader itself is not widened: it serves blocking guards). The word-pair arm keeps `main`'s match on the two words `git push` side by side and widens it slightly: a quote, backtick, parenthesis or semicolon touching either word is ignored (nothing else is trimmed), so a push inside a quoted remote command (`ssh host 'git push'`, `ssh host "git push origin main"`, `ssh host '(cd r && git push)'`, `ssh host 'git push; git status'`) and a script interpreter running a string that holds the two words are read. The parsed arm adds the pushes the word pair never saw (`git -C dir push`, a push inside a subshell), which on `main` still reminded through the commit in the same command; the word pair keeps the pushes it did see (behind `ssh`, `docker exec`, `parallel`, in a heredoc body), so no push the word pair matched on `main` stops reminding. Documented boundary, not recognised: a push that keeps a git global option between the words behind a runner the parsed reader does not know (`docker exec c git -C d push`, `ssh host git -C d push`, `time -p git -C d push`, `parallel git -C {} push ::: a b`, a heredoc body holding `git -C d push`) a push whose `git` is glued to the word before it inside a quote (`ssh host 'cd r;git push'`), and a push that never spells the two words (`make push`, a script file). They reminded on `main` only through a commit in the same command, and are silent now. The word pair also keeps its over-triggers, and the trim adds a quoted `'git push'` to them (`echo git push`, a quoted mention, a commit message that spells the pair): an extra advisory reminder is cheap, a missed push is the defect. This widens which pushes remind, a decision recorded on the pull request.
- REMOVE the four quiet-period requirements from #1648 (the quiet period, its spending, the plain-commit shape, its key). A commit that never reminds has no reminder to spend.
- No change to which posts or file edits remind. No change to the reminder text. The leak scan (`redact-external-content`) keeps treating `git commit` as a posting command.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: one requirement modified, three added (commit exemption, push recognition, push boundary), four removed.

## Impact

- `cadence-hooks cadence warn-overshare`: a commit-only command exits 0 with no output; the session marker `overshare-commit-warned` is no longer read or written.
- `crates/cadence/src/warn_overshare.rs`, `crates/cadence/src/redact_external_content.rs` (a posting-gate variant without the commit arm), `src/dispatch.rs`, `docs/hooks.md`, `CHANGELOG.md`, `openspec/specs/external-content/spec.md`.
- `tests/overshare_quiet_period.rs` is deleted.
