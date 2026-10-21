## 1. Behavior

- [x] 1.1 Remove the positional-parameter block and its helpers, keeping the shared shell option reader
- [x] 1.2 Flip the positional block tests to allows, keeping literal reads blocked behind an option cluster and behind the peeled runners
- [x] 1.3 Record the `parallel`, `fd -x`/`-X` and `bash -s` rows as an accepted cost in `positional_parameters_do_not_change_the_verdict`

## 2. Docs

- [x] 2.1 Drop CLAUDE.md's commit-message gotcha, which no shape triggers any more
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased], naming which runners still block and which do not
- [x] 2.3 Leave docs/hooks.md as is: its prevent-secret-leaks row names no positional rule
