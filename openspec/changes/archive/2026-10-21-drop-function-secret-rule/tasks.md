## 1. Behavior

- [x] 1.1 Remove the function-definition block and the definition search behind it (raw text, resolved segments, `BASH_FUNC_` imports, parenthesis substitution)
- [x] 1.2 Flip the function block tests to allows, keeping literal reads in a function body blocked
- [x] 1.3 Keep the exit-2 checks that a read at the end of a long command is still reached (1000 substitution assignments, a long value before `bash -O extglob -c 'cat .env'`)

## 2. Docs

- [x] 2.1 Drop the function shape from CLAUDE.md's commit-message gotcha
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
- [x] 2.3 Leave docs/hooks.md as is: its prevent-secret-leaks row names no function rule
