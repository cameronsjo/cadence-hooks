## ADDED Requirements

### Requirement: Words an exec wrapper runs stay whole
`flock FILE CMD…`, BSD `script FILE CMD…`, `watch -x`, `runuser -u USER CMD…`, the words after `env -S STRING`, and tmux `new-session`, `new-window`, `split-window`, `respawn-*` or `display-popup` given several words exec their words as they are. A guard SHALL read each of those words whole, so a `-c` script behind them is one script and a quoted `;` is part of one argument.

#### Scenario: Script behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l sh -c 'cat .env'`, `script -q /dev/null sh -c 'cat .env'`, `watch -x sh -c 'cat .env'`, `env -S 'sh -c' 'cat .env'` or `tmux new -d sh -c 'cat .env'`
- **THEN** it blocks

#### Scenario: Quoted semicolon behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l echo 'x; cat .env'`, `watch -x echo 'x; cat .env'` or `runuser -u app -- echo 'x; cat .env'`
- **THEN** it exits 0

### Requirement: Words a wrapper runs under sh -c are read joined
`watch` without `-x`, tmux `run-shell` and `pipe-pane`, and a tmux shell command given as one word run a string under `sh -c`. A guard SHALL read their words joined, as the shell splits that string.

#### Scenario: watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch echo 'x; cat .env'`
- **THEN** it blocks

#### Scenario: Shell script behind watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch sh -c 'cat .env'`, which runs `sh -c cat .env` and reads no file
- **THEN** it exits 0

#### Scenario: run-shell given a second word
- **WHEN** `cadence prevent-secret-leaks` reads `tmux run-shell 'cat .env' x`, which runs `cat .env` and ignores `x`
- **THEN** it blocks
