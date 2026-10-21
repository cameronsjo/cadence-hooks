## ADDED Requirements

### Requirement: Words an exec wrapper runs stay whole
`flock FILE CMD…`, BSD `script FILE CMD…`, `watch -x`, `runuser -u USER CMD…`, the words after `env -S STRING`, and a tmux shell command given as several words exec their words as they are. A guard SHALL read each of those words whole, so a `-c` script behind them is one script and a quoted `;` is part of one argument. `watch` without `-x`, and a tmux shell command given as one word, run under `sh -c`, and a guard SHALL read that string as the shell splits it.

#### Scenario: Script behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l sh -c 'cat .env'`, `script -q /dev/null sh -c 'cat .env'`, `watch -x sh -c 'cat .env'`, `env -S 'sh -c' 'cat .env'` or `tmux new -d sh -c 'cat .env'`
- **THEN** it blocks

#### Scenario: Quoted semicolon behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l echo 'x; cat .env'`, `watch -x echo 'x; cat .env'` or `runuser -u app -- echo 'x; cat .env'`
- **THEN** it exits 0

#### Scenario: watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch echo 'x; cat .env'`
- **THEN** it blocks

#### Scenario: Shell script behind watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch sh -c 'cat .env'`, which runs `sh -c cat .env` and reads no file
- **THEN** it exits 0
