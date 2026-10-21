## Why

`flock FILE CMD…`, BSD `script FILE CMD…`, `watch -x`, `runuser -u USER CMD…`, the words after `env -S STRING`, and a tmux shell command given as several words (`new-session`, `new-window`, `split-window`, `respawn-*`, `display-popup`) exec their words as they are. Core joined those words with their quotes stripped, so `flock /tmp/l sh -c 'cat .env'` reached the guards as `sh -c cat .env`, a script of `cat` with `$0` set to `.env`, and `prevent-secret-leaks` allowed it. The same join split `flock /tmp/l echo 'x; cat .env'` into two commands, a false block. cameronsjo/cadence-hooks#1468 recorded the hidden read as an accepted cost and named this as the fix. Part of cameronsjo/cadence-hooks#1443 (ADR-0046 phase 2).

## What Changes

- Core keeps each word whole when it surfaces the command behind these wrappers, as it already did for `find -exec`. Every guard that reads a wrapped command gets the same reading.
- `flock /tmp/l sh -c 'cat .env'`, `script -q /dev/null sh -c 'cat .env'`, `watch -x sh -c 'cat .env'`, `env -S 'sh -c' 'cat .env'` and `tmux new -d sh -c 'cat .env'` block again.
- `flock /tmp/l echo 'x; cat .env'`, `watch -x echo 'x; cat .env'` and `runuser -u app -- echo 'x; cat .env'` no longer block.
- `watch` without `-x` hands its words to `sh -c` as one string, so it is read as before: `watch echo 'x; cat .env'` blocks and `watch sh -c 'cat .env'`, which reads no file, passes. A tmux shell command given as one word runs under `sh -c` too.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `command-reading`: adds "Words an exec wrapper runs stay whole".
- `secret-reads`: "A script the guard does not read is allowed" no longer names `flock FILE CMD…` or BSD `script FILE CMD…`.

## Impact

- `cadence-hooks-core` `crates/core/src/shell.rs`: `flock_command`, `script_command`, `watch_command` (with `-x`/`--exec`), `su_script` (`runuser -u`), `env_split_string_script` and `tmux_command_script` (several words) use `quoted_script` instead of `joined_script`.
- Every Bash-reading guard sees the change. Scored on the everyday corpus (303 rows, bare and behind each of the five wrappers, across 14 guards): no new block; 15 nudges from `git-safety` on `<wrapper> eval "$(…)"` drop, matching the bare `eval "$(…)"`.
- No env var, config key, ledger, marker file or hooks.json change.
