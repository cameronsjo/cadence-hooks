## 1. Behavior

- [x] 1.1 Surface the command behind `flock FILE CMD…`, BSD `script FILE CMD…`, `watch -x`/`--exec`, `runuser -u USER CMD…`, the words after `env -S STRING` and a several-word tmux shell command with `quoted_script`
- [x] 1.2 Keep `joined_script` for `watch` without `-x` and a one-word tmux shell command, which run under `sh -c`
- [x] 1.3 Pin the surfaced scripts in core (`a_wrapper_that_execs_its_words_keeps_each_word_whole`)
- [x] 1.4 Move the `flock` and `script` rows in `positional_parameters_do_not_change_the_verdict` from the accepted-cost allows to the blocks, and pin the quoted-`;` rows as allows

## 2. Docs

- [x] 2.1 Rewrite the `wrapper_utility_script` and `joined_script` comments
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased], and drop `flock` and `script` from the positional bullet's accepted costs
