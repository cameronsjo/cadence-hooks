## 1. Behavior

- [x] 1.1 Add `push_locations_reading` to core's push walk, reading an unread `eval` as `UnreadEval` says, and share the operand checks with the directory walk
- [x] 1.2 Ask for `UnreadEval::StaysPut` in both of `guard-push-remote`'s walks
- [x] 1.3 Pin both readings in core (`an_unread_eval_leaves_the_push_where_it_was_only_when_asked`) and the guard's verdicts from owned and unowned checkouts (`a_push_after_an_unread_eval_is_judged_where_it_was_read`)

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased], and say there that `guard-push-remote` reads these `eval`s as `guard-gh-write` does. #1523's bullet shipped in 0.132.0, so it stays as released
- [x] 2.2 Leave docs/hooks.md as is: its guard-push-remote row names no `eval` rule
