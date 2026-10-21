## 1. Behavior

- [x] 1.1 Drop the rebase block so a `git rebase` naming `main` or `master` takes the history nudge
- [x] 1.2 Add the `git reflog` line to a rebase's nudge
- [x] 1.3 Fold the rebase tests into `every_rebase_nudges`, asserting the nudge and its `git reflog` line, and pin that other nudges carry no such line

## 2. Docs

- [x] 2.1 Drop the CLAUDE.md gotcha about the rebase block, and the stale rebase clause in prevent-secret-push's scope note
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
- [x] 2.3 Leave docs/hooks.md as is: its git-safety row names no rebase rule
