## 1. Hook

- [x] 1.1 Nudge from `warn-commit-provenance` when `git commit --no-edit` would finish a conflicted merge whose MERGE_MSG has trailers followed by `# Conflicts:`
- [x] 1.2 Stay silent for any git option before `commit`, a message or cleanup flag, a missing `MERGE_HEAD`, no trailers above the block, or a subject that only looks like a trailer
- [x] 1.3 Keep the nudge text static and leave the once-per-session provenance marker alone
- [x] 1.4 Pin it on real conflicted merges, and pin that a plain `--no-edit` lands the block and leaves nothing to redo, and that `git commit --amend --no-edit --cleanup=strip` removes the block and keeps both parents
- [x] 1.5 Say that `--cleanup=strip` also drops other lines starting with `#`, give the `git log -1 --format=%B` copy and `git commit --amend -F` route, and pin both on a real merge
- [x] 1.6 Advise an amend of the landed commit, not a second commit or a copy of MERGE_MSG, because the commit runs in the same tool call and MERGE_MSG is gone when the nudge is read; pin that git refuses the amend when the commit did not land

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
