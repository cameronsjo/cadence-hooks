## 1. Hook

- [x] 1.1 Nudge from `warn-commit-provenance` when `git commit --no-edit` would finish a conflicted merge whose MERGE_MSG has trailers followed by `# Conflicts:`
- [x] 1.2 Stay silent for any git option before `commit`, a message or cleanup flag, a missing `MERGE_HEAD`, no trailers above the block, or a subject that only looks like a trailer
- [x] 1.3 Keep the nudge text static and leave the once-per-session provenance marker alone
- [x] 1.4 Pin it on real conflicted merges, and pin that `--cleanup=strip` removes the block and a plain `--no-edit` keeps it
- [x] 1.5 Say that `--cleanup=strip` also drops other lines starting with `#`, give the `-F` route, and pin both on a real merge

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
