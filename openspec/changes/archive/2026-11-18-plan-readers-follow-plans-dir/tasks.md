## 1. Behavior

- [x] 1.1 Add a read-only resolver for the repo's plans folder that applies the writer's path gate and refuses a folder resolving outside the checkout
- [x] 1.2 Point the SessionStart scan, the in-flight plan list, and `session plans` at it, and name the scanned folder in their output
- [x] 1.3 Cover the uncommitted-plan line and the commit-time unstaged-plan check, skip gitignored plans in the commit-advice guards, read the session checkout's settings from a linked worktree, and fall back on an overlong or non-literal folder (review findings)

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
