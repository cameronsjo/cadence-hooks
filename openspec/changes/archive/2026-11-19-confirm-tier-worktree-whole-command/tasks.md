## 1. Key and reader

- [x] 1.1 `confirm_action`: Bash keys on the judged repo and `whole_command_action`; Edit and Write keep the repo and the file
- [x] 1.2 `git_exports` passes the exported value raw (only the name is unescaped)

## 2. Evidence

- [x] 2.1 Reproduced red first: the macOS stand-in (a primary whose directory name holds a backslash) passed the quoted export on A's confirmation
- [x] 2.2 Tests: the quoted export (macOS stand-in and a Windows native path), a link made in the command, an identical retry, a spacing-only retry, a changed commit message, a first-attempt quoted export from a worktree
- [x] 2.3 Staged breaks: the repository-only key, and the old export reader
- [x] 2.4 `scripts/confirm-tier-compare.py` re-run

## 3. Docs

- [x] 3.1 `docs/configuration.md`, `docs/hooks.md`, `CHANGELOG.md`
