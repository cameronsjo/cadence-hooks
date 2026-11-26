## Why

Security review 4 of cameronsjo/cadence-hooks#1659 (cameronsjo/cadence-hooks#1658) found that on Windows a confirmation earned in one primary checkout carried into another. After a blocked plain `git commit` in checkout A, `export GIT_DIR="<B's native path>\.git"; git commit -am x` passed on A's confirmation. `git_exports` unescaped the double-quoted value, so it read as a relative path that resolved to A, while Git Bash keeps backslashes inside double quotes and commits into B. A link made by `ln` in the same command has the same shape. This is the third time an earlier part of a command moved the target under a key that did not see it; rounds 1 and 2 moved `guard-op-vault-scan` and `guard-held-close` to the whole command. The owner's decision: `enforce-worktree`'s Bash key becomes the repository and the whole command too.

## What Changes

- MODIFY `worktree-enforcement` Confirmed retry snoozes enforce-worktree: a Bash block is keyed by the judged repo and the whole command, normalized for spaces and tabs; Edit and Write stay keyed by the repo and the file.
- ADD `worktree-enforcement` Bash confirmations key on the whole command: only the identical command in the same checkout pairs; the confirm is per command, and the snooze it arms is per repository.
- `git_exports` passes an exported `GIT_DIR`/`GIT_WORK_TREE` value raw, as the `GIT_DIR=` prefix reader does, so `shell_dir_value` judges both the same way. From a linked worktree, a double-quoted export into a primary now blocks on its first attempt (it allowed on `main`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `worktree-enforcement`: Confirmed retry snoozes enforce-worktree modified; Bash confirmations key on the whole command added.

## Impact

- `crates/guardrails/src/enforce_worktree.rs`: `confirm_action`, the `git_exports` value reader, tests.
- `docs/configuration.md`, `docs/hooks.md`, `CHANGELOG.md`, the `core::confirm` module doc.
- Left for a follow-up: `note_ln` (`crates/guardrails/src/enforce_worktree/commit_gaps.rs`) still unescapes a quoted native link path; the whole-command key keeps a confirmation from following it, but the first-attempt gap from a linked worktree predates this change.
