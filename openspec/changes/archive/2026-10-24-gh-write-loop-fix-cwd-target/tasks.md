## 1. Code

- [x] 1.1 Suggest the checkout's repository in a loop block only when the loop body stays in it
- [x] 1.2 Name the checkout's repository in a looped `gh api` fix only for a `repos/{owner}/{repo}/…` path
- [x] 1.3 Test a `cd` loop in both modes, a strict loop of `gh api` paths that name their own owner or repo, and a strict loop that keeps the name
- [x] 1.4 Drop the suggestion when the command names or the hook inherits `GH_REPO`, `GH_HOST` or `GIT_DIR`, or when the per-segment reading puts a gh command outside the directory
- [x] 1.5 Test those shapes in both modes, and a strict loop after a `cd` both readings follow, which keeps that repository's name

## 2. Spec and docs

- [x] 2.1 Add "Loop fix targets": the directory's repository is named only for a write gh sends there
- [x] 2.2 Point the strict-loops sentence at it
- [x] 2.3 Match the strict-loops paragraph in `docs/configuration.md` and add a CHANGELOG bullet
