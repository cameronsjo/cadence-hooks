---
status: "done"
next: "none — #711 closed without merging, archive/worktree-b74fc92c deleted (tip b74fc92c recoverable at refs/pull/711/head)"
pr: "cameronsjo/cadence-hooks#864"
updated: "2026-09-06"
branch: "docs/711-close-verdict"
body_sha256: "4d23b1e304f68f1b0c2f8c3498d21c36d5f890a43f5ab96e7e0ab886a67f7f98"
session: "iron-chisel"
session_id: "1876a420-b0bd-421e-8e91-7043657803ae"
model: "claude-opus-5"
harness: "claude-code 2.1.263"
machine: "cf6e768835c7"
approved_in: "frost-anthem"
approved_session_id: "7c1eb04b-974c-4476-b459-93498e673d20"
---

# cadence-hooks#711 — close with evidence, do not merge

## Context

`cameronsjo/cadence-hooks#711` is a **shim PR** opened by the 2026-08-16 branch-cleanup sweep over the orphan branch `archive/worktree-b74fc92c`. The sweep opened these so each orphan got an explicit merge/close decision instead of silent deletion. It carries no review and no verdict; the goal is to settle it.

**The finding that decides it: the branch's content is already on `main`, and merging would only conflict.** The branch tip is from 2026-07-28; `main` is now `7cfae56`. Because PR #500 squash-merged the same content under a rewritten SHA, git sees two independent edits to the same lines: `git merge-tree --write-tree --name-only origin/main origin/archive/worktree-b74fc92c` returns rc=1 with four content conflicts (`CHANGELOG.md`, `prevent_secret_leaks.rs`, `redact_external_content.rs`, `shell.rs`), and resolving them would add ~698 duplicate lines for zero behavior change.

> **Retracted, 2026-09-06.** This section originally claimed merging would revert ~39,700 lines of `main` including three shipped guards and two test suites, reading `git diff origin/main origin/archive/worktree-b74fc92c` (156 files, +5,133/−39,733) as if it described a merge. **That was wrong** — a tip-to-tip diff is not a merge preview. Git merges three-way from the merge-base `c264853`, where the branch's own diff is `4 files changed, 988 insertions(+), 93 deletions(-)`. Every file named is present on `origin/main` at `7cfae56`. See `## Deviations`.

The work itself is not lost. It already landed.

## Evidence — the branch's content is on `main`

The branch is the worktree copy of `fix/redact-segment-scope`, the fix for issue #475 (`guard-gh-write`: backslash-newline continuation drops the repo target into an unjudged segment).

| Claim | Proving command | Result |
|---|---|---|
| All 10 substantive commits are in PR #500's head | `git log --oneline refs/tmp/pr500..origin/archive/worktree-b74fc92c` | only `b74fc92` remains — a content-free `Merge origin/main into HEAD` |
| PR #500 landed on `main` | `git merge-base --is-ancestor 44e823e origin/main` | exit 0 (squash-merged 2026-07-28T17:20:48Z) |
| Every symbol the branch adds exists on `main` | 49 added `fn`/test names extracted from the branch diff, each `git grep -F` against `origin/main -- '*.rs'` | **0 missing** |
| #475 is settled | `gh issue view 475` | `CLOSED` 2026-07-28T17:20:50Z, 2 s after #500 merged |

The 49 checked names cover every behavior in the branch's commit subjects: heredoc bodies read as data, ANSI-C quoting, continuation joining, segmenter/tokenizer agreement, substitution spans, and redaction body extraction scoped to the posting segment.

`git branch -r --contains b74fc92c` returns only the archive branch itself — expected under squash merge, and the reason a SHA-ancestry check alone cannot settle this. Content is the authority here, not ancestry.

## Plan

1. [x] **Post the verdict as a PR comment on #711** — the table above, plus the merge-conflict finding, so the record survives the close.
2. [x] **Close #711** (`gh pr close 711`). No merge.
3. [x] **Delete `archive/worktree-b74fc92c`.** *(Amended 2026-09-06 — the plan originally deferred this to Cameron; Cameron ruled to clean it up. The content is proven present on `main`, so the branch carries nothing unique.)*
4. [x] **Report the verdict to `russet-scale`** via SendMessage.

No source files change. No changelog entry is owed (no consumer-visible effect). No polish pass is owed (no code change).

## Panel

Panel: none — verdict is close-with-evidence; the deliverable is a PR comment and a close, with no code, plan-contract, or security-control change for a seat to review.

## Alternatives declined

- **Merge #711 as-is** — four content conflicts to land content already on `main`, adding ~698 duplicate lines for zero behavior change. Declined on the `merge-tree` result. *(Amended: originally declined on a misread tip-to-tip diff — see the retraction above.)*
- **Rebase or merge `main` up into the archive branch, then merge** — same four conflicts, resolved manually instead of at merge time. Zero net change for real effort.
- **Cherry-pick the branch's fixes onto a fresh branch off `main`** — the contingency `russet-scale` named, correctly gated on finding an unlanded fix. The 0-missing symbol sweep refutes the premise, so it does not apply.
- **Delete the branch silently** — what the 2026-08-16 sweep was built to prevent.

## Verification

Anyone can re-derive the verdict from the cadence-hooks checkout:

```bash
git fetch origin refs/pull/500/head:refs/tmp/pr500 --force
git log --oneline refs/tmp/pr500..origin/archive/worktree-b74fc92c   # expect: only b74fc92 (a merge)
git merge-base --is-ancestor 44e823e origin/main && echo LANDED
```

After closing: `gh pr view 711 --repo cameronsjo/cadence-hooks --json state` returns `CLOSED`, and the comment is on the PR.

## Deviations

- **The plan's "merging would be destructive" finding was wrong and was retracted.** It read `git diff origin/main origin/archive/worktree-b74fc92c` (156 files, +5,133/-39,733) as describing a merge. That is a tip-to-tip diff; git merges three-way from the merge-base `c264853`, where the branch's diff is `4 files changed, 988 insertions(+), 93 deletions(-)`. `guard_sops_decrypt.rs`, `guard_rm_liveness.rs`, `warn_unreviewed_ready_flip.rs`, and `tests/lint_plan_shape.rs` are all present on `origin/main` at `7cfae56` and were never at risk. Caught by `russet-scale`, which had already merged three sibling shims from the same 08-16 sweep with `--merge` and observed main intact.
- **Replaced with a measured finding.** `git merge-tree --write-tree --name-only origin/main origin/archive/worktree-b74fc92c` returns rc=1 with four content conflicts (`CHANGELOG.md`, `prevent_secret_leaks.rs`, `redact_external_content.rs`, `shell.rs`); resolving them adds ~698 duplicate lines for zero behavior change. Merging conflicts, it does not revert.
- The PR comment was posted with the wrong finding, then edited to carry an explicit retraction rather than silently dropping it.
- `main` moved during execution: the plan cited `e2c35c7` (0.94.0), live was `7cfae56`.
- **Step 3 reversed by operator ruling.** The plan deferred deleting `archive/worktree-b74fc92c` to Cameron; Cameron ruled to delete it in the same pass. Safe because the content is proven present on `main` and the evidence now lives on the PR comment, which survives the branch — that is the thing the 2026-08-16 sweep was protecting, not the ref itself.

## Learnings

- A tip-to-tip `git diff <main> <old-branch>` never describes a merge. The honest reader is `git merge-tree --write-tree`, which is non-destructive and reports the real conflict set.
- Verified outcome: PR #711 `CLOSED`, not merged; branch `archive/worktree-b74fc92c` deleted.
- **Recovery pointer.** The deleted branch tip was `b74fc92c9977d233790715bb9edbdb4fc17e8348`. GitHub keeps a closed PR's head reachable at `refs/pull/711/head`, so the branch is restorable with `git fetch origin refs/pull/711/head:archive/worktree-b74fc92c` even after the ref is gone.
