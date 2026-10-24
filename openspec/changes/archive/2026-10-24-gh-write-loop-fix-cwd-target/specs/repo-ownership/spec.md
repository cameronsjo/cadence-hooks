## ADDED Requirements

### Requirement: Loop fix targets
A `guard-gh-write` loop block SHALL name the directory's resolved repository in its fix only when gh sends every looped write there: the loop body stays in the directory; every gh command in the command runs in that directory when each segment is followed on its own, so a `cd` in a subshell, a `{ …; }` group or an `if`, a `pushd`, a `cd` on a line after another command, or `env -C`/`sudo -D` moves it; the command does not name `GH_REPO`, `GH_HOST` or `GIT_DIR`, and none is set non-empty in the hook's environment; and a `gh api` write's path is `repos/{owner}/{repo}/…`. Every other fix SHALL hold a placeholder for the repository (`-R owner/repo`, `gh api repos/owner/repo/…`), since such a write goes to another repository.

#### Scenario: Strict loop that stays in the checkout
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for n in 1 2; do gh issue close $n; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R cameronsjo/tool`

#### Scenario: Loop that changes directory
- **WHEN** the command is `for d in a b; do (cd "$d" && gh release delete v1 --yes); done` in a checkout of `cameronsjo/tool`, with or without `CADENCE_GH_STRICT_LOOPS=1`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

#### Scenario: Strict loop of an api path that names its own owner
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for r in a b; do gh api -X DELETE "repos/work-org/$r/releases/1"; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `gh api repos/owner/repo/…`, not `cameronsjo/tool`

#### Scenario: Strict loop of an api path gh fills from the checkout
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for b in x y; do gh api -X DELETE "repos/{owner}/{repo}/git/refs/heads/$b"; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `gh api repos/cameronsjo/tool/…`

#### Scenario: Strict loop under a GH_REPO
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `export GH_REPO=work-org/x; for n in 3 4; do gh pr merge $n --squash; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

#### Scenario: Strict loop after a cd in a subshell
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `(cd ../other && for n in 1 2; do gh pr merge $n; done)` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

## MODIFIED Requirements

### Requirement: gh writes allowed without an ownership check
`guard-gh-write` SHALL allow `gh gist` writes and `gh repo fork` (they land under the operator's account) and `gh issue create --web`/`-w` unless the command sets `BROWSER=` or `GH_BROWSER=`. A loop of writes that name no target SHALL be allowed when its body never changes directory and the directory resolves to an owned non-fork repository; with `CADENCE_GH_STRICT_LOOPS=1` it MUST block, with the fix "Loop fix targets" names. An ownership probe past the git-probe deadline MUST allow.

#### Scenario: Gist from an unowned checkout
- **WHEN** `gh gist create notes.md` runs in a checkout whose remote is unowned
- **THEN** the hook allows

#### Scenario: Strict loops
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for n in 1 2; do gh issue close $n; done` in an owned checkout
- **THEN** the hook exits 2 and the reason suggests the resolved `-R owner/repo`
