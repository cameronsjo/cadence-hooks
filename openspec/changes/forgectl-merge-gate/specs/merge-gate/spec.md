## ADDED Requirements

### Requirement: Merge gate reads forgectl's snapshot
`cadence-hooks guardrails guard-gh-merge` SHALL act only on a `gh pr merge` that the shared merge matcher pins to one PR number in the repository of the checkout's `origin` remote on github.com. For that PR it SHALL run `forgectl events state <owner/repo#N> --json` and judge the answer only when it names the same PR.

#### Scenario: PR in another repository
- **WHEN** the command is `gh pr merge 7 -R someone/else` and origin is `o/r`
- **THEN** the hook exits 0 with no output and runs no forgectl command

### Requirement: Merge gate blocks on facts it read
With a snapshot of an open PR polled under 10 minutes ago, the gate SHALL block when the check rollup at the head is `FAILURE`, `ERROR`, `PENDING` or `EXPECTED`; when no cadence-review marker counts at the head; when the markers at the head sum to `crit` > 0; when the PR carries `CITL`; or when `--match-head-commit` names a SHA other than the head. The block message SHALL name each such fact on its own line. A PR with no check rollup SHALL NOT be blocked for its checks.

#### Scenario: Red checks
- **WHEN** the snapshot says checks at the head are `FAILURE` and a clean marker counts at the head
- **THEN** the merge is blocked and the message says `checks at the head are FAILURE`

### Requirement: Merge gate is on the confirm tier
A block SHALL pass once on an identical second attempt in the same session, recorded as `confirmed`, keyed on the PR and the whole command.

#### Scenario: Deliberate retry
- **WHEN** the same `gh pr merge 7 --merge` is retried right after its block
- **THEN** it is allowed once

### Requirement: Merge gate allows what it cannot read
The gate SHALL allow with no output for `--auto` or `--disable-auto`, a PR that is not open, no forgectl on PATH, no snapshot (forgectl exits 3), or a timeout. It SHALL allow with a nudge naming `forgectl events poll --once` when the snapshot is older than 10 minutes, has an unreadable time or check state, or does not parse.

#### Scenario: Stale snapshot
- **WHEN** the snapshot says checks failed but was polled 11 minutes ago
- **THEN** the merge is allowed and a nudge says the checks were not checked
