## Why

Merging safely is a prose rule today: chief-of-staff's `merge-watcher.sh` and the cloud-issue-run skill tell the model to check that the head is unchanged, checks are green at the head, a clean cadence-review marker sits at the head, and no CITL step is pending. `warn-gh-merge-preflight` only prints a static checklist. Nothing reads those facts before `gh pr merge` runs.

The operator asked for one always-on layer where nothing depends on the model remembering to run a script. forgectl's new `events` poller (cameronsjo/forgectl, OpenSpec change `pr-events`) keeps a typed snapshot of each watched PR. This change reads it at the two moments that matter: when a session opens a PR, and when it merges one.

Policy: cadence-ecosystem ADR-0046, amendment 2026-11-27 (the merge gate joins rule 2's kinds, on the confirm tier). Plan: "Making cadence more deterministic" (2026-11-27). Tracking: CAM-1262.

## What Changes

- **New guard `guardrails guard-gh-merge`** (PreToolUse Bash). On a `gh pr merge` the shared matcher pins to one PR in origin's github.com repo, it runs `forgectl events state <owner/repo#N> --json` and blocks, on the confirm tier, when a snapshot under 10 minutes old says: checks at the head are not `SUCCESS`; no cadence-review marker from the operator's login counts at the head, or one says `crit` > 0; the PR carries `CITL`; or `--match-head-commit` names another SHA. It allows `--auto`, a PR that is not open, and anything it cannot read; with forgectl present but no fresh snapshot it nudges once with the command that would let it check.
- **New hook `guardrails watch-created-pr`** (PostToolUse Bash). After `gh pr create` prints exactly one github.com PR URL, it runs `forgectl events watch --session <session_id> <owner/repo#N>`, so the c3 mod hands that session its checks, reviews and merge. Silent; any failure changes nothing.
- Both enter `PENDING_WIRING_HOOKS` until the cadence-guardrails `hooks.json` entries land in the cadence monorepo.

## Capabilities

### New Capabilities

- `merge-gate`: `guard-gh-merge`.

### Modified Capabilities

- `pr-workflow`: adds `watch-created-pr`.

## Impact

- New spawns: `forgectl events state` before a matched merge, `forgectl events watch` after a PR create, each bounded by the shared tool cap (2 s). No GitHub call from either hook.
- Merge method is not checked: GitHub refuses a method the repository does not allow, so a block there would add nothing.
