## Why

cadence-hooks tracked intent in dated `docs/plans/` files and decisions in `docs/adr/`, but nothing said what the shipped binary does today: a done plan is history, `docs/hooks.md` is a catalog, and the precise verdicts lived only in the code and its tests. Moving to OpenSpec gives every capability a living spec that each change updates as it lands (cameronsjo/cadence-hooks#1446), the same move cameronsjo/forgectl#1306 made.

## What Changes

- Add `openspec/` with the spec-driven schema and a project context (`openspec/config.yaml`).
- Record the shipped behavior of every hook and CLI action as baseline capability specs, read from the code and checked against `docs/hooks.md`. The guard specs describe behavior after the phase 1 loosening (cameronsjo/cadence-hooks#1445, cadence-ecosystem ADR-0046).
- Install the OpenSpec skills and `/opsx:*` commands for Claude Code (`.claude/`) and Codex (`.agents/`), rewritten to call the pinned CLI.
- Pin the OpenSpec CLI in `scripts/openspec/` (lockfile with integrity hashes) behind `scripts/openspec.sh`, and run `validate --all --strict` in CI.
- Freeze `docs/plans/`: a test rejects a plan dated after 2026-10-20. Plans already there finish in place.
- No change to the binary's behavior.

## Capabilities

### New Capabilities

- `hook-protocol`: stdin payloads, exit codes, fail-open, deadlines, remote policy, bypass and disable switches, grouped runs, and the audit logs.
- `command-reading`: how Bash guards read a command line and what they do with the parts they cannot read.
- `cli`: `list`, `manifest`, `try`, `configure`, `migrate-config`, the disable-resolution report, and the version and help surface.
- `doctor`: the install health check.
- `configuration`: the unified cadence config and its resolution.
- `git-safety`: destructive git operations, amends of pushed commits, untracked files, and branch bases.
- `worktree-enforcement`: mutations in a primary checkout and the main-branch and worktree nudges.
- `secret-reads`: secrets entering the context (reads, dumps, sops decrypts, vault enumeration) and output redaction.
- `secret-writes`: writes, edits and deletes of secret-bearing files.
- `secret-push`: pushes that would publish a secret.
- `repo-ownership`: writes to repositories the operator does not own, irreversible gh operations, and repo creation.
- `issue-guards`: critical-grade labels, held issues, issue-tracker routing.
- `pr-workflow`: the polish gate, review markers, ready and merge checks, PR body and auto-close checks.
- `content-checks`: terminology, markers, memory limits, frontmatter, markdown, security patterns and other write-time checks.
- `external-content`: redaction of harness vocabulary and overshare in external posts.
- `runbook-scrub`: the scrub gate on the runbooks directory.
- `obsidian-vault`: deletion in an Obsidian vault.
- `tool-nudges`: aliased tools, cron, chezmoi, dotfiles, model and device gates, agent dispatch, AskUserQuestion, model posture and platform drift.
- `metrics`: the telemetry loggers, staleness warning, session grade and pricing.
- `session-coordination`: the session registry, peer lanes, branch drift and intent, commit provenance, backstop, and idle gaps.
- `plan-lifecycle`: persisting, linting, ticking and driving living plans.

### Modified Capabilities

None. There were no specs before this change.

## Impact

- New: `openspec/`, `.claude/skills/openspec-*`, `.claude/commands/opsx/`, `.agents/skills/openspec-*`, `scripts/openspec.sh`, `scripts/openspec-localize.sh`, `scripts/openspec/`, `tests/openspec_skills.rs`, `tests/plans_freeze.rs`.
- Changed: `.github/workflows/ci.yml` (new `openspec` job), `.gitignore`, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
- Phases 2 and 3 of the ADR-0046 work (narrowing guards, moving push and commit checks into git hooks) land as OpenSpec changes against these specs.
