## MODIFIED Requirements

### Requirement: Overshare audit triggers
`cadence warn-overshare` SHALL nudge, never block, with a `Pre-ship audit:` message asking the model to check outgoing content for personal context (health, relationships, non-technical biography), on a Bash command carrying `git push` or a posting segment as defined for `redact-external-content` (a `git commit`, and a `gh api` write that posts no prose field, excepted), and on a Write, Edit or MultiEdit to a path containing `/docs/field-reports/`. Reads, views and listings MUST be allowed.

#### Scenario: Commit nudges
- **WHEN** a Bash call runs `git commit -m 'x' && git push`, which carries a push as well as the commit
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Commit with a post nudges
- **WHEN** a Bash call runs `git commit -m 'x' && gh pr create --title t`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Push nudges
- **WHEN** a Bash call runs `git push origin main`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash call runs `gh pr view 5` or `git status`
- **THEN** the hook exits 0 with no output

#### Scenario: Quoted mention
- **WHEN** the command is `echo 'docs: gh pr comment usage'`
- **THEN** the hook exits 0 with no output

#### Scenario: Push or post after a silenced commit
- **WHEN** a commit-only command has run silently in the session, and a later Bash call runs `git push`, `gh pr create`, `gh pr comment`, `gh issue create`, `gh release create`, a `gh api` write or `gh repo edit`, or a Write targets `/docs/field-reports/x.md`
- **THEN** each of those calls exits 0 with a nudge, every time

## ADDED Requirements

### Requirement: Overshare commit exemption
A `git commit` SHALL NOT trigger the overshare reminder in any form: plain, after a `cd` or `git add`, with `git -C` or another global option, or with a message built by substitution, except that a message spelling `git push` as two words is read as a push. A command that also carries a push or a posting segment SHALL still trigger it, for the push or the post.

#### Scenario: Commit alone is silent
- **WHEN** a Bash call runs `git commit -m 'x'`, `cd other && git commit -m 'x'`, `git -C other commit -m 'x'` or `git commit -m "$(cat msg.txt)"`
- **THEN** the hook exits 0 with no output

## REMOVED Requirements

### Requirement: Overshare commit quiet period
**Reason**: A `git commit` no longer triggers the reminder, so there is no commit reminder to quiet.
**Migration**: None. The session marker `overshare-commit-warned` is no longer read or written.

### Requirement: Overshare quiet period spending
**Reason**: Nothing is spent when a commit never reminds.
**Migration**: None.

### Requirement: Overshare plain commit shape
**Reason**: The plain-commit shape only decided which commits the quiet period applied to.
**Migration**: None.

### Requirement: Overshare quiet period key
**Reason**: With no quiet period there is no key.
**Migration**: None.
