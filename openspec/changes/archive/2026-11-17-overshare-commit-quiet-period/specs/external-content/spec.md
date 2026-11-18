## MODIFIED Requirements

### Requirement: Overshare audit triggers
`cadence warn-overshare` SHALL nudge, never block, with a `Pre-ship audit:` message asking the model to check outgoing content for personal context, on a Bash command carrying `git push` or a posting segment as defined for `redact-external-content` (a `gh api` write that posts no prose field excepted), and on a Write, Edit or MultiEdit to a path containing `/docs/field-reports/`. Reads, views and listings MUST be allowed.

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
- **WHEN** a plain `git commit` has already nudged in the session, and a later Bash call runs `git push`, `gh pr create`, `gh pr comment`, `gh issue create`, `gh release create`, a `gh api` write or `gh repo edit`, or a Write targets `/docs/field-reports/x.md`
- **THEN** each of those calls exits 0 with a nudge, every time

## ADDED Requirements

### Requirement: Overshare commit quiet period
`warn-overshare` SHALL nudge on the first plain `git commit` of a session and SHALL allow later plain commits in the same session with no output. Every other trigger MUST nudge every time and MUST NOT spend or consult the quiet period: a push, a post, a field-report edit, and any command that contains a commit without being a plain commit. A call that rides `CADENCE_SKIP_OVERSHARE_AUDIT=1` SHALL NOT spend the quiet period.

#### Scenario: Second plain commit
- **WHEN** a session runs `git commit -m 'a'` and then `git commit -m 'b'`
- **THEN** the first exits 0 with a nudge and the second exits 0 with no output

#### Scenario: Commit chained with a push
- **WHEN** a session has spent its quiet period and runs `git commit -m 'x' && git push`
- **THEN** the hook exits 0 with a nudge

### Requirement: Overshare plain commit shape
A commit SHALL be plain only when the whole command is one `git commit` invocation: the trimmed text starts with `git commit` and a blank or the end, and everything after it is bare words of ASCII letters, digits and `_ . / = : @ + , % -`, single-quoted text, or double-quoted text with no `$`, backtick, backslash or `!`, separated by spaces or tabs. Any other text MUST NOT be plain.

#### Scenario: Commit with a global option
- **WHEN** a session has spent its quiet period and runs `git -C other commit -m 'x'` or `cd other && git commit -m 'x'`
- **THEN** the hook exits 0 with a nudge

#### Scenario: Commit with a substitution
- **WHEN** a session has spent its quiet period and runs `git commit -m "$(cat msg.txt)"`
- **THEN** the hook exits 0 with a nudge

#### Scenario: Other shapes that are not plain
- **WHEN** a session has spent its quiet period and runs a commit with a variable or wrapper prefix, a pipe, a heredoc, a redirect, a trailing comment, a glob, or a newline outside quotes
- **THEN** the hook exits 0 with a nudge

### Requirement: Overshare quiet period key
The quiet period SHALL be keyed on the session id alone. A subagent shares its parent's session id, so a plain commit in either silences a later plain commit in the other; this is accepted, because the quiet period can silence nothing but another plain commit. With no session id, an empty one, or a marker directory that is not private, the hook SHALL nudge every time.

#### Scenario: Different session
- **WHEN** a session has spent its quiet period and a payload with another session id runs `git commit -m 'x'`
- **THEN** the hook exits 0 with a nudge

#### Scenario: No session id
- **WHEN** a payload carries no session id and runs `git commit -m 'x'` twice
- **THEN** both calls exit 0 with a nudge
