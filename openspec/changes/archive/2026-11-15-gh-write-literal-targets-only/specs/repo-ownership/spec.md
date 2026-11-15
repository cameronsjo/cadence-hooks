## MODIFIED Requirements

### Requirement: gh writes the guard cannot place
`guard-gh-write` MUST allow a write whose target it cannot read exactly (cadence-ecosystem ADR-0046 rule 3): no readable `-R` or remote, `-R` readings that disagree, a target or host holding a shell expansion with no literal owner, a directory it cannot follow, a `gh api` write outside `repos/<owner>/<repo>/…`, and a command too large or nested to read. With no allowlist configured, a write MUST still block.

#### Scenario: Write with no resolvable target
- **WHEN** `gh issue create --title t` runs in a directory with no git remote
- **THEN** the hook allows

#### Scenario: Variable target
- **WHEN** the command is `gh issue comment 1 -R "$REPO" --body-file c.md`
- **THEN** the hook allows

#### Scenario: Unexpanded host
- **WHEN** the command is `GH_HOST=$GH_HOST gh pr edit 7 --repo cameronsjo/tool --body-file b.md`
- **THEN** the hook allows

#### Scenario: Literal owner with an expanded name
- **WHEN** the command is `gh issue create -R "evil/$r" --title t`
- **THEN** the hook exits 2 naming the owner `evil`

#### Scenario: GraphQL read and thread resolution
- **WHEN** the command is `gh api graphql -f query='query { viewer { login } }'` or a `resolveReviewThread` mutation
- **THEN** the hook allows

#### Scenario: GraphQL mutation
- **WHEN** the command is `gh api graphql -f query='mutation { addComment(input: {subjectId: "S", body: "x"}) { clientMutationId } }'`
- **THEN** the hook allows

#### Scenario: Unconfigured machine
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and the command is `gh pr merge 5 -R cameronsjo/tool`
- **THEN** the hook exits 2 with `Not configured`

### Requirement: gh write named by a PR or issue URL argument
On a `gh pr` or `gh issue` write verb that takes a `<number> | <url> | <branch>` argument, `guard-gh-write` SHALL judge the repo and host a PR or issue URL there names before `-R`, `GH_REPO` and the checkout; under `gh issue transfer` the URL is judged in addition to them. A URL it cannot read for certain SHALL be judged as before. An unowned URL SHALL block with a fix that names no target. A flag's value SHALL NOT count.

#### Scenario: Unowned PR URL past an owned target
- **WHEN** the command is `gh pr merge https://github.com/evil/repo/pull/1 --squash -R cameronsjo/tool`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `github.com/evil/repo`, and the fix asks the user to run the command and names no `cameronsjo/` repo

#### Scenario: Owned issue URL outside an owned checkout
- **WHEN** the command is `gh issue close https://github.com/cameronsjo/tool/issues/3`, in a checkout of `evil/repo` or in `/tmp`
- **THEN** the hook allows

#### Scenario: URL as a flag's value
- **WHEN** the command is `gh pr comment 5 --body https://github.com/evil/repo/pull/1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Owned issue URL in a transfer from an unowned checkout
- **WHEN** the command is `gh issue transfer https://github.com/cameronsjo/tool/issues/3 evil/repo`, in a checkout of `evil/repo`
- **THEN** the hook exits 2 naming `evil/repo`

#### Scenario: Owned PR URL in a loop from an unowned checkout
- **WHEN** the command is `for n in 1 2; do gh pr merge https://github.com/cameronsjo/tool/pull/$n; done`, in a checkout of `evil/repo`
- **THEN** the hook allows, judging each merge as a single command, where gh takes the URL's repo

#### Scenario: Percent sign in the query
- **WHEN** the command is `gh pr merge 'https://github.com/evil/repo/pull/1/files?file-filters%5B%5D=.rs'`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `github.com/evil/repo`

#### Scenario: Percent sign in the path
- **WHEN** the command is `gh pr merge https://github.com/evil%2Drepo/x/pull/1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows, judging the checkout as before

#### Scenario: Bad escape in the fragment
- **WHEN** the command is `gh pr merge 'https://github.com/evil/repo/pull/1#f%zz'`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows, judging the checkout as before

## REMOVED Requirements

### Requirement: gh writes allowed without an ownership check
**Reason**: Its loop half and `CADENCE_GH_STRICT_LOOPS` are removed with the loop gate; the rest moves to "User-scoped gh writes".
**Migration**: Unset `CADENCE_GH_STRICT_LOOPS`; it has no effect.

### Requirement: gh writes in a loop the parser cannot read
**Reason**: cadence-ecosystem ADR-0046 rule 3. A loop gets no rule of its own; each write in it is judged as a single command, so the nudge and the strict-loops block for an unread loop go.
**Migration**: None. "gh writes in a loop" covers loop bodies.

### Requirement: gh writes in a loop the parser reads
**Reason**: The loop gate blocked writes whose target it could not prove, which ADR-0046 rule 3 allows. A literal unowned target in a loop body still blocks through the per-command check.
**Migration**: None. "gh writes in a loop" covers loop bodies.

### Requirement: Strict loops the parser cannot read
**Reason**: `CADENCE_GH_STRICT_LOOPS` is removed with the loop gate.
**Migration**: Unset `CADENCE_GH_STRICT_LOOPS`; it has no effect.

### Requirement: Loop fix targets
**Reason**: The loop block it worded is removed.
**Migration**: None.

## ADDED Requirements

### Requirement: User-scoped gh writes
`guard-gh-write` SHALL allow `gh gist` writes and `gh repo fork` (they land under the operator's account) and `gh issue create --web`/`-w` unless the command sets `BROWSER=` or `GH_BROWSER=`. An ownership probe past the git-probe deadline MUST allow.

#### Scenario: Gist from an unowned checkout
- **WHEN** `gh gist create notes.md` runs in a checkout whose remote is unowned
- **THEN** the hook allows

### Requirement: gh writes in a loop
`guard-gh-write` SHALL judge each gh write in a loop body as a single command, in the directory the guard reads it to run in. A literal unowned target SHALL block; a write without a target SHALL be judged on its directory's remotes; a target the shell builds per iteration (`-R "$r"`) MUST be allowed.

#### Scenario: Loop with a literal unowned target
- **WHEN** the command is `for i in 1 2; do gh issue close $i -R evil/x; done`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Loop in an unowned checkout
- **WHEN** the command is `for n in 1 2; do gh issue close $n; done` in a checkout whose remote is unowned
- **THEN** the hook exits 2

#### Scenario: Loop in an owned checkout
- **WHEN** the command is `for n in 1 2; do gh issue close $n; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Loop over a variable target
- **WHEN** the command is `for r in a b; do gh issue close 1 -R "$o/$r"; done`
- **THEN** the hook allows
