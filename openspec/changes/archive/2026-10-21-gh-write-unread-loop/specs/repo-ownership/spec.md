## MODIFIED Requirements

### Requirement: gh writes the guard cannot place
`guard-gh-write` SHALL block a write it cannot place on an owned repository: no `-R` and no resolvable remote (`Cannot determine target repo for gh write operation`), an unparseable or ambiguous `-R`, an unexpanded variable target, a fork checkout with an unowned fork or upstream, a `gh api` write outside `repos/<owner>/<repo>` and an allowed owner's `orgs/<org>`, a GraphQL mutation, and a command too large or nested to read. Each reason SHALL name a concrete fix.

#### Scenario: Write with no resolvable target
- **WHEN** `gh issue create --title t` runs in a directory with no git remote
- **THEN** the hook exits 2 and the reason tells the operator to add `-R <owner>/<repo>`

#### Scenario: GraphQL read and thread resolution
- **WHEN** the command is `gh api graphql -f query='query { viewer { login } }'` or a `resolveReviewThread` mutation
- **THEN** the hook allows

#### Scenario: Unconfigured machine
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and the command is `gh pr merge 5 -R cameronsjo/tool`
- **THEN** the hook exits 2 with `Not configured`

## ADDED Requirements

### Requirement: gh writes in a loop the parser cannot read
`guard-gh-write` MUST NOT block a loop the loop parser cannot read (past its 12 KB cap, or a syntax error) for that alone. It SHALL judge each gh write in the loop on its own, as outside a loop, and SHALL nudge on a judged write with no `-R`, `GH_REPO` or literal `repos/<owner>/<repo>/…` path, naming `-R owner/repo`. With `CADENCE_GH_STRICT_LOOPS=1` it MUST block such a loop when a write in it has no `-R` or literal path; a `GH_REPO` does not count.

#### Scenario: Unreadable loop with an unowned target
- **WHEN** a comment takes `for i in 1 2; do gh issue close $i -R evil/x; done` past 12 KB
- **THEN** the hook exits 2 because the write targets a repo the operator does not own

#### Scenario: Unreadable loop with a directory it cannot follow
- **WHEN** a comment takes `for d in a b; do cd "$d"; gh issue close 1; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 because the write's directory cannot be resolved

#### Scenario: Unreadable loop of targeted writes or reads
- **WHEN** a comment takes `for i in 1 2; do gh issue close $i -R cameronsjo/tool; done` or `for i in 1 2; do gh pr view $i; done` past 12 KB
- **THEN** the hook allows with no output

#### Scenario: Unreadable loop with a write that names no target
- **WHEN** a comment takes `for i in 1 2; do gh issue close $i; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge to give every gh write in the loop `-R owner/repo`

#### Scenario: Strict loops past the parse cap
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for n in 1 2; do gh issue close $n; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 and the reason tells the operator to give every gh write in the loop `-R owner/repo`

#### Scenario: Strict loops past the parse cap with targets
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for n in 1 2; do gh issue close $n -R cameronsjo/tool; done` past 12 KB
- **THEN** the hook allows
