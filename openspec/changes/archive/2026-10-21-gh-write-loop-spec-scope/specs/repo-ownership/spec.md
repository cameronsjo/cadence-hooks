## ADDED Requirements

### Requirement: gh writes in a loop the parser reads
In a loop the loop parser reads, `guard-gh-write` MUST block a gh write with no `-R` when the loop body changes directory or the directory does not resolve to an owned non-fork repository, and the reason SHALL name `-R` as the fix.

#### Scenario: Loop that changes directory
- **WHEN** the command is `for d in a b; do cd $d; gh issue close 1; done` in an owned checkout
- **THEN** the hook exits 2 and the reason tells the operator to add `-R`

#### Scenario: Loop in an unowned checkout
- **WHEN** the command is `for n in 1 2; do gh issue close $n; done` in a checkout whose remote is unowned
- **THEN** the hook exits 2

### Requirement: Strict loops the parser cannot read
With `CADENCE_GH_STRICT_LOOPS=1`, `guard-gh-write` MUST block a command the loop parser cannot read when it shows a `for … in` or `while …; do` loop and holds a write judged for ownership that has no `-R`, `gh repo` positional `owner/repo` or literal `repos/<owner>/<repo>/…` path; a `GH_REPO` does not count. A write allowed without an ownership check stays allowed.

#### Scenario: Strict loops past the parse cap with a positional repo
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for r in a b; do gh repo edit cameronsjo/tool --description $r; done` past 12 KB
- **THEN** the hook allows

#### Scenario: Strict loops past the parse cap with a gist
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for i in 1 2; do gh gist create f$i.md; done` past 12 KB
- **THEN** the hook allows

## MODIFIED Requirements

### Requirement: gh writes in a loop the parser cannot read
`guard-gh-write` MUST NOT block a loop the loop parser cannot read (past its 12 KB cap or time budget, or a syntax error) for that alone. It SHALL judge each gh write in the loop on its own, as outside a loop, and SHALL nudge on a judged write with no `-R`, `gh repo` positional `owner/repo`, `GH_REPO` or literal `repos/<owner>/<repo>/…` path, naming `-R owner/repo`. Under `CADENCE_GH_STRICT_LOOPS=1`, "Strict loops the parser cannot read" decides instead.

#### Scenario: Unreadable loop with an unowned target
- **WHEN** a comment takes `for i in 1 2; do gh issue close $i -R evil/x; done` past 12 KB
- **THEN** the hook exits 2 because the write targets a repo the operator does not own

#### Scenario: Unreadable loop with a directory it cannot follow
- **WHEN** a comment takes `for d in a b; do cd "$d"; gh issue close 1; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 because the write's directory cannot be resolved

#### Scenario: Unreadable loop of targeted writes or reads
- **WHEN** a comment takes `for i in 1 2; do gh issue close $i -R cameronsjo/tool; done`, `for r in a b; do gh repo edit cameronsjo/tool --description $r; done` or `for i in 1 2; do gh pr view $i; done` past 12 KB
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
