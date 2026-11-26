## MODIFIED Requirements

### Requirement: What counts as a gh write
`guard-gh-write` SHALL treat as writes: `gh pr|issue|release|label|repo|gist|workflow` with a mutating verb (`create`, `merge`, `close`, `comment`, `edit`, `delete`, `review`, `ready`, `reopen`, `lock`, `archive`, `rename`, `transfer`, `fork`, `run`, `enable`, `disable`), `gh secret|variable set|delete`, `gh release upload`, `gh label clone`, the deploy-key and autolink writes, and `gh api` with a mutating `-X`/`--method`, a field flag or `--input`, unless an explicit `GET` method is given.

#### Scenario: API field write
- **WHEN** the command is `gh api repos/evil/repo/issues -f title=x`
- **THEN** the hook exits 2

#### Scenario: Explicit GET with fields
- **WHEN** the command is `gh api repos/evil/repo/issues -X GET -f state=open`
- **THEN** the hook allows

### Requirement: gh writes the guard cannot place
`guard-gh-write` MUST allow a write whose target it cannot read exactly (cadence-ecosystem ADR-0046 rule 3): no readable `-R` or remote, `-R` readings that disagree, a target or host holding a shell expansion with no literal owner, a directory it cannot follow, a `gh api` write outside `repos/<owner>/<repo>/…` and `orgs/<org>/…`, and a command too large or nested to read. With no allowlist configured, a write MUST still block.

#### Scenario: Substituted owner with a literal name
- **WHEN** the command is `gh issue close 1 -R "$(cat o)/x"`
- **THEN** the hook allows, because the substitution is an expansion in the owner

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

#### Scenario: Absolute API URL
- **WHEN** the command is `gh api -X POST https://api.github.com/repos/evil/x/issues/1/comments -f body=hi`
- **THEN** the hook exits 2 naming `evil/x`, as for the relative `repos/evil/x/…` path

#### Scenario: Org-level API write
- **WHEN** the command is `gh api -X POST orgs/evil/repos -f name=x`
- **THEN** the hook exits 2 naming the owner `evil`

#### Scenario: Placeholder owner
- **WHEN** the command is `gh api -X POST repos/{owner}/{repo}/issues -f title=x` or `repos/:owner/:repo/issues` in a checkout of `cameronsjo/tool`
- **THEN** the hook allows, because gh fills the placeholders from that checkout

#### Scenario: Placeholder owner on a named host
- **WHEN** the command is `gh api --hostname evil.example -X POST repos/{owner}/{repo}/issues -f title=x` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2, because gh sends it to `evil.example`, which the allowlist does not cover

#### Scenario: Upload and GHE.com URL prefixes
- **WHEN** the command is `gh api -X POST "https://uploads.github.com/repos/evil/x/releases/1/assets?name=a" --input a`, or `https://api.acme.ghe.com/repos/evil/x/…` with `acme.ghe.com` in `CADENCE_EXTRA_HOSTS`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Look-alike API host
- **WHEN** the command is `gh api -X POST https://api.github.com.evil.example/repos/evil/x/issues -f t=x`
- **THEN** the hook allows, because the host is compared whole and names no repo this guard reads

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

### Requirement: Deploy-key and autolink writes
`guard-gh-write` SHALL treat `gh repo deploy-key add|delete` and `gh repo autolink create|new|delete` as writes, judged on the same targets as every other `-R` write (`-R`, else `GH_REPO` and the checkout's remotes). Their `list` and `view` verbs SHALL be reads.

#### Scenario: Deploy key on an unowned repo
- **WHEN** the command is `gh repo deploy-key add key.pub -R evil/x`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Autolink through an exported GH_REPO
- **WHEN** the command is `export GH_REPO=evil/x; gh repo autolink delete 1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2

### Requirement: GH_REPO a gh write inherits
`guard-gh-write` SHALL read `GH_REPO` from an inline `GH_REPO=` on the gh word, and otherwise from the `GH_REPO` in force: the hook process's, replaced by each literal `export GH_REPO=` and cleared by each `unset GH_REPO` the command runs in its own shell before the write (bash's `unset -v` and `--` forms included). Any `GH_REPO` SHALL be judged only on a command gh reads it for: in the `gh repo` group only `rename`, `deploy-key` and `autolink`, and in `gh api` only to fill a placeholder.

#### Scenario: Command that never reads GH_REPO
- **WHEN** the command is `export GH_REPO=evil/x; gh repo create cameronsjo/new --private`
- **THEN** the hook allows, because `gh repo create` takes its repository from its argument

#### Scenario: Export in a child shell
- **WHEN** the command is `bash -c 'export GH_REPO=evil/x'; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Exported GH_REPO
- **WHEN** the command is `export GH_REPO=evil/x; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Hook process GH_REPO
- **WHEN** the hook process has `GH_REPO=evil/x` and `gh issue comment 1 --body hi` runs in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2

### Requirement: GH_REPO spellings the guard does not read
`guard-gh-write` MUST NOT read a `GH_REPO` set any other way, as an accepted gap (cadence-ecosystem ADR-0046 rule 3): `GH_REPO=x; export GH_REPO`, `declare -x`, `typeset -x`, `readonly -x` (zsh), `export -p` (bash), `set -a`, and an `export` or `unset` inside a loop, `if`, brace group or other compound command. An `export` behind `&&` or `||` SHALL be read as if it ran.

#### Scenario: Unset in a brace group
- **WHEN** the command is `export GH_REPO=evil/x; { unset GH_REPO; }; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2, an accepted false block: the `unset` is not read, so the export stays in force

#### Scenario: Assignment exported afterwards
- **WHEN** the command is `GH_REPO=evil/x; export GH_REPO; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Conditional export
- **WHEN** the command is `false && export GH_REPO=evil/x; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2, reading the export as if it ran

### Requirement: GH_HOST a gh write inherits
`guard-gh-write` SHALL judge a write on the host it names (`--hostname`, an inline `GH_HOST=`), else the hook process's `GH_HOST`. A `GH_HOST` the command sets other than inline on the gh word (an `export`, a bare reassignment of an inherited one, an `unset`) MUST NOT be read.

#### Scenario: Host the command exports
- **WHEN** the command is `export GH_HOST=evil.example.com && gh pr create -R cameronsjo/x --title t`
- **THEN** the hook allows, judging `cameronsjo/x` on the hook process's host

### Requirement: Home directory in a gh write's cd
`guard-gh-write` SHALL follow a `cd` or `pushd` to a leading `$HOME` or `${HOME}` that bash expands as it follows `cd ~/…`, unless the command may rebind `HOME`, and judge a write after it on that directory's remotes. An unquoted `$HOME` whose home path holds whitespace or a glob character MUST be left unread, as an accepted gap: that matches bash, which splits and globs it, and not zsh, which does neither and lands in the directory.

#### Scenario: Unquoted HOME with a space
- **WHEN** the home path holds a space, `~/up` is a checkout of `evil/up`, and the command is `cd $HOME/up; gh pr create --title t`, run from a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Home directory spelled with $HOME
- **WHEN** `~/up` is a checkout of `evil/up` and the command is `cd "$HOME/up" && gh pr create --title t`
- **THEN** the hook exits 2, as for `cd ~/up && gh pr create --title t`

#### Scenario: HOME rebound first
- **WHEN** the command is `HOME=/x; cd "$HOME/up" && gh pr create --title t`
- **THEN** the hook allows, because it cannot follow the directory

### Requirement: gh writes the guard does not judge
`guard-gh-write` MUST allow, as an accepted gap, the gh writes outside its write set, whatever their target: `gh repo unarchive`, `gh repo sync`, `gh pr revert`, `gh pr update-branch`, `gh issue pin`, `unpin` and `develop`, `gh run rerun`, `cancel` and `delete`, `gh cache delete`, and `gh discussion create`, `edit` and `comment`.

#### Scenario: Run rerun on an unowned repo
- **WHEN** the command is `gh run rerun 1 -R evil/x`
- **THEN** the hook allows
