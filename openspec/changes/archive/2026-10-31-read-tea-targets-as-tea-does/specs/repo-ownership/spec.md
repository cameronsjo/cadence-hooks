## MODIFIED Requirements

### Requirement: tea and glab writes
`guard-forge-write` (PreToolUse, Bash) SHALL block (exit 2) a `tea` or `glab` write whose target is outside the allowlist or cannot be read, and SHALL allow reads and any verb outside its write table. For `glab` the target is `-R`/`--repo`; a bare target MUST match a bare entry only on a host in `CADENCE_EXTRA_HOSTS` or a `gitlab.com/<owner>` entry, never on the GitHub default host. With no allowlist every write it reaches MUST block. `glab api` and `tea api` SHALL be allowed.

#### Scenario: Unowned GitLab write
- **WHEN** the command is `glab mr create -R evil/r --title t`
- **THEN** the hook exits 2 naming `glab write targets` and the allowed entries

#### Scenario: GitLab read
- **WHEN** the command is `glab mr list -R evil/r`
- **THEN** the hook allows

## ADDED Requirements

### Requirement: tea targets read as tea reads them
For `tea` the target SHALL be `--repo`/`-r` (`-R` is tea's `--remote`), its first two `/` parts being owner and repo, and tea's flags SHALL be read as tea's parser reads them: one or two dashes, a name or alias, `=` or the next word, none after `--`, a lone `-`, or `-` plus a non-letter. A bare slug MUST be owned on every tea login host (the `--login` one, else every saved login, plus a `GITEA_INSTANCE_URL` host). Only with no readable login and no such host does `CADENCE_EXTRA_HOSTS` decide.

#### Scenario: Bare tea slug on the login host
- **WHEN** tea's only login is `https://git.sjo.lol`, `git.sjo.lol/cameron` is allowed, and the command is `tea pr create --repo cameron/lectern`
- **THEN** the hook allows

#### Scenario: Single-dash login flag
- **WHEN** the checkout's remote is owned and the command is `tea pr create --title t -login work`, where `work` is a login on an unowned host
- **THEN** the hook exits 2

#### Scenario: Host-qualified tea slug
- **WHEN** the command is `tea pr create --repo git.sjo.lol/cameron/lectern`
- **THEN** the hook exits 2 naming `tea write targets git.sjo.lol/cameron`, since tea reads owner `git.sjo.lol`

### Requirement: tea writes judged on their directory
A `tea` `pulls`, `issues` or `comment` write with no `--repo` or `--owner` SHALL be judged on the git remotes of the directory it runs in (payload `cwd`, literal `cd`s, `env -C`); every remote, or the `--remote` one, MUST be owned, and on the login host when `--login` or `GITEA_INSTANCE_URL` moves it. No readable two-part remote MUST block as unreadable.

#### Scenario: tea write in an owned checkout
- **WHEN** the command is `cd <repo> && tea pr create --title t` and every remote of `<repo>` is an owned repo
- **THEN** the hook allows

#### Scenario: Login on another host
- **WHEN** the checkout's remote is owned on `git.sjo.lol` and the command is `tea pr create --title t --login work`, where `work` is a login on an unowned host
- **THEN** the hook exits 2

### Requirement: tea targets the guard cannot read
`guard-forge-write` MUST block as unreadable a `tea` write whose `--repo`/`--owner` is not a literal `owner/repo`, whose `--repo` names an existing directory, that is `repos create|delete` without `--owner`, that carries a near miss of a repo, login, remote or owner flag (`--rep`, `-logi`), whose command assigns `GITEA_INSTANCE_URL`, or that sets `HOME`, `XDG_CONFIG_HOME` or a `GITEA_*` variable in front of `tea`. Each is a shape where tea's write target can differ from what the guard read.

#### Scenario: Repo from a variable
- **WHEN** the command is `tea pr create --repo "$REPO"` in an owned checkout
- **THEN** the hook exits 2 with rule `forge-write-target-unresolvable`

### Requirement: tea login config the guard cannot read
A `tea` write judged on a login host MUST block when tea's config has a login the guard cannot read (an entry without a plain `name:` and `url:`, a list at the key's column, an inline list, a file over 1 MiB, or content yielding no login), or a literal `--login` names no saved login. It MUST NOT fall back to `CADENCE_EXTRA_HOSTS`; only a missing, empty or comment-only config does.

#### Scenario: One unreadable login with extra hosts set
- **WHEN** `CADENCE_EXTRA_HOSTS` names the owned host and tea's config has a readable `sjo` login and a `work` login written with a quoted `"url":` key
- **THEN** `tea pr create --repo cameron/lectern` exits 2
