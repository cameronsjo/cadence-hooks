## MODIFIED Requirements

### Requirement: Deploy-key and autolink writes
`guard-gh-write` SHALL treat `gh repo deploy-key add|delete` and `gh repo autolink create|new|delete` as writes, judged on the same targets as every other `-R` write (`-R`, else a `GH_REPO` in force, else the checkout's remotes). Their `list` and `view` verbs SHALL be reads.

#### Scenario: Deploy key on an unowned repo
- **WHEN** the command is `gh repo deploy-key add key.pub -R evil/x`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Autolink through an exported GH_REPO
- **WHEN** the command is `export GH_REPO=evil/x; gh repo autolink delete 1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2

#### Scenario: Deploy key through an owned GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh repo deploy-key add key.pub`, in a checkout of `evil/up`
- **THEN** the hook allows, because gh writes to `cameronsjo/tool` rather than the checkout

## ADDED Requirements

### Requirement: GH_REPO replaces the checkout
On a command gh reads `GH_REPO` for, `guard-gh-write` SHALL drop the checkout's remotes as a target (the fallback and a `repos/` placeholder fill) only when it shows the `GH_REPO` it read exactly is the value gh receives, by one of three rules: an inline prefix on the gh word itself; one plain top-level export before the write; or the hook process's value with no mention in the command. Otherwise the checkout MUST stay a target beside it.

#### Scenario: Rule 1, an inline prefix on gh
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` or `GH_REPO=cameronsjo/tool gh api -X POST repos/{owner}/{repo}/issues -f title=x`, in a checkout of `evil/up` or a fork whose upstream is `evil/up`
- **THEN** the hook allows, because every word before `gh` is an assignment and the last `GH_REPO=` there is a non-empty literal

#### Scenario: Rule 2, one plain export
- **WHEN** the command is `export GH_REPO=cameronsjo/tool; gh issue comment 1 --body hi` (or with a newline for `;`), in a checkout of `evil/up`
- **THEN** the hook allows, because the export is a top-level segment before the write, joined by `;` or a newline, no group, subshell, keyword or substitution opens before it, gh is the plain command word, the command names `GH_REPO` nowhere else outside the write's own text, and, as in rule 3, the write's text occurs once and no segment sources a script or sets a variable through an expanded operand

#### Scenario: Rule 3, the hook process's value
- **WHEN** the hook process has `GH_REPO=cameronsjo/tool` and the command is `gh issue comment 1 --body hi`, in a checkout of `evil/up`
- **THEN** the hook allows, because the command never names `GH_REPO`, gh is a plain top-level command whose text occurs once, no segment sources a script or runs `eval` (behind a keyword, group, `builtin` or `command` too), and no `export`, `declare`, `typeset`, `local`, `readonly` or `unset` has an operand holding an expansion

#### Scenario: Unowned GH_REPO from an owned checkout
- **WHEN** the command is `GH_REPO=evil/x gh issue comment 1 --body hi` or `export GH_REPO=evil/x; gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: A value the guard cannot show reaches gh
- **WHEN** the checkout is `evil/up` and the command is one of `export GH_REPO=cameronsjo/tool; GH_REPO=evil/up; gh issue comment 1 --body hi`, `export GH_REPO=cameronsjo/tool; declare -x GH_REPO=evil/up; gh …`, `export GH_REPO=cameronsjo/tool & gh …`, `export GH_REPO=cameronsjo/tool | cat; gh …`, `[ -n "$X" ] && export GH_REPO=cameronsjo/tool; gh …`, `GH_REPO=cameronsjo/tool sudo gh …`, or, with `GH_REPO=cameronsjo/tool` in the hook process, `GH_REPO=evil/up; gh …`, `. ./x.sh; gh …`, `if [ -f .env ]; then source .env; fi; gh …`, `export $(cat .env | xargs); gh …`, `env -i bash -c 'gh …'; gh …`, `env -u GH_REPO gh …` or `ssh box gh …`
- **THEN** the hook exits 2 on the checkout, as before this rule

#### Scenario: Unreadable GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO="$R" gh issue comment 1 --body hi`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout, and the same command allows in a checkout of `cameronsjo/tool`

#### Scenario: Command that never reads GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh repo edit --description d`, in a checkout of `evil/up`
- **THEN** the hook exits 2, because `gh repo edit` writes to the checkout's repository

### Requirement: Writes past their repository keep the checkout
`guard-gh-write` MUST NOT let a `GH_REPO` replace the checkout on `gh secret` or `gh variable` `set` or `delete` with `--org` (`-o`), or on `gh issue transfer`, whose real target (the org, the destination repo) it does not read.

#### Scenario: Org secret under an owned GH_REPO
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh secret set TOKEN --org evil --body x`, `GH_REPO=cameronsjo/tool gh secret delete TOKEN --org evil` or `GH_REPO=cameronsjo/tool gh issue transfer 1 evil/up`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout
