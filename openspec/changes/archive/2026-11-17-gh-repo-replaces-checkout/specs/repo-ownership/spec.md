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
On a command gh reads `GH_REPO` for, `guard-gh-write` SHALL drop the checkout as a target only for three exact shapes, the `GH_REPO` read exactly: an inline `GH_REPO=` prefix on the gh word; a whole command of one top-level `export GH_REPO=<literal>`, then `;` or a newline, then only plain gh invocations; or a whole command of only plain gh invocations under the hook process's value. Any other command MUST keep the checkout a target.

#### Scenario: Rule 1, an inline prefix on gh
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi`, `GH_REPO=cameronsjo/tool gh api -X POST repos/{owner}/{repo}/issues -f title=x`, or `cd . && GH_REPO=cameronsjo/tool gh pr merge 5 --squash`, in a checkout of `evil/up` or a fork whose upstream is `evil/up`
- **THEN** the hook allows: every word before `gh` is an assignment, the last `GH_REPO=` there is a non-empty literal, and the command names `GH_HOST` nowhere else, so the rule holds whatever else the command holds

#### Scenario: Rule 2, one export then only gh
- **WHEN** the command is `export GH_REPO=cameronsjo/tool; gh issue comment 1 --body hi`, or the same with a newline for `;`, or with `&& gh pr merge 5 --squash` after it, in a checkout of `evil/up`
- **THEN** the hook allows, because the whole command is that export joined by `;` or a newline to plain gh invocations joined by `;`, a newline, `&&` or `||`, with no substitution, backtick, subshell, group, function, keyword, process substitution or here-document anywhere, and no `GH_HOST` outside an inline prefix

#### Scenario: Rule 3, only gh under the hook process's value
- **WHEN** the hook process has `GH_REPO=cameronsjo/tool` and the command is `gh issue comment 1 --body hi` or `gh issue comment 1 --body hi; gh pr merge 5 --squash`, in a checkout of `evil/up`
- **THEN** the hook allows, because the whole command is plain gh invocations, it never names `GH_REPO`, and it names `GH_HOST` nowhere outside an inline prefix

#### Scenario: Any other shape keeps the checkout
- **WHEN** the checkout is `evil/up` and, under an exported or hook-process `GH_REPO=cameronsjo/tool`, the command is `cd . && gh pr merge 5 --squash`, `gh issue comment 1 --body "$(cat body.md)"`, `export FOO=bar; gh …`, `export GH_REPO=cameronsjo/tool; GH_REPO=evil/up; gh …`, `export GH_REPO=cameronsjo/tool & gh …`, `[ -n "$X" ] && export GH_REPO=cameronsjo/tool; gh …`, `. ./x.sh; gh …`, `PR=$(source .env && gh pr create …)`, `case "$E" in prod) source .env;; esac; gh …`, `load_env() { source .env; }; load_env; gh …`, `env -u GH_REPO gh …`, `sudo gh …` or `export GH_HOST=ghe.example.com; gh …`
- **THEN** the hook exits 2 on the checkout, as before this rule

#### Scenario: Unowned GH_REPO from an owned checkout
- **WHEN** the command is `GH_REPO=evil/x gh issue comment 1 --body hi` or `export GH_REPO=evil/x; gh issue comment 1 --body hi`, or the hook process has `GH_REPO=evil/x` and the command is `gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Unreadable GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO="$R" gh issue comment 1 --body hi`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout, and the same command allows in a checkout of `cameronsjo/tool`

#### Scenario: Command that never reads GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh repo edit --description d`, in a checkout of `evil/up`
- **THEN** the hook exits 2, because `gh repo edit` writes to the checkout's repository

### Requirement: The hook process's GH_REPO is the command shell's
For rule 3, `guard-gh-write` SHALL assume, as an accepted assumption, that the `GH_REPO` in the hook process's environment is the one the command's shell hands gh, though a shell profile or session environment file could export a different one.

#### Scenario: Hook process value under rule 3
- **WHEN** the hook process has `GH_REPO=cameronsjo/tool` and the command is `gh pr merge 5 --squash`, in a checkout of `evil/up`
- **THEN** the hook allows on that value, without reading any profile or session environment file

### Requirement: Writes past their repository keep the checkout
`guard-gh-write` MUST NOT let a `GH_REPO` replace the checkout on `gh secret` or `gh variable` `set` or `delete` with `--org` (`-o`), or on `gh issue transfer`, whose real target (the org, the destination repo) it does not read.

#### Scenario: Org secret under an owned GH_REPO
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh secret set TOKEN --org evil --body x`, `GH_REPO=cameronsjo/tool gh secret delete TOKEN --org evil` or `GH_REPO=cameronsjo/tool gh issue transfer 1 evil/up`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout
