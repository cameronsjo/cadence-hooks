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
On a command gh reads `GH_REPO` for, when every `GH_REPO` value in force names a repository `guard-gh-write` read exactly and certainly reaches gh, the checkout's remotes MUST NOT be a target, as the fallback or to fill a `repos/` placeholder, because gh writes to the `GH_REPO` repository. Otherwise the checkout SHALL stay a target beside it. A command gh does not read `GH_REPO` for SHALL be judged on the checkout.

#### Scenario: Owned GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` or `GH_REPO=cameronsjo/tool gh api -X POST repos/{owner}/{repo}/issues -f title=x` (or with `GH_REPO` exported or inherited), in a checkout of `evil/up` or a fork whose upstream is `evil/up`
- **THEN** the hook allows, because gh writes to `cameronsjo/tool` rather than the checkout

#### Scenario: Unowned GH_REPO from an owned checkout
- **WHEN** the command is `GH_REPO=evil/x gh issue comment 1 --body hi`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `evil/x`

#### Scenario: Unreadable GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO="$R" gh issue comment 1 --body hi`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout, and the same command allows in a checkout of `cameronsjo/tool`

#### Scenario: GH_REPO the command may clear or never set
- **WHEN** the hook process has `GH_REPO=cameronsjo/tool` and the command is `env -u GH_REPO gh issue comment 1 --body hi` (or uses `env -i`, `export -n GH_REPO`, or `unset GH_REPO` in any shell or compound command), or the command is `[ -n "$X" ] && export GH_REPO=cameronsjo/tool; gh issue comment 1 --body hi`, in a checkout of `evil/up`
- **THEN** the hook exits 2 on the checkout, because the guard cannot be certain gh receives that `GH_REPO`

#### Scenario: Command that never reads GH_REPO from an unowned checkout
- **WHEN** the command is `GH_REPO=cameronsjo/tool gh repo edit --description d`, in a checkout of `evil/up`
- **THEN** the hook exits 2, because `gh repo edit` writes to the checkout's repository
