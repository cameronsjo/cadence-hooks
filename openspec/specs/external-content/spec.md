# external-content Specification

## Purpose
Checks on text about to leave the machine in an external post: `cadence-hooks cadence redact-external-content` (a PreToolUse hook on Bash, Write, Edit and every MCP tool), the `cadence-hooks cadence redact-scan` CLI action that runs the same engine on stdin or a file, and `cadence-hooks cadence warn-overshare`, a PreToolUse nudge to audit about-to-ship content for personal context. All three run unchanged in a cloud session.

## Requirements

### Requirement: Posting commands and their bodies
`redact-external-content` SHALL judge a Bash command one segment at a time and treat a segment as a post when it runs `gh pr|issue|release|gist|discussion create|comment|edit|review|reopen`, `gh pr merge`, `gh repo|label create|edit`, a `gh api` write, `git commit`, or `tea pr|issue create|comment|edit`. It SHALL scan only the flag values that segment posts, reading a `--body-file` it names. A quoted mention of a posting command MUST NOT count as a post.

#### Scenario: Sibling segment is not read
- **WHEN** the command is `gh secret set N --body-file f && gh pr comment 5 -b hi`
- **THEN** the hook scans only `hi` and never opens `f`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash call runs `ls -la` or `gh pr view 5`
- **THEN** the hook exits 0 with no output and does not load the term source

#### Scenario: Heredoc in a commit message
- **WHEN** `git commit -m "$(cat <<'EOF' ... EOF)"` carries body lines
- **THEN** those body lines are scanned as the commit message

### Requirement: Credential tokens in a post block
`redact-external-content` SHALL block (exit 2) a post whose text, as written or as the shell passes it, carries a credential token. This block MUST hold regardless of the identity tier's mode, `CADENCE_ALLOW_SENSITIVE_TERMS`, or any repo config, and any identity or shaped findings MUST follow it in the same message.

#### Scenario: Token in a PR body
- **WHEN** `gh pr create --body` carries a live-looking access token
- **THEN** the hook exits 2 even with `CADENCE_ALLOW_SENSITIVE_TERMS=1` set

### Requirement: Identity tier blocks work-identifiable terms
`redact-external-content` SHALL load work-identifiable terms from `<account home>/.config/cadence/redaction.toml` only (the account database home, never `HOME` or `USERPROFILE`) and block (exit 2) a post carrying one, with stderr headed `redact-external-content: BLOCKED` and each term named verbatim as `[<id>] <snippet>`. No repo file MUST be able to add, remove or soften a term; only an `allow` entry in the term source (by `path`, `pattern` or `destinations`) MAY excuse a match.

#### Scenario: Term in an issue body
- **WHEN** the term source lists a term and `gh issue create --body` contains it
- **THEN** the hook exits 2 and stderr names the term's id and the matched text

#### Scenario: Repo allowlist cannot excuse it
- **WHEN** `.claude/cadence.json` `redaction.allowlist` names the same term
- **THEN** the hook still exits 2

#### Scenario: HOME set by a repo env block
- **WHEN** the hook's environment sets `HOME` to a directory with no term source and the account home has one
- **THEN** the term source in the account home is loaded and a post carrying one of its terms exits 2

### Requirement: Identity tier softening switches
A term source with `mode = "warn"` SHALL turn identity findings into a nudge that says it is not blocking; a term source with no `mode` MUST block. `CADENCE_ALLOW_SENSITIVE_TERMS` set to any value other than empty or `0` SHALL downgrade an identity block to a nudge and MUST record a bypass row naming the switch. `redact-external-content` is a protected guard, so `CADENCE_DISABLE` MUST NOT turn it off.

#### Scenario: Bypass switch armed
- **WHEN** `CADENCE_ALLOW_SENSITIVE_TERMS=1` is in the hook's environment and a post carries an identity term
- **THEN** the hook exits 0 with a nudge saying the block was suppressed and a bypass row is written

#### Scenario: Disable request refused
- **WHEN** `CADENCE_DISABLE=redact-external-content` is set and a post carries an identity term
- **THEN** the hook still exits 2

### Requirement: Identity tier fails open on its own failure
When the term source is absent, malformed, or carries zero terms, the identity tier SHALL be inert and the hook MUST allow on its account. The hook MUST NOT announce an inert state per post; `redact-scan --status`, `doctor` and SessionStart report it. When the tier is armed and a posted text could not be read (an unreadable `--body-file`, stdin), the hook SHALL say so on stderr without changing the verdict.

#### Scenario: Machine without a term source
- **WHEN** no `redaction.toml` exists and a post carries text that would match on another machine
- **THEN** the identity tier contributes nothing and the hook does not block on it

### Requirement: Unreadable term source blocks posts
When the term source exists but cannot be read, `redact-external-content` MUST block (exit 2) every post and commit message, and every `mcp__*` call, other than one to a local tool, that carries any string the identity tier reads, object keys included, naming the path and the fix, and `redact-scan` MUST exit 1 with the same message. An absent file MUST NOT trigger either.

#### Scenario: Term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file (permissions on it or its directory, a dangling link, a directory) and a Bash call posts any text or runs `git commit` with a message
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: MCP post with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an `mcp__github__create_issue` call carries a clean `body`
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: Empty MCP call with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP call's input is `{}`
- **THEN** the hook exits 0

#### Scenario: MCP call with only a key and a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP call's input is `{"page": 2}`
- **THEN** the hook exits 2

#### Scenario: Local path with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP write names a provably local path and carries a `title` beside its `content`
- **THEN** the hook exits 2

#### Scenario: redact-scan on a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and `redact-scan` scans a clean body
- **THEN** it exits 1 and stderr carries the same message

### Requirement: Identity scan of file writes
On Write and Edit calls, `redact-external-content` SHALL run the identity tier only, over introduced text, blocking only on occurrences beyond those already in the edit's `old_string`. It MUST skip the term source itself, and MUST skip a code or config file proven local (a home dotfile, `~/.ssh/config`, `~/.config`, `~/.local`, `~/.cache` or a temp dir, outside any repo, sync tree or remote mount). A prose draft MUST still be scanned.

#### Scenario: Prose draft in a temp directory
- **WHEN** a Write to `/tmp/pr-body.md` introduces an identity term
- **THEN** the hook exits 2

#### Scenario: Term carried through an edit
- **WHEN** an Edit's `old_string` holds an identity term once and its `new_string` holds it once
- **THEN** the hook exits 0

### Requirement: SSH client config is the one exempt file under ~/.ssh
`~/.ssh/config` SHALL count as a local config file for the file-write exemption only as that exact resolved path under the account home, read as config rather than a prose draft. No other path under `~/.ssh`, no path with a `..` component, and no `~/.ssh/config` that resolves elsewhere MUST be exempt by it; `~/.aws/config` and `~/.kube/config` MUST still be scanned.

#### Scenario: SSH client config
- **WHEN** an Edit to `~/.ssh/config`, a regular file outside any repo or sync tree, introduces an identity term
- **THEN** the hook exits 0

#### Scenario: Cloud and cluster configs stay scanned
- **WHEN** an Edit to `~/.aws/config`, `~/.kube/config`, `~/.ssh/config.d/x` or `~/.ssh/../.aws/config` introduces an identity term
- **THEN** the hook exits 2

### Requirement: Shaped tier nudges on harness vocabulary
`redact-external-content` SHALL scan posted bodies for four categories, `skill-id` (a skill id such as `cadence:attune`), `marketplace` (plugin-cache paths), `local-path` (`/Users/...`, `~/.claude/...`) and `harness-noun` (`tool_input`, `tool_response`), and nudge, never block, on a hit. The shaped tier MUST NOT run on Write or Edit calls, and repeated hits MUST each be listed.

#### Scenario: Skill id in a public PR
- **WHEN** `gh pr create --body` mentions `cadence:attune`, no audience is configured, and the target repo is not an owned repo
- **THEN** the hook exits 0 with a nudge listing the `skill-id` hit

### Requirement: Audience tiers decide which shaped hits report
A shaped hit SHALL report only when the destination tier is wider than its ceiling. Tiers run `owned-internal`, `private-external`, `public`; built-in ceilings are `owned-internal`, and `always` reports everywhere. The destination tier MUST come from `CADENCE_AUDIENCE`, then the config's `originAudience`, then `public`; an unknown value MUST read as `public`. When every post target is owned per `CADENCE_ALLOWED_OWNERS`, `skill-id`, `marketplace` and `harness-noun` hits MUST be dropped.

#### Scenario: Owned-internal audience
- **WHEN** `CADENCE_AUDIENCE=owned-internal` and a commit message mentions `tool_input`
- **THEN** the hook exits 0 with no shaped nudge

#### Scenario: Unknown audience value
- **WHEN** `CADENCE_AUDIENCE=everyone` and a post mentions `~/.claude/settings.json`
- **THEN** the hook nudges as for `public`

### Requirement: Per-repo redaction config
The `redaction` section of `.claude/cadence.json` SHALL tune the shaped tier only: `originAudience`, per-category `ceiling`, `additionalPatterns` and `allowlist`. A malformed key MUST be dropped and named in the nudge. A post to a repo that is none of the checkout's remotes MUST NOT inherit the checkout's allowlist, ceilings or `originAudience`. A post carrying a fenced block over 40 lines to a stated `public` audience SHALL add a pasted-output nudge.

#### Scenario: Post to a foreign repo
- **WHEN** the checkout's allowlist covers a hit and the post runs `gh issue create -R other/repo`
- **THEN** the hit is still reported, with a note naming the foreign destination

### Requirement: redact-scan CLI scan
`cadence-hooks cadence redact-scan` SHALL scan stdin, or the file named by `--file`, with the same identity and shaped tiers, printing each shaped hit to stderr as `[<category>]:<line>:<snippet>`. Exit MUST be 0 when clean, 1 on a shaped hit, an enforced identity hit or an unreadable source, and 2 on a usage error (a bad `--audience` or `--repo`, an unreadable file). `--repo OWNER/REPO` names the destination; the audience is `--audience`, then `CADENCE_AUDIENCE`, then config, then `public`.

#### Scenario: Clean body
- **WHEN** `echo "Fixes the parser" | cadence-hooks cadence redact-scan` runs
- **THEN** it exits 0 with no hit lines

#### Scenario: Shaped hit
- **WHEN** the scanned text mentions `tool_response` with no audience set
- **THEN** stderr carries `[harness-noun]:1:tool_response` and the exit status is 1

#### Scenario: Unarmed identity tier
- **WHEN** no term source exists
- **THEN** stderr carries one line saying the identity tier is not armed and the exit status is unchanged

### Requirement: redact-scan status, validation and init
`redact-scan --status` SHALL print whether the identity tier is armed, with its mode, `term_count` and `term_digest` when armed, and exit 0 armed or 1 not armed. `--validate-config` SHALL exit 0 for a valid term source and 2 with each problem on stderr. `--init` SHALL add a starter `redaction` section to `<git root>/.claude/cadence.json`, leave an existing section unchanged, and refuse (exit 2) to write through a symlink or into invalid JSON.

#### Scenario: Status without a term source
- **WHEN** `cadence-hooks cadence redact-scan --status` runs with no `redaction.toml`
- **THEN** it prints a line containing `redaction identity tier: NOT ARMED` and exits 1

#### Scenario: Init on an existing section
- **WHEN** `.claude/cadence.json` already has a `redaction` section and `--init` runs
- **THEN** the file is unchanged and the exit status is 0

### Requirement: Overshare audit triggers
`cadence warn-overshare` SHALL nudge, never block, with a `Pre-ship audit:` message asking the model to check outgoing content for personal context (health, relationships, non-technical biography), on a Bash command carrying `git push` or a posting segment as defined for `redact-external-content` (a `git commit`, and a `gh api` write that posts no prose field, excepted), and on a Write, Edit or MultiEdit to a path containing `/docs/field-reports/`. Reads, views and listings MUST be allowed.

#### Scenario: Commit nudges
- **WHEN** a Bash call runs `git commit -m 'x' && git push`, which carries a push as well as the commit
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Commit with a post nudges
- **WHEN** a Bash call runs `git commit -m 'x' && gh pr create --title t`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Push nudges
- **WHEN** a Bash call runs `git push origin main`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash call runs `gh pr view 5` or `git status`
- **THEN** the hook exits 0 with no output

#### Scenario: Quoted mention
- **WHEN** the command is `echo 'docs: gh pr comment usage'`
- **THEN** the hook exits 0 with no output

#### Scenario: Push or post after a silenced commit
- **WHEN** a commit-only command has run silently in the session, and a later Bash call runs `git push`, `gh pr create`, `gh pr comment`, `gh issue create`, `gh release create`, a `gh api` write or `gh repo edit`, or a Write targets `/docs/field-reports/x.md`
- **THEN** the first such call in that session and repo exits 0 with a nudge, and subsequent triggers in the same session and repo stay silent

### Requirement: Overshare audit escapes
`warn-overshare` SHALL allow a write whose path starts with a non-empty `OBSIDIAN_VAULT`. With `CADENCE_SKIP_OVERSHARE_AUDIT=1` exactly, it SHALL allow every call and record a bypass row only for a call that would have nudged; any other value MUST NOT silence it. It MAY also be silenced through the `nudges` map of `.claude/cadence.json`.

#### Scenario: Vault write
- **WHEN** `OBSIDIAN_VAULT=/vault` and a Write targets `/vault/docs/field-reports/x.md`
- **THEN** the hook exits 0 with no output

#### Scenario: Skip switch on an unrelated call
- **WHEN** `CADENCE_SKIP_OVERSHARE_AUDIT=1` is set and a Bash call runs `ls`
- **THEN** the hook exits 0 and records no bypass row

### Requirement: Identity scan of MCP calls
On an `mcp__*` call, `redact-external-content` SHALL run the identity tier over every string value in the call's input at any depth, object keys included, read from the payload as sent so a field that fails the typed parse is still read. The top-level `file_path`/`path` SHALL be scanned like any other string. The shaped tier MUST NOT run on MCP calls.

#### Scenario: Issue body through an MCP tool
- **WHEN** an `mcp__github__create_issue` call carries an identity term only in `body`
- **THEN** the hook exits 2

#### Scenario: Term in a nested block array
- **WHEN** an MCP call carries an identity term only in a string nested in an array of objects
- **THEN** the hook exits 2

#### Scenario: Term only in a local-looking path
- **WHEN** an MCP write's `path` is an absolute path in a system temp dir naming a directory that holds an identity term, and its `content` is clean
- **THEN** the hook exits 2

#### Scenario: Term in a repo file path
- **WHEN** an `mcp__github__create_or_update_file` call's `path` is `docs/<term>-notes.md` and its `content` is clean
- **THEN** the hook exits 2

### Requirement: MCP command strings are scanned
On an `mcp__*` call, a `command` or `cmd` string SHALL be scanned like any other string. On a local shell tool (`mcp__iterm__write_to_terminal`), the key the Bash surface reads (`command`, else `cmd`) MUST NOT get the identity tier; the credential tier SHALL still read it. A shell `command` SHALL also get the Bash-surface checks, and a nudge from the string scan SHALL be shown beside their result.

#### Scenario: Command sent to a server
- **WHEN** an `mcp__slack__run_command` call's `command` holds an identity term
- **THEN** the hook exits 2

#### Scenario: Command a local terminal runs
- **WHEN** an `mcp__iterm__write_to_terminal` call's `command` is `cd ~/<term-dir> && ls`
- **THEN** the hook exits 0

#### Scenario: Token in a local terminal command
- **WHEN** an `mcp__iterm__write_to_terminal` call's `command` holds a token
- **THEN** the hook exits 2

#### Scenario: Warn-mode finding beside a command
- **WHEN** the term source is in warn mode and an MCP call carries `command: ls` and an identity term in `body`
- **THEN** the hook exits 0 and shows the finding

### Requirement: Credential scan of MCP calls
On every `mcp__*` call, local tools included, `redact-external-content` SHALL run the credential tier over every string in the input, the top-level `file_path`/`path`, the content beside any path and old-side edit text included, with or without a term source and in every identity mode. A token MUST block, and no bypass applies.

#### Scenario: Token in an MCP issue body
- **WHEN** an `mcp__github__create_issue` call carries a GitHub token only in `body` and no term source exists
- **THEN** the hook exits 2 and the message names the token's kind without the token

#### Scenario: MCP edit removes a token
- **WHEN** an MCP edit's `old_string` holds a token and its `new_string` does not
- **THEN** the hook exits 2, since the server receives the old side too

#### Scenario: Token typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call's `text` holds a token
- **THEN** the hook exits 2

#### Scenario: Token in a file path
- **WHEN** an MCP write's `path` holds a token, local or not
- **THEN** the hook exits 2

### Requirement: Local MCP tools skip the identity tier
The identity tier MUST NOT run on a call to a local tool: `c3` `compact`, `model` or `rename`, `easel` `chart`, `herdr-bridge` `panes` or `read`, or a `rea` tool on the binary's list of rea tools that neither launch a process, reach the network, nor write files. Server and tool are the text after `mcp__` split at the next `__`, matched exactly; a tool holding another `__` is not local. Every other call SHALL get the identity tier, and every call SHALL get the credential tier.

#### Scenario: Local tool call
- **WHEN** an `mcp__herdr-bridge__read` call carries an identity term
- **THEN** the hook exits 0

#### Scenario: Prompt typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call carries an identity term
- **THEN** the hook exits 2

#### Scenario: Server that only resembles a listed one
- **WHEN** an `mcp__c3x__post` call carries an identity term
- **THEN** the hook exits 2

#### Scenario: rea tool that reaches a process or the network
- **WHEN** an `mcp__rea__gdb_console` call carries an identity term
- **THEN** the hook exits 2

### Requirement: No path exemption on MCP calls
An MCP call's `file_path` or `path` MUST NOT exempt any string from either tier, whatever it names, and a `path`-scoped allow entry MUST NOT apply to an MCP call: whether a path is local is known only for this machine, and the server that receives the call may be remote. The term source, a code or config file proven local and `~/.ssh/config` are exempt on `Write` and `Edit` only.

#### Scenario: Token beside a local-looking path
- **WHEN** an `mcp__sandbox__write_file` call's `path` is `/tmp/notes.json` and its `content` holds a token
- **THEN** the hook exits 2

#### Scenario: Local source and remote destination
- **WHEN** an MCP call's `file_path` is a provably local path and its `path` is `docs/<term>.md`
- **THEN** the hook exits 2

#### Scenario: Path-scoped allow entry on an MCP call
- **WHEN** the term source holds an allow entry scoped to `path = "docs/"` and an `mcp__github__create_or_update_file` call's `path` is `docs/x.md` with an identity term in `content`
- **THEN** the hook exits 2

### Requirement: MCP edits count against their old-side text
In an MCP call, a string under an old-side key (`old_string`, `oldString`, `old_str`, `old_text`, `oldText`) beside a new-side string MUST NOT get the identity tier; with no new-side sibling it SHALL get it. The credential tier reads it either way. A new-side string beside it (`new_string`, `newString`, `new_str`, `new_text`, `newText`, `content`) MUST block only on each term's occurrences beyond that term's occurrences in the old-side text; any other string beside it MUST be scanned in full.

#### Scenario: MCP edit removes a term
- **WHEN** an MCP edit's `oldText` holds an identity term and its `newText` does not
- **THEN** the hook exits 0

#### Scenario: MCP edit adds an occurrence
- **WHEN** an MCP edit's `oldText` holds an identity term once and its `newText` holds it twice
- **THEN** the hook exits 2

### Requirement: Overshare commit exemption
A `git commit` SHALL NOT trigger the overshare reminder when its command text never contains the word `push`, in any form: plain, after a `cd` or `git add`, with `git -C` or another global option, or with a message built by substitution. A command that also carries a push or a posting segment SHALL still trigger it, for the push or the post.

#### Scenario: Commit alone is silent
- **WHEN** a Bash call runs `git commit -m 'x'`, `cd other && git commit -m 'x'`, `git -C other commit -m 'x'` or `git commit -m "$(cat msg.txt)"`
- **THEN** the hook exits 0 with no output

### Requirement: Overshare push recognition
`warn-overshare` SHALL read a push two ways, and either SHALL trigger it: a `git` invocation whose subcommand is `push`, read past git's global options, before a separator or a `)`, and inside a subshell, group, `sh -c` script, `eval` or command substitution; and the two words `git push` side by side in the whitespace-split command, with no trimming. A word that only starts with `push`, and `push` as another subcommand's argument, MUST NOT trigger it through these two readings.

#### Scenario: Push past a global option
- **WHEN** a Bash call runs `git -C dir push`, `git -c k=v push` or `git --no-pager push`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Push ended by a separator or inside a group
- **WHEN** a Bash call runs `git push;`, `git push|cat`, `{ git push; }`, `(cd x && git commit -m y && git push)` or `bash -c 'cd x && git push'`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Wrapped push
- **WHEN** a Bash call runs `time -p git push`, `ssh host git push` or `docker exec c git push`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Words that spell the pair
- **WHEN** a Bash call runs `echo git push`, which carries the two words side by side but is not a push
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Not a push
- **WHEN** a Bash call runs `git push-something`, `git stash push` or `echo 'git push'`
- **THEN** the hook exits 0 with no output

### Requirement: Overshare commit that spells push
`warn-overshare` SHALL trigger on a commit whose command text contains the substring `push` anywhere, case-sensitive and read as raw text, so a push that reminded through its commit before still reminds in any shape that spells the word. A push that never spells the word, after a commit, SHALL NOT trigger it: that is the whole documented boundary.

#### Scenario: Commit plus a wrapped push
- **WHEN** a Bash call runs `git commit -m x && ssh host 'git push'`, `git commit -m x && docker exec c git -C d push` or `git commit -m x && make push`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Commit message that spells push
- **WHEN** a Bash call runs `git commit -m "fix: push hangs"`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Commit plus a target that never spells push
- **WHEN** a Bash call runs `git commit -m x && make deploy`
- **THEN** the hook exits 0 with no output

