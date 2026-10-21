## Purpose
The contract every hook subcommand (`cadence-hooks <ns> <hook>`) follows with Claude Code: how it reads its stdin payload and answers, how it fails open, how the `CADENCE_BYPASS`, `CADENCE_DISABLE`, `CADENCE_HOOK_DEADLINE_MS` and `CLAUDE_CODE_REMOTE` variables change a run, the audit ledgers it writes, `cadence-hooks guardrails enforcement-status`, and `cadence-hooks group`.

## ADDED Requirements

### Requirement: Payload in, verdict out
A hook subcommand SHALL read one JSON payload on stdin and answer with one verdict. Allow MUST exit 0 with no output. A nudge MUST exit 0 with a stdout `hookSpecificOutput` envelope carrying `hookEventName` and `additionalContext`. An ask MUST exit 0 with `permissionDecision: "ask"` and a `permissionDecisionReason`. A block MUST exit 2 with its reason on stderr and nothing on stdout. Messages SHALL be clamped to the per-hook output budget without changing the verdict.

#### Scenario: Block goes to stderr only
- **WHEN** `cadence-hooks cadence git-safety` receives a Bash payload for `git reset --hard`
- **THEN** it exits 2, stdout is empty, and stderr starts with `BLOCKED: git-safety`

#### Scenario: Fix hint rides the block
- **WHEN** a block carries a structured fix hint and its message has no `Fix:` line
- **THEN** the hint is appended to stderr as a `Fix:` line

#### Scenario: Nudge is an envelope on stdout
- **WHEN** a SessionStart payload reaches `cadence-hooks guardrails enforcement-status` with `CADENCE_BYPASS=1` set
- **THEN** it exits 0 and stdout is one JSON object whose `hookSpecificOutput.additionalContext` carries the report

#### Scenario: Ordinary command is silent
- **WHEN** `cadence-hooks cadence git-safety` receives a Bash payload for `git status`
- **THEN** it exits 0 with no stdout and no stderr

### Requirement: Not run by hand
A hook subcommand whose stdin is an interactive terminal SHALL print guidance naming `cadence-hooks try <ns> <hook>` and a sample payload, and MUST exit 1 without waiting for input. A bare `cadence-hooks`, or a namespace with no hook, MUST exit 1 saying hooks are invoked by Claude Code plugins. An unknown subcommand or flag MUST exit 1, never 2, saying a plugin likely expects a newer cadence-hooks, and SHALL record a `version_mismatch` row in `failopen.jsonl`.

#### Scenario: Bare run in a terminal
- **WHEN** an operator runs `cadence-hooks cadence git-safety` at a terminal with nothing piped
- **THEN** it prints the `cadence-hooks try` hint to stderr and exits 1

#### Scenario: Plugin newer than the binary
- **WHEN** a plugin runs `cadence-hooks future-ns hook`
- **THEN** the exit status is 1, stderr says `unrecognized subcommand or arguments`, and the tool call proceeds

### Requirement: Fail open on the binary's own failure
Per ADR-0001 a hook's own failure MUST NOT block. A payload that is not valid JSON SHALL exit 0 with a `Failed to parse hook JSON` line on stderr and a `parse` row in `failopen.jsonl`. A panic in a check SHALL print `This hook will not block your operation.` to stderr, write a `panic` row, and exit 1. The row MUST withhold a formatted panic message, keeping only its length and the source location. A logger subcommand MUST always exit 0.

#### Scenario: Malformed payload
- **WHEN** `not json` is piped to `cadence-hooks cadence git-safety`
- **THEN** it exits 0 and `failopen.jsonl` gains a row with `"reason":"parse"` and `"subcommand":"git-safety"`

#### Scenario: Panic does not block
- **WHEN** a check panics while deciding
- **THEN** the hook exits 1, not 2, and the operation proceeds

### Requirement: Unreadable operation fields
When the payload parses but a field a guard judges is present with the wrong type, the readable fields SHALL be salvaged, and a command given as an array of strings SHALL be joined and judged. A security-critical guard whose judged field cannot be read MUST block, naming the field and never its value, and SHALL write an `unreadable_input` row. A non-critical hook MUST run on the salvaged input. A patch whose file targets cannot be enumerated MUST block on a security-critical guard.

#### Scenario: Argv-array command
- **WHEN** `tool_input.command` is `["git","reset","--hard"]` for `cadence git-safety`
- **THEN** the command is judged as `git reset --hard` and blocked

#### Scenario: Object-valued command
- **WHEN** `tool_input.command` is a JSON object for `cadence git-safety`
- **THEN** it exits 2 and stderr contains `command present with the wrong type`

#### Scenario: Advisory hook ignores the mistype
- **WHEN** `tool_input.command` is `["ls"]` for `guardrails warn-main-branch`
- **THEN** it exits 0

### Requirement: Git probe deadline
A hook SHALL bound the subprocess probes it spawns by an internal budget so it decides before Claude Code's external timeout. The budget MUST default to 3000 ms. `CADENCE_HOOK_DEADLINE_MS` SHALL clamp a positive value into 1000 to 4500 ms, fall back to the default when unparseable, and disable the budget at `0`. A probe that runs out of budget MUST degrade to the check's fail-open arm.

#### Scenario: Out-of-range override
- **WHEN** `CADENCE_HOOK_DEADLINE_MS=50` is set
- **THEN** the budget is 1000 ms

#### Scenario: Disabled budget
- **WHEN** `CADENCE_HOOK_DEADLINE_MS=0` is set
- **THEN** probes run unbounded

### Requirement: Deadline degradation is reported
When a probe ran out of budget and the final verdict is allow or nudge, the hook SHALL print a `probe deadline exceeded` line on stderr and write a `deadline` row to `failopen.jsonl`, or a `deadline_block_suppressed` row when a would-be block was lost. A run whose final verdict is block or ask MUST NOT write either row. Neither write SHALL change the verdict or exit code.

#### Scenario: Probe timeout on an allowed command
- **WHEN** a git probe exceeds the budget and the check then allows
- **THEN** the exit status is 0 and `failopen.jsonl` gains a `deadline` row naming the hook

#### Scenario: Probe timeout on a blocked command
- **WHEN** one segment's probe times out but a later segment blocks without a probe
- **THEN** the hook exits 2 and writes no deadline row

### Requirement: Cloud session policy
Every registered hook SHALL declare a remote policy of `run`, `self-disable` or `block-with-reason`. When `CLAUDE_CODE_REMOTE` is exactly `true`, a `self-disable` hook MUST exit 0 with no output before reading stdin, a `block-with-reason` hook MUST exit 2 with `is blocked in cloud sessions` and its reason, and a `run` hook SHALL behave as locally. Any other value, including `1` or `TRUE`, MUST NOT count as a cloud session.

#### Scenario: Worktree guard in the cloud
- **WHEN** `CLAUDE_CODE_REMOTE=true` and `guardrails enforce-worktree` receives any payload
- **THEN** it exits 0 with no output and does not read stdin

#### Scenario: Security guard in the cloud
- **WHEN** `CLAUDE_CODE_REMOTE=true` and `cadence git-safety` receives `git reset --hard`
- **THEN** it blocks exactly as it does locally

#### Scenario: Not the exact value
- **WHEN** `CLAUDE_CODE_REMOTE=1` and `guardrails enforce-worktree` runs
- **THEN** it runs its normal checks

#### Scenario: Machine-local hooks self-disable
- **WHEN** `CLAUDE_CODE_REMOTE=true` and a metrics logger, `guardrails warn-subagent-worktree`, `session heartbeat` or `session persist-plan-approval` runs
- **THEN** it exits 0 with no output

### Requirement: Blanket bypass
When `CADENCE_BYPASS` is exactly `1`, every hook subcommand SHALL exit 0 before reading stdin, print `all enforcement bypassed (CADENCE_BYPASS=1)` to stderr, and append a `global_bypass` row to `bypasses.jsonl`. Any other value MUST NOT bypass. The exemption MUST go by subcommand position, not by any argument: the CLI commands and the `guardrails enforcement-status` hook MUST still run.

#### Scenario: Bypassed guard
- **WHEN** `CADENCE_BYPASS=1` and `cadence git-safety` receives `git reset --hard`
- **THEN** it exits 0 and stderr carries the bypass line

#### Scenario: Truthy but not 1
- **WHEN** `CADENCE_BYPASS=yes` and `cadence git-safety` receives `git reset --hard`
- **THEN** it blocks

#### Scenario: Exempt commands
- **WHEN** `CADENCE_BYPASS=1` and `list`, `manifest`, `configure`, `doctor`, `try`, `migrate-config`, `session declare|status|plans|timer` or `metrics grade|price` runs
- **THEN** it runs normally

#### Scenario: Argument that names a CLI command
- **WHEN** `CADENCE_BYPASS=1` and `cadence-hooks metrics log-commit --prices try` runs
- **THEN** it is bypassed, because `try` is not in the subcommand position

### Requirement: Selective disable
`CADENCE_DISABLE` SHALL be read per invocation as a comma-separated list of exact hook names. A named hook that is not protected MUST exit 0 before reading stdin, print `'<hook>' disabled via CADENCE_DISABLE` to stderr, and append a `global_disable` row to `bypasses.jsonl`. A named protected guard MUST still run and SHALL print `refusing to disable protected guard '<hook>'` to stderr.

#### Scenario: Protected guard keeps running
- **WHEN** `CADENCE_DISABLE=git-safety` and `cadence git-safety` receives `git reset --hard`
- **THEN** stderr carries the refusal line and the exit status is 2

#### Scenario: Advisory hook switched off
- **WHEN** `CADENCE_DISABLE=warn-main-branch` and `guardrails warn-main-branch` runs
- **THEN** it exits 0 without reading stdin and `bypasses.jsonl` gains a `global_disable` row

#### Scenario: The protected set
- **WHEN** `CADENCE_DISABLE` names `prevent-secret-leaks`, `prevent-secret-writes`, `prevent-secret-push`, `redact-external-content`, `git-safety`, `guard-push-remote`, `guard-gh-dangerous`, `guard-gh-write`, `guard-op-vault-scan`, `guard-sops-decrypt`, `guard-runbook-scrub`, `guard-browser-device`, `guard-dotfiles`, `guard-read-model`, `trash-guard` or `enforcement-status`
- **THEN** that hook still runs

### Requirement: Session-start enforcement report
`cadence-hooks guardrails enforcement-status` SHALL run at SessionStart, MUST NOT block, and neither switch can silence it. It SHALL nudge with a report prefixed `[cadence-hooks enforcement-status]` when `CADENCE_BYPASS=1` is set, when `CADENCE_DISABLE` names a protected guard, or when an armed allow-switch is non-empty, and SHALL stay silent otherwise. It MUST print the `CADENCE_DISABLE` value only when it is a plain hook-name list of at most 120 characters, else `(value withheld)`.

#### Scenario: Bypass is reported
- **WHEN** a session starts with `CADENCE_BYPASS=1`
- **THEN** the context names every protected guard as switched off and says to check `.claude/settings.json`

#### Scenario: Armed allow-switches
- **WHEN** any of `CADENCE_ALLOW_SENSITIVE_TERMS`, `CADENCE_ALLOW_MAIN`, `CADENCE_NO_ENFORCE_WORKTREE`, `CADENCE_BYPASS`, `CADENCE_DISABLE`, `CADENCE_MARKER_DIR` or `CADENCE_METRICS_DIR` is non-empty
- **THEN** one line names each armed switch

#### Scenario: Normal session
- **WHEN** a session starts with no `CADENCE_*` switch set, outside a cloud session
- **THEN** it exits 0 with no output

### Requirement: Cloud enforcement status line
In a cloud session `enforcement-status` SHALL add `cadence-hooks: ARMED v<version>` when `CADENCE_ALLOWED_OWNERS` is non-blank, else `cadence-hooks: INERT (allowed owners not configured)`. It MUST omit that line under `CADENCE_BYPASS=1`, where the bypass report already says every guard is off.

#### Scenario: Cloud session without owners
- **WHEN** a session starts with `CLAUDE_CODE_REMOTE=true` and no `CADENCE_ALLOWED_OWNERS`
- **THEN** the context includes `cadence-hooks: INERT (allowed owners not configured)`

#### Scenario: Cloud session under the bypass
- **WHEN** a session starts with `CLAUDE_CODE_REMOTE=true`, `CADENCE_ALLOWED_OWNERS=me` and `CADENCE_BYPASS=1`
- **THEN** the context carries the bypass report and no `ARMED` line

### Requirement: Audit ledgers
Hooks SHALL append JSONL rows under the metrics directory (`CADENCE_METRICS_DIR` when non-empty, else `<config_dir>/cadence/metrics`, or an existing legacy `<config_dir>/metrics`). `denials.jsonl` gets a row per invocation that denied, asked or nudged; `bypasses.jsonl` a row whenever a switch or escape let an operation through; `failopen.jsonl` a row for every fail-open path; `hooks.jsonl` a row only for a hook slower than `CADENCE_HOOK_TIMING_THRESHOLD_MS` (default 1000).

#### Scenario: Denial row
- **WHEN** `cadence git-safety` blocks `git reset --hard`
- **THEN** `denials.jsonl` gains a row with `"hook":"git-safety"` and `"decision":"deny"`

#### Scenario: Nudge rows opted out
- **WHEN** `CADENCE_LOG_NUDGES=0` is set and a hook nudges
- **THEN** no `denials.jsonl` row is written for the nudge

#### Scenario: Fail-open reasons
- **WHEN** a hook fails open
- **THEN** the `failopen.jsonl` row's `reason` is one of `parse`, `panic`, `version_mismatch`, `unreadable_input`, `schema_drift`, `deadline`, `deadline_block_suppressed`, `group_deadline`, `group_spawn` or `unjudged`

### Requirement: Ledgers stay private and harmless
Ledger rows MUST name the hook, event, tool and repo, but MUST NOT contain command text, file paths or edited content. A failed ledger write MUST NOT change any verdict, message or exit code.

#### Scenario: Denial row carries no payload
- **WHEN** `cadence git-safety` blocks `git reset --hard`
- **THEN** the `denials.jsonl` row does not contain `reset`

#### Scenario: Read-only metrics directory
- **WHEN** the metrics directory cannot be written and a guard blocks
- **THEN** the guard still exits 2 with its unchanged stderr

### Requirement: Closed stdout
On Unix the binary SHALL restore the default SIGPIPE disposition before writing anything, so a write to a closed pipe ends the process by SIGPIPE instead of a panic, and MUST NOT write a `panic` row for it. A real write failure, such as a full disk, SHALL still panic and record a `panic` row.

#### Scenario: Output piped to head
- **WHEN** an operator runs `cadence-hooks list | head -1`
- **THEN** one line prints, no panic message appears, and `failopen.jsonl` gains no row

### Requirement: Group membership
`cadence-hooks group <ns>/<hook>...` SHALL run each listed check against one stdin payload in one process, each member on its own thread with its own git budget, panic guard, `CADENCE_DISABLE` resolution, remote policy and audit rows. Only PreToolUse and PostToolUse checks MAY join. An unknown member, a logger, a CLI action, a multi-event or session-event hook, or a duplicate MUST be skipped with a notice while the others run.

#### Scenario: Bad members do not stop the rest
- **WHEN** `group cadence/git-safety cadence/nope metrics/snapshot` receives `ls`
- **THEN** git-safety runs, stderr carries one notice each for `cadence/nope` and `metrics/snapshot`, and the exit status is 1

#### Scenario: Unknown member is logged
- **WHEN** a group lists `cadence/nope`
- **THEN** `failopen.jsonl` gains a `version_mismatch` row for it

#### Scenario: Malformed payload
- **WHEN** a group of two members receives a payload that is not JSON
- **THEN** it exits 0 and writes one `parse` row per member

### Requirement: Group results merge like separate processes
A group SHALL merge member verdicts as separate processes would: any block exits 2 with every blocker's message, then nudges and notices, on stderr; otherwise one exit-0 envelope carries every ask reason and every nudge; notices alone exit 1 on stderr. On PostToolUse an output rewrite SHALL survive a sibling block. After the git budget plus one second (9 s with the budget disabled) the group MUST emit what was decided, failing open for any member still running.

#### Scenario: One blocker among members
- **WHEN** `group cadence/git-safety cadence/terminology` receives `git reset --hard`
- **THEN** the exit status is 2 and stderr carries the git-safety block

#### Scenario: Slow member
- **WHEN** one member is still deciding when the group deadline passes
- **THEN** the group emits the other members' verdicts, logs `group_deadline` for the slow one, and adds a notice that it did not block
