# metrics Specification

## Purpose
Metrics is the local telemetry layer: fire-and-forget loggers that append JSONL ledgers (`cadence-hooks metrics snapshot`, `cadence-hooks metrics log-commit`, `cadence-hooks metrics log-subagent`, `cadence-hooks metrics log-session`, `cadence-hooks metrics log-session-start`, `cadence-hooks metrics log-polish-nudge`, `cadence-hooks metrics log-ask-user-question`, `cadence-hooks metrics log-skill`), a SessionStart staleness alarm (`cadence-hooks metrics warn-stale`), two CLI actions that read a transcript (`cadence-hooks metrics grade`, `cadence-hooks metrics price`), and two that keep the ledgers' history (`cadence-hooks metrics rotate`, `cadence-hooks metrics cat`).

## Requirements

### Requirement: Metrics directory resolution
Every metrics ledger SHALL live in one directory: `CADENCE_METRICS_DIR` when set and non-empty; else `<config_dir>/cadence/metrics` if it exists; else `<config_dir>/metrics` if it exists, resolved through any symlink; else `<config_dir>/cadence/metrics`, created on first write. `<config_dir>` MUST honor `CLAUDE_CONFIG_DIR`, falling back to `~/.claude`. Session markers SHALL live in its `state/` subdirectory, and the audit ledgers other hooks write MUST resolve to the same directory.

#### Scenario: Explicit override
- **WHEN** `CADENCE_METRICS_DIR=/tmp/m` and a commit lands
- **THEN** the row is appended to `/tmp/m/commits.jsonl`

#### Scenario: Unmigrated install
- **WHEN** `CADENCE_METRICS_DIR` is unset, `~/.claude/metrics/` exists, and `~/.claude/cadence/metrics/` does not
- **THEN** ledgers are read and appended under `~/.claude/metrics/`

#### Scenario: Fresh install
- **WHEN** neither metrics root exists
- **THEN** the first write creates `~/.claude/cadence/metrics/`

#### Scenario: Shared audit ledgers
- **WHEN** a guard denies a call, a bypass is used, a hook fails open, or a hook runs slow
- **THEN** the row lands in `denials.jsonl`, `bypasses.jsonl`, `failopen.jsonl`, or `hooks.jsonl` in that same directory

### Requirement: Ledger files are private, append-only lines
Each ledger write SHALL append exactly one compact JSON object followed by a newline in a single write. A ledger MUST be created with mode `0600` on Unix, and an existing ledger with group or other permission bits SHALL have those bits cleared on its next write. A ledger path that is a symlink MUST NOT be written through; the row is skipped instead.

#### Scenario: Permissive existing ledger
- **WHEN** `commits.jsonl` exists with mode `0644` and a commit row is written
- **THEN** the file's mode becomes `0600` and the row is appended

#### Scenario: Symlinked ledger
- **WHEN** `subagents.jsonl` is a symlink and a SubagentStart event arrives
- **THEN** nothing is written through the symlink and the hook exits 0

### Requirement: Loggers never block and stay silent
The eight loggers MUST exit 0 with no stdout on every input, including an unparseable payload, a missing field, an unwritable directory, or a panic inside the logger, and MUST NOT block or change any tool call. A logger that cannot complete SHALL skip its row. In a cloud session (`CLAUDE_CODE_REMOTE=true`) the loggers and `warn-stale` SHALL self-disable: exit 0 without reading stdin or writing anything.

#### Scenario: Garbage payload
- **WHEN** `cadence-hooks metrics log-skill` receives stdin that is not JSON
- **THEN** it exits 0 and writes no `skills.jsonl` row (the parse failure is recorded in `failopen.jsonl`)

#### Scenario: Cloud session
- **WHEN** `CLAUDE_CODE_REMOTE=true` and a `git commit` lands
- **THEN** `snapshot` and `log-commit` exit 0 and no ledger or marker is written

### Requirement: Commit detection and snapshot
`snapshot` SHALL, on a PreToolUse Bash command that runs `git commit` (or `git -C <dir> commit`, but not `git commit-tree`), write HEAD's SHA to `state/<session_id>.before`. `log-commit` SHALL, after such a command, read and delete that marker and append a `commits.jsonl` row only when HEAD moved. Both MUST no-op when the session id is empty or holds anything but ASCII letters, digits, `-`, and `_`.

#### Scenario: Nothing to commit
- **WHEN** `git commit` runs and HEAD does not move
- **THEN** no row is written and the `.before` marker is removed

#### Scenario: Ordinary command is ignored
- **WHEN** the Bash command is `git status`
- **THEN** neither logger writes anything

#### Scenario: Path-like session id
- **WHEN** the session id is `../../etc/passwd`
- **THEN** no marker or row is written

### Requirement: Cost per commit
A `commits.jsonl` row SHALL carry `commitHashBefore`, `commitHashAfter`, `branch`, `repo`, `tokens`, `byModel`, `unpricedModels`, `costUsd`, `lastMessageId`, and `sinceMarker`, pricing only transcript usage since the session's previous row. `sinceMarker` MUST be that previous row's `lastMessageId`, or `session-start` for the session's first commit.

#### Scenario: First commit of a session
- **WHEN** `git commit -m x` moves HEAD from `aaa` to `bbb` in a session with no earlier row
- **THEN** one row records `commitHashBefore` `aaa`, `commitHashAfter` `bbb`, and `sinceMarker` `session-start`

#### Scenario: Second commit
- **WHEN** the same session commits again
- **THEN** the new row's `sinceMarker` is the first row's `lastMessageId` and only usage after it is priced

### Requirement: Price table resolution
Cost SHALL be computed per model from the table at `CADENCE_METRICS_PRICES` when set and non-empty, else at `--prices <path>` (on `log-commit`, `log-session`, `grade`, and `price`), else the table embedded in the binary. For the loggers and `grade`, an unreadable or invalid override MUST fall back silently to the embedded table. A model missing from the table MUST be listed in `unpricedModels`, never priced as zero.

#### Scenario: Environment beats flag
- **WHEN** `CADENCE_METRICS_PRICES=/a.json` and `log-session --prices /b.json` runs
- **THEN** costs are computed from `/a.json`

#### Scenario: Broken override
- **WHEN** `--prices` names a file that does not parse and `log-commit` writes a row
- **THEN** the row is priced from the embedded table

#### Scenario: Override without a 1-hour cache rate
- **WHEN** an override entry gives `inputPerMTok`, `outputPerMTok`, `cacheWritePerMTok`, and `cacheReadPerMTok` but no `cacheWrite1hPerMTok`
- **THEN** the override still loads and is used

### Requirement: Subagent lifecycle
`log-subagent` SHALL append a `subagents.jsonl` row for each `SubagentStart` and each `SubagentStop` that names an agent type, with `event`, the session, agent, and parent ids, `cwd`, `transcriptPath`, and `durationMs`. A Stop with no payload `durationMs` SHALL take it from the Start. A Stop SHALL add `model`, `tokens`, `byModel`, `unpricedModels`, `costUsd` from `<parent transcript stem>/subagents/agent-<agentId>.jsonl`, `null` if missing, unreadable, over 256 MiB, or without usage.

#### Scenario: Read-only reviewer finishes
- **WHEN** a `SubagentStop` arrives and the agent's transcript has usage
- **THEN** the row carries a numeric `costUsd`

#### Scenario: Agent transcript not flushed
- **WHEN** a `SubagentStop` arrives and the agent's transcript does not exist
- **THEN** the row is written with `costUsd` `null`, not `0`

#### Scenario: Harness side agent
- **WHEN** a `SubagentStop` arrives with an empty or absent agent type
- **THEN** no row is written

#### Scenario: Duration from the Start
- **WHEN** a typed `SubagentStart` and later its `SubagentStop` arrive and the Stop carries no `duration_ms`
- **THEN** the Stop row's `durationMs` is the milliseconds between them and the Start marker is removed

#### Scenario: Unrelated event
- **WHEN** `log-subagent` receives a `SessionEnd` payload
- **THEN** it writes nothing

### Requirement: Per-session cost
`log-session-start` SHALL, on `SessionStart`, write the UTC time to `state/<session_id>.start`, and on `startup` or `clear` create an empty `state/commits/<session_id>/count`. `log-session` SHALL, on `SessionEnd`, consume the marker, scan the transcript, append a `sessions.jsonl` row with `repo`, `branch`, `reason`, `startTs`, `endTs`, `durationMs`, model costs, the commit count (`count`'s bytes, else `commits.jsonl`), and `grading`. Both MUST ignore other events and unsafe ids.

#### Scenario: Session ends after two commits
- **WHEN** a session with a start marker and two `commits.jsonl` rows ends
- **THEN** its row carries a `durationMs`, a commit count of 2, and a `grading` object, and the start marker is removed

#### Scenario: Counter outranks the ledger
- **WHEN** a session started with a commit counter ends with no commits and the ledger holds rows for its id
- **THEN** its row's commit count is 0 and `state/commits/<session>/` is removed

#### Scenario: Resumed after SessionEnd
- **WHEN** a session that already ended resumes (`source` `resume`) and ends again
- **THEN** no counter was created and its commit count comes from its `commits.jsonl` rows

#### Scenario: No start marker
- **WHEN** a session ends that has no `.start` marker
- **THEN** the row is written with `startTs` and `durationMs` null

#### Scenario: Wrong event
- **WHEN** `log-session` receives a `SessionStart` payload
- **THEN** it writes nothing

### Requirement: Polish nudge denominator
`log-polish-nudge` SHALL, after a Bash command whose first ship anchor is `gh pr ready`, a non-draft `gh pr create`, or `gh pr merge`, append a `polish_nudges.jsonl` row with `anchor`, `branch`, `repo`, `polished`, `markerPresent`, and `markerTarget`. `polished` MUST reflect a `cadence-forge:polish` run in the parent or any subagent transcript and be false when none is readable. A draft create or a command with no ship anchor MUST NOT be logged.

#### Scenario: Ready flip without polish
- **WHEN** `gh pr ready` runs and no polish run appears in the transcripts
- **THEN** a row is written with the ready anchor and `polished` false

#### Scenario: Draft create
- **WHEN** `gh pr create --draft` runs
- **THEN** no row is written

#### Scenario: One ship cannot be checked
- **WHEN** a command ships twice and one target's polish marker cannot be looked up
- **THEN** the row's `markerTarget` is `cannot_check` and `markerPresent` is false

### Requirement: AskUserQuestion stance and answers
`log-ask-user-question` SHALL append to `askuserquestion.jsonl` an `asked` row on PreToolUse with `stance` (`recommended`, `declared_no_rec`, or `silent`, classified as `warn-recommended-option` classifies it), `multiSelect`, `nQuestions`, `nOptions`, `sessionId`, and `model`, and an `answered` row on PostToolUse holding each answer verbatim with its `header` and `matchedRecommended`. A call with no questions, or no answers, MUST write nothing.

#### Scenario: Silent question asked
- **WHEN** an AskUserQuestion with two unlabeled options is about to run
- **THEN** an `asked` row with `stance` `silent` and `nOptions` 2 is appended

#### Scenario: Recommended option picked
- **WHEN** the user selects the option labeled `Use X (Recommended)`
- **THEN** the `answered` entry has `matchedRecommended` true

#### Scenario: Free-text answer mentions the marker
- **WHEN** the answer is the Other text `not the (Recommended) one`
- **THEN** the entry records that text verbatim with `matchedRecommended` false

### Requirement: Skill invocations without raw arguments
`log-skill` SHALL append one row to `skills.jsonl` for each PostToolUse `Skill` call, carrying `event` `skill`, `sessionId`, `repo` (the cwd basename), `skill`, `argsHash`, `agentId`, `agentType`, and `parentSessionId`. The skill's arguments MUST NOT be written; `argsHash` SHALL be a stable 16-hex-digit digest of them, or `null` when the call has none. Any other tool or event MUST write nothing.

#### Scenario: Skill with arguments
- **WHEN** a `Skill` call for `cadence:capture` carries args `secret idea`
- **THEN** the row's `argsHash` is 16 hex digits and the text `secret idea` appears nowhere in `skills.jsonl`

#### Scenario: Skill without arguments
- **WHEN** a `Skill` call carries no args
- **THEN** the row's `argsHash` is `null`

### Requirement: Payload key debugging
When `CADENCE_METRICS_DEBUG` is exactly `1`, `log-subagent`, `log-skill`, and `log-ask-user-question` SHALL add a `_keys` array of the raw payload's top-level keys to each row they write. Any other value MUST leave rows without `_keys`.

#### Scenario: Debug enabled
- **WHEN** `CADENCE_METRICS_DEBUG=1` and a `SubagentStart` arrives
- **THEN** the `subagents.jsonl` row includes `_keys`

### Requirement: Telemetry staleness verdicts
`warn-stale` SHALL, at SessionStart, check the top-level `*.jsonl` files in the metrics directory plus `<config_dir>/cadence/insights.jsonl` against `CADENCE_METRICS_STALE_DAYS` days (default 4; zero or junk means 4). If all are older, it SHALL nudge that telemetry is stale. If one is fresh but `commits.jsonl`, `sessions.jsonl`, `skills.jsonl`, or `subagents.jsonl` is older, it SHALL nudge that telemetry has partially flatlined, naming them. Each nudge MUST name `cadence-hooks doctor`.

#### Scenario: Whole subsystem quiet
- **WHEN** the newest watched file was written 6 days ago and the threshold is 4
- **THEN** the hook nudges `cadence-metrics telemetry is stale` and names that file and `6d`

#### Scenario: One collector died
- **WHEN** `sessions.jsonl` was written today and `commits.jsonl` 10 days ago
- **THEN** the hook nudges that `commits.jsonl (10d)` stopped writing while `sessions.jsonl` wrote

#### Scenario: Event-sparse ledger is quiet
- **WHEN** only `denials.jsonl` is older than the threshold and every continuous stream is fresh
- **THEN** the hook is silent

### Requirement: Staleness alarm fails open and fires once a day per verdict
`warn-stale` MUST NOT block. A missing or empty metrics directory, files dated more than five minutes in the future, and every read error MUST be silent, and file names MUST be sanitized before they reach the nudge. Each verdict SHALL fire at most once per UTC day, recorded in `state/stale_warn.date`; a different verdict, such as a newly stopped stream, MAY fire again the same day.

#### Scenario: Fresh install
- **WHEN** the metrics directory does not exist
- **THEN** the hook is silent

#### Scenario: Repeat the same day
- **WHEN** the same verdict already fired today
- **THEN** the hook is silent

#### Scenario: Another stream stops later that day
- **WHEN** a flatline naming `commits.jsonl` fired this morning and `skills.jsonl` has since crossed the threshold
- **THEN** the hook nudges again naming both streams

### Requirement: Session grade CLI
`cadence-hooks metrics grade` SHALL print one transcript's grading as pretty JSON. The transcript SHALL be `--transcript <path>`, else the single `<id>.jsonl` under the config directory's `projects/*/` for `--session-id <uuid>` or `$CLAUDE_CODE_SESSION_ID`. It MUST exit 1 with a `metrics grade:` reason on stderr when no transcript is named, the id is not UUID-shaped, zero or several transcripts match, or the file is unreadable. `CADENCE_BYPASS=1` MUST NOT stop it.

#### Scenario: Grade by session id
- **WHEN** `cadence-hooks metrics grade --session-id <uuid>` runs and exactly one project directory holds `<uuid>.jsonl`
- **THEN** stdout holds JSON with `wallClockMs`, `gaps`, `coldRestartUsdTotal`, `peakContextTokens`, `compactions`, `turnsPerPrompt`, `flags`, and `config`, and the exit status is 0

#### Scenario: Nothing to grade
- **WHEN** `metrics grade` runs with no flags and `CLAUDE_CODE_SESSION_ID` unset
- **THEN** the exit status is 1 and stderr names `--transcript` and `--session-id`

#### Scenario: Ambiguous session id
- **WHEN** two project directories both hold `<uuid>.jsonl`
- **THEN** the exit status is 1 and no grading is printed

### Requirement: Transcript price CLI
`cadence-hooks metrics price --transcript <path>` SHALL print one JSON line with `costUsd`, `byModel`, and `unpricedModels`, matching a `sessions.jsonl` row for that transcript, and exit 0 on a readable transcript. It MUST exit 1 with a `metrics price:` reason on stderr when the file is missing, unreadable, not a regular file, or over 512 MiB, or when a named price table is invalid. `CADENCE_BYPASS=1` MUST NOT stop it.

#### Scenario: Unknown model
- **WHEN** the transcript uses a model absent from the price table
- **THEN** the exit status is 0 and that model is listed in `unpricedModels`

#### Scenario: Broken price table is not ignored
- **WHEN** `CADENCE_METRICS_PRICES` names a file that does not parse
- **THEN** the exit status is 1 and no cost is printed

#### Scenario: Path is a FIFO
- **WHEN** `--transcript` names a named pipe
- **THEN** the command exits 1 promptly with a reason that it is not a regular file

#### Scenario: Transcript with no usage
- **WHEN** the transcript holds no assistant usage
- **THEN** it prints `costUsd` 0 with empty lists and exits 0

### Requirement: Ledgers rotate past a size cap
A ledger write that finds its `<metrics_dir>/*.jsonl` ledger at or past the cap SHALL move it to `<name>.<YYYYMMDDTHHMMSSZ>-<NNN>.jsonl` beside it (`<NNN>` counts earlier rotations that second) and append to a fresh `0600` file. The move MUST NOT replace an existing file. The cap is `CADENCE_METRICS_MAX_BYTES` bytes (16 MiB default; `0` is off; empty, unparsable or under 1 MiB keeps the default). Unix only. A history reader SHALL read segments in name order, then the live file.

#### Scenario: Ledger at the cap
- **WHEN** `denials.jsonl` holds at least the cap and a denial row is written
- **THEN** the old content is in one `denials.<stamp>-000.jsonl` segment, `denials.jsonl` holds only the new row, and both files are mode `0600`

#### Scenario: Every generation kept
- **WHEN** `denials.jsonl` rotates three times within one second
- **THEN** three segments exist (`<stamp>-000`, `<stamp>-001`, `<stamp>-002`), each holding its own generation, and reading the ledger returns every row oldest first

#### Scenario: Older generation replaced
- **WHEN** a segment from an earlier rotation exists and `denials.jsonl` rotates again
- **THEN** the earlier segment is unchanged (no generation is ever replaced) and a new segment holds the rotated content

#### Scenario: Segment name already taken
- **WHEN** a file already exists at the segment name a rotation would use
- **THEN** that file is unchanged and the rotation uses the next sequence number

#### Scenario: Rotation off
- **WHEN** `CADENCE_METRICS_MAX_BYTES=0` and a ledger is far past 16 MiB
- **THEN** the row is appended and no segment appears

### Requirement: Rotation is safe for concurrent writers and never blocks a hook
The rotator MUST take a non-blocking `flock` on the live file and move it only when the path still names the file it holds, so concurrent writers lose no row and never rotate a fresh ledger out from under a newer generation. A rotation error MUST NOT fail or block the hook: it is recorded as a `ledger_rotate_failed` row in `failopen.jsonl` (never for `failopen.jsonl` itself) and the row is still appended.

#### Scenario: Rotation fails
- **WHEN** the move cannot happen (every segment name for the stamp is taken)
- **THEN** the hook exits 0 as usual, the row is appended to the live ledger, and `failopen.jsonl` gains a `ledger_rotate_failed` row naming the ledger

#### Scenario: A writer holding the old file
- **WHEN** a process opened the ledger before another rotated it and then finds it past the cap
- **THEN** it does not move the fresh ledger aside, and appends to the live file

#### Scenario: Concurrent writers across a rotation
- **WHEN** eight writers append 250 rows each and the ledger crosses the cap several times
- **THEN** every row is in a segment or the live file exactly once, and every line parses

### Requirement: Per-session state is cleared at SessionEnd
`log-session` SHALL remove `<state>/subagents/<session>/` and `<state>/bypass/<session>/` at `SessionEnd` for a session id safe in a path, and leave every other session's state alone.

#### Scenario: Session ends with markers
- **WHEN** a session with a pending subagent Start marker and a bypass claim ends
- **THEN** both directories for that session are gone and another session's markers remain

### Requirement: Segments past retention are archived, never dropped
`cadence-hooks metrics rotate` SHALL move every rotated segment older than its window (by segment stamp: `denials` 90 days; every other ledger 180 days, the never-dropped `commits`, `sessions` and `plan-links` included) into `archive/<ledger>.<YYYY-MM>.jsonl.gz`, the month of the stamp. It MUST NOT drop a row or touch a live `*.jsonl` file. It SHALL hold an exclusive non-blocking `flock` on `state/rotate.lock`; a run that loses it prints a skip line and exits 0.

#### Scenario: Window boundaries
- **WHEN** `denials` segments stamped 89 and 91 days ago and `commits` segments stamped 179 and 181 days ago exist
- **THEN** only the 91-day and 181-day segments move to their monthly archives, and the row multiset across archives and segments is unchanged

#### Scenario: Second run
- **WHEN** `metrics rotate` runs again with nothing new past its window
- **THEN** it archives nothing and every archive and rollup is byte-identical

#### Scenario: Lock held
- **WHEN** another run holds `state/rotate.lock`
- **THEN** the run changes nothing and exits 0

### Requirement: Archive moves survive a crash
Before each move `metrics rotate` SHALL write `state/rotate-manifest.json` naming the segment, archive, row count, sha256 and archive length. The archive MUST grow only by a temp file holding its old bytes plus a new gzip member, fsynced and renamed over it. The segment SHALL be deleted only after that member decodes to its bytes, then the manifest. A run SHALL first finish or roll back a leftover manifest and MUST NOT archive a segment twice.

#### Scenario: Killed after the archive rename
- **WHEN** a run stops after renaming the new archive and before deleting the segment, and `metrics rotate` runs again
- **THEN** the segment is deleted without a second append, and every row is stored exactly once

#### Scenario: Killed before the archive rename
- **WHEN** a run stops after writing the manifest or the temp archive
- **THEN** the next run removes the temp file and manifest, archives the segment once, and loses no row

### Requirement: Denial rollups
Before archiving rows of a `denials` segment, `metrics rotate` SHALL append to `rollups/denials-daily.jsonl` one row per (day, hook, repo, decision) with its `count`, the `segment` name and the moved byte range (`movedSha256`, `movedLen`), in one write. Only rows past a recorded range that is a prefix of the bytes moved SHALL be rolled up; a row with no range covers the whole segment.

#### Scenario: Killed after the rollup
- **WHEN** a run stops after appending a segment's rollup rows and `metrics rotate` runs again
- **THEN** the segment is archived and its rows are counted in the rollup once

#### Scenario: One segment moved twice
- **WHEN** a move leaves a row appended during it in the segment, and a later run archives that row
- **THEN** the rollup counts equal the rows archived

#### Scenario: Killed after the rollup, then appended to
- **WHEN** a run stops after the rollup, a row is appended to the segment, and `metrics rotate` runs again
- **THEN** the rollup counts equal the rows archived

### Requirement: Stale per-session state is swept
`metrics rotate` SHALL remove `state/subagents/<session>/`, `state/bypass/<session>/` and `state/commits/<session>/` when the newest entry inside is older than 7 days. It MUST only remove real directories whose name passes the session-id check, under parents that are real directories, and MUST NOT follow a symlink.

#### Scenario: A session that never ended
- **WHEN** `state/subagents/<id>/` was last written 8 days ago and `state/subagents/<other>/` 6 days ago
- **THEN** the first is removed and the second stays

#### Scenario: Symlinked state
- **WHEN** `state/bypass/<id>` or `state/commits` is a symlink to a directory with old entries
- **THEN** nothing the symlink points at is removed

### Requirement: Rotate success marker, failures and file modes
`metrics rotate` SHALL write the UTC time to `state/rotate.last-success` only after a complete run. Any failure SHALL append a `metrics_rotate_failed` row to `failopen.jsonl` and exit 1. Files it creates MUST be `0600` and directories `0700`, opened without following a symlink; a symlinked `archive/`, `rollups/` or `state/` is a failure, never written through.

#### Scenario: Symlinked archive directory
- **WHEN** `archive/` is a symlink and a segment is past its window
- **THEN** the run exits 1, `failopen.jsonl` gains a `metrics_rotate_failed` row, and nothing is written through the symlink

### Requirement: Daily archive at SessionStart
`metrics log-session-start` SHALL run the archive at most once per UTC day. It writes `state/rotate.day` before the run, so a failed or skipped run waits for the next day. It SHALL stop between segments after 2 seconds and skip segments over twice the rotation cap, leaving both for a later run. A run that stops early or skips a segment MUST NOT write `state/rotate.last-success`. It MUST fail open: a failure is a `failopen.jsonl` row and never changes the hook's exit.

#### Scenario: Second session the same day
- **WHEN** a second session starts on the same UTC day
- **THEN** no archive run happens

#### Scenario: A segment over the bound
- **WHEN** the SessionStart run finds a 9 MiB segment past its window beside a small one
- **THEN** the small one is archived, the large one stays for `metrics rotate`, and `state/rotate.last-success` is not written

### Requirement: Test-row quarantine
`metrics rotate --quarantine-test-rows` SHALL move `denials` rows whose `sessionId` is absent, null or not a UUID out of the live file and its segments into `archive/denials.testrows.jsonl.gz`, where `cat --include-test-rows` still reads them. It MUST move the live file aside first under the rotation `flock`, rewrite each segment under its own name through a temp file, and use the manifest discipline. Every real run SHALL write `state/quarantine-<date>.json`. `--dry-run` changes nothing.

#### Scenario: Quarantine run
- **WHEN** the live file and two segments hold three non-UUID rows among UUID rows
- **THEN** the three rows are in the test-row archive, the UUID rows stay in their segments, and the record names the host, per-file counts and source sha256

#### Scenario: Dry run
- **WHEN** `--quarantine-test-rows --dry-run` runs
- **THEN** it prints the counts and every file is byte-identical

#### Scenario: Concurrent appender
- **WHEN** hooks append denial rows while the quarantine runs
- **THEN** every appended row is stored exactly once, and a second run moves nothing it already moved

#### Scenario: Nothing to move
- **WHEN** a quarantine run finds no test rows
- **THEN** it still writes its record

### Requirement: Ledger cat
`cadence-hooks metrics cat <ledger>` SHALL print the ledger's monthly archives in month order, then its segments in name order, then the live file, one row per line. A segment whose bytes a leftover manifest shows already archived MUST print once. `--since` keeps rows whose `ts` is at or after it. `--include-test-rows` prepends the test-row archive for `denials`. A name other than letters, digits, `-` and `_` exits 2.

#### Scenario: History in order
- **WHEN** a ledger has two monthly archives, two segments and a live file
- **THEN** `metrics cat` prints the January archive, the February archive, the segments, then the live rows

#### Scenario: Half-done move
- **WHEN** a crash left a manifest whose archive already holds its segment
- **THEN** `metrics cat` prints that segment's rows once

### Requirement: A damaged archive is never appended to
Before growing an archive, `metrics rotate` and `--quarantine-test-rows` SHALL decode it to the end. When that fails, the move MUST fail with a `metrics_rotate_failed` row naming the archive, the source segment MUST stay, and the archive MUST be left byte-identical. The message SHALL give commands that save the intact members under the archive's name, quote every path as one word, and stop without moving anything when `<name>.damaged` exists.

#### Scenario: Truncated monthly archive
- **WHEN** `archive/denials.2026-07.jsonl.gz` ends in a truncated member and a July segment is past its window
- **THEN** the run exits 1, the segment and the archive are unchanged, and no manifest is left

#### Scenario: Salvage
- **WHEN** the operator runs the commands the message gives and then `metrics rotate`
- **THEN** every row of the intact members is kept, no partial row is, and the segment is archived

#### Scenario: Hostile name
- **WHEN** the archive name holds a quote, a `$(…)` substitution, a space and a leading `-`
- **THEN** the commands parse, run nothing from the name, and write only inside the archive directory

#### Scenario: Second salvage
- **WHEN** the commands run again while `<name>.damaged` exists
- **THEN** they exit non-zero and the first `.damaged` copy is byte-identical

### Requirement: Cat reads under the rotate lock
`metrics cat` SHALL hold a shared `flock` on `state/rotate.lock` for its whole read, waiting for a running move to finish. A rotate that starts while it reads SHALL find the exclusive lock unavailable and skip, so no row prints twice or goes missing.

#### Scenario: Rotate starts mid-read
- **WHEN** a rotate starts while `metrics cat` is printing an archive and a segment of that month is past its window
- **THEN** the rotate skips and `metrics cat` prints every row once

### Requirement: Rotate runs only on Unix
Off Unix, `metrics rotate` and `--quarantine-test-rows` SHALL exit 1 with a message and change nothing, and the SessionStart run SHALL do nothing, until a run lock exists there.

#### Scenario: Windows
- **WHEN** `metrics rotate` runs on Windows
- **THEN** it exits 1 and no file under the metrics directory changes

### Requirement: Denials archive waits for the quarantine
`metrics rotate` MUST NOT archive a `denials` segment until a `state/quarantine-*.json` record exists. Such segments SHALL count as waiting: the run is partial, writes no `state/rotate.last-success`, and the CLI prints one line naming `--quarantine-test-rows`. Other ledgers archive as usual.

#### Scenario: Before and after the quarantine
- **WHEN** a `denials` segment and a `commits` segment are past their windows and no quarantine record exists
- **THEN** only the `commits` segment is archived; after a quarantine run, the next run archives the `denials` segment

### Requirement: Cat reports read failures
`metrics cat` SHALL treat only an absent `archive/` as empty; any other error listing it MUST fail naming the directory. Every read error SHALL name its file. When the lock file cannot be opened or created for lack of permission or a read-only filesystem, `cat` SHALL print a stderr note and read unlocked.

#### Scenario: Unreadable archive directory
- **WHEN** `archive/` cannot be listed
- **THEN** `metrics cat` exits 1 naming `archive/`

#### Scenario: Read-only state directory
- **WHEN** `state/` is not writable and holds no lock file
- **THEN** `metrics cat` prints every row

### Requirement: Recovery checks what a manifest names
Recovery and `metrics cat` SHALL share one judgement of a leftover manifest. An `archive` manifest must name its segment's own month, and its member must decode to the segment's first `source_len` bytes. A `quarantine` manifest must name a `denials` segment and the test-row archive, and its member must be exactly those bytes' test rows. An unproven manifest MUST change nothing on disk, and `cat` SHALL print that segment as it is.

#### Scenario: Forged quarantine manifest
- **WHEN** a `quarantine` manifest names a `sessions` segment and the test-row archive
- **THEN** the run exits 1 and the segment is byte-identical

#### Scenario: Tail is another segment's content
- **WHEN** an `archive` manifest's archive tail decodes to rows that are not its segment's
- **THEN** the run exits 1, the segment is byte-identical, and `metrics cat` prints its rows once

#### Scenario: Unrelated test-row member
- **WHEN** a `quarantine` manifest on a `denials` segment points at a test-row member holding other rows
- **THEN** the run exits 1, no row is stripped, and `metrics cat` prints every row of the segment

### Requirement: Rows appended after an archive read stay
When a proven move's segment has grown past `source_len`, recovery SHALL leave only the appended bytes in the segment (after the kept rows for a quarantine) and clear the manifest. Before that, `metrics cat` SHALL print the archived member and only the appended bytes.

#### Scenario: Append after the archive rename
- **WHEN** a run stops after renaming the new archive, a row is appended to the segment, and `metrics rotate` runs again
- **THEN** the manifest is cleared, the appended row is kept, and every row is stored and printed once

### Requirement: No salvage commands for names that display differently
When a damaged archive's name or directory changes under `display_safe`, the message MUST give no commands and SHALL say to rename the file to a plain name by hand.

#### Scenario: Zero-width character in the name
- **WHEN** a damaged archive's name holds U+200B
- **THEN** the displayed message holds no `mv` command and names the rename-by-hand step

### Requirement: A rewritten segment is recorded first
Before a move replaces or empties a segment that keeps bytes, the manifest SHALL record the sha256 and length of exactly what the segment will hold, durably. A segment equal to that record SHALL read as finished, so a crash after the rewrite never blocks a later run. Both forward moves SHALL finish through the same judgement as recovery, re-reading the segment.

#### Scenario: Killed inside recovery
- **WHEN** recovery of a move with a late append is killed after recording, after the temp file, or after the rewrite
- **THEN** `metrics cat` prints every row once, and the next run finishes and clears the manifest

### Requirement: Only whole rows move
A move SHALL hold back a last row with no newline only while its segment changed within the last minute (or over a day in the future); an older segment's last row SHALL move with the rest, closed with a newline, and bytes appended after that read SHALL stay as their own fragment. A quarantine whose moved prefix ends mid-row and has bytes after it MUST be unproven. A writer still holding the file open after the move re-reads it loses its later writes.

#### Scenario: Last row half written
- **WHEN** a fresh segment is read while its last row is half written, and the writer appends the rest by path before the move re-reads it
- **THEN** the row is whole, parses, and is stored in exactly one place

#### Scenario: Old segment ends mid-row
- **WHEN** a segment past retention, unchanged for over a minute, ends in a fragment with no newline
- **THEN** one run archives it whole, the segment is gone, and `metrics cat` prints the fragment once

#### Scenario: Old fragment finished after the read
- **WHEN** the writer of an old segment's fragment appends its end after the move read the segment
- **THEN** the run completes, the archive holds the fragment as read, the end stays in the segment as its own fragment, and `metrics cat` prints each once
