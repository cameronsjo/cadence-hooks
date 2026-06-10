# Bug Hunt: cadence-hooks Full Sweep

> Approved plan, 2026-06-09. Execution: `cadence-forge:bug-hunt` multi-agent sweep. Findings filed as GitHub issues on `cameronsjo/claude-configurations`. **Files only — never patches.**

## Context

cadence-hooks is the enforcement binary that polices every tool call in every Claude Code session, every day — 48 hooks across 7 namespaces (~24.5k LOC, 8 crates). Cameron asked for a review of this code because it is trust-bearing infrastructure: a defect here either silently fails to guard (irreversible lost work) or falsely blocks legitimate work (daily friction).

## Activation (confirmed with user)

- **Surface**: Full sweep — all namespaces (cadence, guardrails, rules, obsidian, metrics, lab, session, plus dispatch/registry/core)
- **Critical path / P0 anchor**: **Silent failure to guard** — git-safety missing a destructive op, a guard not firing when it should. False blocks are P1-grade friction; missed guards are P0.
- **Destination**: GitHub issues on `cameronsjo/claude-configurations` (the ecosystem tracker), label `cadence-hooks`, filed via a `scripts/` filing script
- **Depth**: High-signal only — 4–8 strong findings per agent, speculative findings dropped

## Severity rubric (anchored)

| Severity | Meaning here |
|----------|-------------|
| P0 | A guard that silently fails to fire on the thing it exists to block (destructive git op slips through, secret leak guard evaded, fail-open masking a real block condition); state corruption that lies to peer sessions |
| P1 | Guard degradation — false blocks on legitimate work, broken check logic, dispatch/registry skew reaching production |
| P2 | Recoverable misbehavior — wrong nudge text, stale state mishandling, rough edges in CLI actions |
| P3 | Latent risk with no trigger today, polish |

## Do-NOT-refile list (existing issues)

Open, cadence-hooks-adjacent:
- #53 warn-going-public — nudge on repo create/publicize (feature request, not a bug)
- #25 RFC: typed hooks.json builder to centralize plugin path quoting
- #22 tracker: apply effort-gating to identified hooks

Closed (do not rediscover):
- #23/#24 hooks.json single-quoted `${CLAUDE_PLUGIN_ROOT}` — fixed
- #11 snooze/dismiss for warn-main-branch — shipped (dismiss-main-branch-warn)
- #9 guard-push-remote blocking self-hosted Gitea — fixed
- #20 PostToolUse block semantics verification — done

## Workspace map (from exploration)

| Crate | LOC | Contents |
|-------|-----|----------|
| core | 4,394 | HookInput/payload parsing, Check/Logger traits, outcome→exit-code, config/allowlist parsing, shell tokenizing, fail-open machinery |
| cadence | 5,776 | 12 PreToolUse checks: terminology, git-safety, secret leak/write guards, orphaned-todos, memory-guard, markdown-lint, … |
| guardrails | 7,798 | 17 checks + snooze CLI: guard-push-remote, guard-gh-write/dangerous, warn-main-branch, check-idle-return, guard-browser-device, inject-gh-context, … |
| rules | 1,197 | validate-frontmatter (edit simulation), security-patterns |
| session | 2,381 | Session registry (.claude/sessions/), heartbeat (mtime liveness), lane guard, branch drift |
| metrics | 1,364 | Fire-and-forget JSONL loggers: log-commit (token cost), log-subagent, snapshot |
| lab | 1,310 | Persona ledger (nudge + gate) |
| obsidian | 253 | trash-guard |
| src/ (binary) | — | main.rs clap dispatch, registry.rs HOOKS catalog, try_hook, configure, doctor |

Persistent state: `.claude/sessions/*.json` (mtime = liveness), `.git/cadence-hooks/main-branch-snoozed-until`, tmp idle markers, `~/.claude/persona/personas.jsonl`, metrics JSONL.

## Key exploration findings shaping the hunt

- **18 checks produce hard blocks** (exit 2); the rest nudge. The P0 anchor (silent failure to guard) concentrates attention on: git-safety command normalization (`crates/cadence/src/git_safety.rs:32-92`), secret guards' quote-aware chain splitting, gh/push allowlist evaluation (`crates/core/src/config.rs`, `shell.rs::host_and_repo_from_url`), and the fail-open machinery itself (`crates/core/src/lib.rs:678-722` — does fail-open ever silently disable a guard that should have fired?).
- **`effective_content()` returns `None` on unreadable files → allow** — by design, but every content guard inherits this bypass shape.
- **Session ledger has no file locking** — mtime liveness, concurrent JSON writes assumed atomic; heartbeat has 3 tests.
- **Path exclusions are substring matches** — e.g. terminology excludes any path containing `cadence-hooks/` (`terminology.rs:118-124`); lane matching in `session/guard.rs:203-223` is contains/starts_with/ends_with.
- **Test coverage is broad (1,505 unit + 75 integration) but uneven** — thin: guard-browser-device (4), heartbeat (3), issue-refs (4), warn-cron-datetime (7), markdown-lint (8). The meta-tests (registry sync, hooks.json audit) are healthy.

## Agent decomposition (8 hunt agents, one parallel dispatch)

Each agent gets: project context paragraph, the P0 anchor, **named files**, subsystem-tailored hunt categories, the do-not-refile list, output format (markdown table: file:line, repro, expected/actual, severity), constraints (no fixes, cite real file:line, skip style/test-gaps, 4–8 strong findings). Agents inherit the session model (Fable 5) — security-shaped hunting gets the deep-judgment tier per Cameron's model-fit rule.

| # | Domain | Files | Tailored lens |
|---|--------|-------|---------------|
| 1 | git-safety evasion | `crates/cadence/src/git_safety.rs`, `crates/core/src/shell.rs` | Destructive ops slipping the normalizer: env-prefixed (`GIT_DIR=x git push -f`), `command git`/absolute-path git, `sh -c`/`xargs` wrapping, alias special-case abuse, protected-branch token-match gaps, quote stripping vs chaining |
| 2 | Secret guards | `crates/cadence/src/prevent_secret_leaks.rs`, `prevent_secret_writes.rs`, `secret_patterns.rs` | Leak/write evasion: chain-operator splitting edge cases, `.env` variant gaps, case/symlink/relative-path evasion; plus false-positive traps (.env.example) |
| 3 | gh/push ownership guards | `crates/guardrails/src/guard_push_remote.rs`, `guard_gh_write.rs`, `guard_gh_dangerous.rs`, `crates/core/src/config.rs`, `shell.rs` (URL parsing) | Allowlist evaluation: SSH/SCP/HTTPS/git:// parsing divergence, host/owner case + `.git` suffix + port handling, `-R` flag extraction, multi-command shells, fail-safe-block vs fail-open inconsistency |
| 4 | Dispatch + fail-open core | `src/main.rs`, `src/registry.rs`, `crates/core/src/lib.rs` | Machinery that silently disables guards: `effective_content()` None→allow shapes, CADENCE_DISABLE/BYPASS parsing, effort gating, panic hook, Block→PreToolUse deny envelope correctness, LoopBlock semantics |
| 5 | Session coordination | `crates/session/src/registry.rs`, `identity.rs`, `guard.rs`, `heartbeat.rs`, `branch_drift.rs`, `start.rs`, `cli.rs` | Concurrency without locks: heartbeat/sweep races, stale sweep killing live sessions, lane substring matching false negatives, peer-field sanitization, `ensure_git_excluded` edge cases |
| 6 | Stateful guards (thin coverage) | `crates/guardrails/src/check_idle_return.rs`, `guard_browser_device.rs`, `dismiss_main_branch_warn.rs` + `warn_main_branch.rs`, `warn_cron_datetime.rs`, `guard_dotfiles.rs`, `guard_op_vault_scan.rs`, `crates/obsidian/src/trash_guard.rs` | Marker-file lifecycle: tmp-dir collisions/permissions, repo-hash collisions, snooze expiry math, device-confirm marker scope, vault/dotfiles path-boundary checks |
| 7 | Content validators | `crates/rules/src/validate_skill_frontmatter.rs`, `check_security_patterns.rs`, `crates/cadence/src/terminology.rs`, `block_orphaned_todos.rs`, `memory_guard.rs`, `markdown_lint.rs`, `validate_line_endings.rs` | Edit-simulation correctness, substring exclusion over/under-matching, the known false-PASS shape (frontmatter no-op off `skills/` paths) generalized to other validators, introduced-vs-preexisting term detection |
| 8 | Loggers + lab | `crates/metrics/src/log_commit.rs`, `log_subagent.rs`, `snapshot.rs`, `compute_cost.rs`, `scan_tokens.rs`, `prices.rs`, `crates/lab/src/gate.rs`, `nudge.rs`, `config.rs` | Fire-and-forget integrity: JSONL append interleaving, transcript parsing assumptions, price-table drift, persona ledger growth/validation gaps — mostly P2/P3, capped attention |

## Workflow

0. Post-approval housekeeping (cadence rules): copy this plan to `docs/plans/2026-06-09-bug-hunt-cadence-hooks.md`, write plan path + summary to auto memory
1. Save critical-path framing as feedback memory (durable; future audits reuse it)
2. Dispatch hunt agents in parallel (one message), each with: project context, P0 anchor, named files, subsystem-tailored bug categories, do-not-refile list, output format (file:line + repro + expected/actual + severity), constraints (no fixes, 4–8 strong findings)
3. Spot-check 2–3 most surprising/severe claims against actual files before filing
4. Triage: drop dupes/speculative, recalibrate severity vs P0 anchor, merge same-root-cause findings
5. Write `scripts/file_bug_hunt_cadence_hooks_issues.sh` (per bash discipline — no inline gh loops); ensure `cadence-hooks` label exists (self-heal per ecosystem convention); file with `-R cameronsjo/claude-configurations`
6. Report: count by severity, top issues by likely real-world hit rate, offer to commit/discard the script

## Verification

- Spot-check phase (step 3) is the correctness gate on agent claims — read the cited lines in the real files
- After filing: `gh issue list -R cameronsjo/claude-configurations --label cadence-hooks --state open` count matches the filed count
- No code changes to verify — this hunt files issues only
