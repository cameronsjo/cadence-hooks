# Wave 1: Compound-Command Guard Hardening (cadence-hooks)

## Context

The bug-hunt sweep (issues #61–#106) found that the most dangerous P0s share one
root cause: **guards re-derive shell command structure ad-hoc and get it wrong.**
Three trust-bearing guards inspect a Bash command as if it were a single command,
so a benign first segment lets a destructive second segment slip:

- **#61** `git status && git push --force origin main` — git-safety only inspects the *first* `git`.
- **#67** `gh pr comment -R me/owned 1 && gh repo delete evil/unowned --yes` — guard-gh-write resolves the *first* `-R` for the whole chain.
- **#75** `echo ok > safe.txt && echo SECRET > .env` — prevent-secret-writes inspects only the *first* redirect.

git-safety additionally mis-parses single commands three ways (**#63**): it keeps
quote characters (`"--force"` ≠ `--force`), matches only the exact token `git`
(so `/usr/bin/git` evades), and can't see into `sh -c '…'`. And its alias check
(**#62**) exempts the *entire* command line, so `git config alias.x … && git push --force origin main`
is waved through.

`core::shell` already provides quote-aware `tokenize` and a cd-chain-aware
`parse_work_dir`, but **no reusable command-segment splitter** — each guard
re-invents it. This wave builds that missing primitive once and routes the three
guards through it. P0 anchor: *silent failure to guard*. Outcome: the chain-blind
bypasses close, and no legitimate chained command starts getting falsely blocked.

**Closes this wave:** #61, #62, #63 (git-safety) · #67 (gh-write) · #75 (secret-writes) — 4 P0 + 1 P1.

## Keystone: command-segment splitting in `core::shell`

Add two pure, exhaustively-tested functions to `crates/core/src/shell.rs`
(sibling to `tokenize`/`parse_work_dir`):

```rust
/// Split a command on top-level control operators (&& || ; | & newline),
/// honoring quotes — operators inside '…' or "…" do NOT split. Segments
/// are trimmed; empties dropped. Multi-char operators (&&, ||) are matched
/// before their single-char prefixes (&, |).
pub fn split_segments(command: &str) -> Vec<String>

/// split_segments, then recursively expand shell wrappers: a segment whose
/// command word is sh/bash/zsh/dash with `-c <arg>` also yields <arg> parsed
/// as its own segments. Bounded recursion depth (3). This is the
/// "every command that will actually execute" view guards should consume.
pub fn command_segments(command: &str) -> Vec<String>
```

**Why `tokenize` (not `strip_quotes`) is the correct primitive — the crux:**
`tokenize` keeps a quoted *span* as one token. `git push "--force"` →
`["git","push","--force"]` (quoted flag → clean token → caught), but
`echo "git push --force origin main"` → `["echo","git push --force origin main"]`
(whole quoted string stays glued → never equals `"git"` → not a git command).
Span-preservation distinguishes a quoted *flag* from a command quoted *as an
argument*. Lock both into tests.

**Test matrix (core):** quote-protected operators (`git commit -m "fix: a; b"`,
`echo "x && y"` → 1 segment); each operator splits (`&&`,`||`,`;`,`|`,`&`,`\n`);
`||`/`&&` not mis-split into `|`/`&`; `sh -c 'git push --force origin main'` →
inner segment surfaced; nested `sh -c 'a && b'` → two inner segments; depth bound
honored; empty/whitespace input → `[]`. Known edge to note in a doc comment:
heredoc bodies split on newlines (accepted — favors catching the bypass).

## PR 1 — git-safety adopts `command_segments` (#61, #62, #63)

`crates/cadence/src/git_safety.rs`. Restructure `GitSafetyGuard::run`:

- Iterate `command_segments(command)`; judge each segment independently. **Block
  precedence:** any segment blocks → block; else any warns → nudge; else allow.
  The block/nudge message still quotes the original full `command`.
- Run `is_alias_definition` **per segment** (closes #62 — exempts only the config
  segment, not its siblings).
- In `normalize_git_command`, tokenize with `core::shell::tokenize` instead of
  `split_whitespace` (strips quotes → closes #63 quoted-flag). Keep the existing
  global-flag stripping.
- Match the git command word as `t == "git" || t.ends_with("/git")` in
  `check_blocked`/`check_warned` (closes #63 path/escaped git). `sh -c '…'` is
  handled upstream by `command_segments`.
- All ~80 existing tests are single-segment and must stay green.

**New tests:** `git status && git push --force origin main` → Block;
`/usr/bin/git push --force origin main` → Block; `git push "--force" origin main`
→ Block; `sh -c 'git push --force origin main'` → Block;
`git config alias.fp '…' && git push --force origin main` → Block (#62).
**False-block guards:** `echo "git push --force origin main"` → Allow;
`echo 'use git push --force carefully' && ls` → Allow;
`git commit -m "wip; reset --hard test"` → Allow.

## PR 2 — guard-gh-write per-segment target resolution (#67)

`crates/guardrails/src/guard_gh_write.rs`. The AST loop paths
(`AllTargetsExplicit`/`MissingTargets`/`ParseFailed`) already handle multi-command
loops — the gap is the **`NoLoops` + write-detection tail** (lines 496–602), which
treats the whole string as one command.

- After `LoopAnalysis::NoLoops`, iterate `command_segments(command)`. For each
  segment that `is_write_command`, resolve its target **from that segment's text**
  (`extract_repo_flag_str`/`REPO_SUBCOMMAND`/`API_REPOS` run on the segment, not
  the whole command) with the per-segment work_dir (`parse_work_dir` over the
  command prefix up to that segment). Block on the first disallowed / unresolvable
  write segment; allow only if every write segment passes.
- Preserve the structured `BlockMetadata` payloads and the unconfigured fail-safe.
- Confirm `analyze_gh_loops` returns `NoLoops` for a plain `&&` chain (add a guard
  test) so the new path actually engages.

**New tests:** `gh pr comment -R me/owned 1 && gh repo delete evil/unowned --yes`
→ Block; two owned segments → Allow; single command unchanged across the existing
suite. **False-block guard:** `gh pr list && gh issue view 1 -R me/owned` (reads)
→ Allow.

## PR 3 — prevent-secret-writes per-segment redirects (#75)

`crates/cadence/src/prevent_secret_writes.rs`. `redirect_target` (line 11) finds
only the *first* `>`/`>>` in the whole string.

- `bash_targets_env_file` iterates `command_segments(command)`; per segment, scan
  **all** redirect operators (`>`, `>>`, `>|`, `N>`, `N>>` incl. `2>`) for targets,
  plus `rm_targets`, quote-aware via `tokenize`. Block if any target is a dangerous
  `.env`.
- Scope strictly to #75 (chained/stderr/`>|`/quoted redirects). #76 (tee/cp/mv/dd),
  #86 (quote-aware false-blocks) stay for wave 2 — the existing `bash_tee_env_not_detected`
  / `bash_cp_env_not_detected` "known gap" tests remain asserting Allow.

**New tests:** `echo ok > safe.txt && echo SECRET > .env` → Block;
`echo SECRET 2> .env` → Block; `echo SECRET >| .env` → Block;
`cmd > a.txt; echo S > .env` → Block. **False-block guard:**
`echo "redirect > .env in a string" > note.txt` → Allow.

## Release

Hold the version across all three PRs (merge-train discipline, repo CLAUDE.md):
resolve any `Cargo.toml`/`Cargo.lock` version conflict to main's current value so
merges don't auto-tag. After PR 3 lands, `make bump VERSION=0.27.0` once →
`cargo check` → commit → push → `auto-tag.yml` cuts the single release. Add CHANGELOG
bullets under `[0.27.0]` attributing the five issues.

## Verification

Per PR, before commit:
- `export PATH="$HOME/.cargo/bin:$PATH" && make ci` (fmt-check + clippy `-D warnings`
  + all tests) green. Treat first GitHub CI run as the real clippy verdict (local
  toolchain may trail).
- `cargo test -p cadence-hooks-core shell::` for the keystone; per-guard module
  tests for adoption.
- Manual repro against the built binary: `cadence-hooks try cadence git-safety`
  and hand-built payloads — confirm `git status && git push --force origin main`
  now exits 2 (was 0). Same for the #67/#75 chain repros.
- Re-run the original bypass commands from issues #61/#67/#75 against
  `./target/debug/cadence-hooks` to prove each now blocks.

After the release: PR `Closes` trailers auto-close #61, #62, #63, #67, #75 on
`cameronsjo/claude-configurations`.

## Out of scope (wave 2 candidates, same primitive)

#71/#72/#73 git-safety precision · #65/#66 secret-leaks operand/verb-list ·
#76/#86 secret-writes writers/quote-FP · #78/#81/#88 gh/op/dangerous coverage.
All build on `command_segments` — cheaper once it exists.
