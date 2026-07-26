# ADR-0001: Guards fail open on their own failure

## Status

Accepted. Cited across ~12 sites in the codebase (`grep -rn "ADR-0001"`), including
`enforce_worktree.rs`, `warn_main_branch.rs`, and `core::markers`.

## Context

Every hook subcommand in this binary is a `PreToolUse`/`PostToolUse` check wired into
Claude Code's tool pipeline. A hook that exits 2 blocks the tool call outright; a hook
that exits 0 or 1 allows it. That gives every guard a choice, on any internal failure of
its own — a git command that errors, a file it can't read, a payload it can't parse — of
whether to block or allow.

The exit-code contract this repo has settled on: **a guard's own failure must never
block the user.** Parse failures, unreadable files, missing git, and unknown subcommands
all exit 0 or 1 — never 2. A discipline guard existing to reduce friction cannot itself
become the friction; a security guard that fails closed on its own bugs turns every
internal edge case into an outage for someone trying to get work done.

This is why, for example, `enforce_worktree::repo_root_for` returns `None` (and the
caller allows) when `git rev-parse --show-toplevel` fails for any reason — a nonexistent
directory, git not on `PATH`, a corrupted repo — rather than treating the failure as
grounds to block. The same pattern recurs throughout: `dismiss_enforce_worktree::is_snoozed_now`
returns `false` (not snoozed) on an unreadable marker; `is_temp_root` and `is_claude_managed_dir`
degrade to their permissive branch on any resolution failure.

## Decision

**Fail open on the guard's own failure. Never fail open on a miss.**

These are different things, and the difference matters:

- **Fail-open** is what happens when the guard *cannot determine* whether its own
  precondition holds — git isn't available, a path doesn't resolve, a marker file is
  corrupt. In this situation the guard has no confident answer, so it defers to the user
  rather than pretend one.
- **A miss** is what happens when the guard's own parsing logic sees *less of the
  command than the shell will actually execute* — a heredoc body it fails to strip
  correctly, a substitution it doesn't expand, a `cd` prefix it silently drops. This is a
  bug in the guard, not an instance of the guard correctly recognizing its own
  uncertainty. A miss means a genuinely dangerous or discipline-violating command reaches
  no guard at all, and ADR-0001 does not excuse it.

The distinction was hard-won. 0.29.0 (`core::shell`, issue #116 on
`claude-configurations`) modeled heredoc bodies, command substitutions, and visible
variable assignments in `split_segments`/`command_segments`, fixing a real false-block
from 0.28.0 (a heredoc body line like `see the .env file` was being parsed as its own
fake `see` command). The fix itself — stripping heredoc bodies before segment-splitting
— then needed an adversarial security review (framed explicitly as "find inputs where a
dangerous command slips through unseen," not "does this pass its own tests") before it
could be trusted: happy-path TDD and full CI (96 core tests passing) could not surface
the case where the parser's heredoc-terminator detection was narrower than bash's own,
letting a real trailing command — one bash would still execute — disappear from every
downstream guard's view. That's a Critical-severity miss, not a benign fail-open; the fix
was to strip a heredoc body *only* when its terminator is unambiguously located, keeping
(not dropping) the lines whenever detection is uncertain. The general rule this produced:
**"sees less of an executed command" is always a miss, never a fail-open** — ADR-0001
protects the user from the guard's own failure, it does not license silently dropping
commands the shell runs.

The corollary sharpened later, with `is_branch_switch` (0.30.0): a predicate that only
ever drove a soft nudge can be re-purposed to gate a hard state mutation, and the moment
that happens its false-positive tolerance inverts — a once-harmless miss (an occasional
un-nudged branch switch) becomes a silent guard bypass. Any transition from
nudge-consumer to mutation-gate for an existing predicate re-opens the case for an
adversarial review, even if the predicate's tests were already green.

This fix (issues #213, #224) is itself a miss-class bug of the ordinary kind:
`enforce_worktree::git_commit_targets` walked command segments for a leading `git` token
and silently skipped any `cd` segment, so a `cd <dir> && git commit` was resolved against
the wrong directory — not because the guard was uncertain, but because its parser saw an
incomplete picture of where the command would actually land. The fix teaches it to track
the `cd` chain the same way `core::shell::parse_work_dir` already does for six other
guards, rather than adding a new fail-open branch.

## Consequences

- A new guard, or new shell-parsing logic that feeds an existing guard, must ask two
  separate questions: "what happens when I can't tell?" (answer: allow) and "what
  happens when my parsing is subtly wrong?" (answer: it must not silently narrow what the
  guard sees — ambiguity in a stripping/expansion transform must keep content, never drop
  it).
- New parsing logic in `core::shell` that feeds guards (heredoc handling, quote
  stripping, substitution expansion, `cd`-chain resolution) gets an adversarial security
  review before merge, framed as "find an input where a dangerous or policy-violating
  command slips through unseen" — TDD and green CI are necessary but not sufficient,
  since happy-path tests only cover divergences already anticipated.
- Whenever a predicate that previously only drove a nudge starts gating a hard block or a
  state mutation, treat that transition as license to re-run the adversarial review on
  that exact predicate, even without any code change to the predicate itself.
