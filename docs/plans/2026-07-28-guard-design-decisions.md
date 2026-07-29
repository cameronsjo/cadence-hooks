---
name: guard-design-decisions
date: 2026-07-28
status: partially-ruled
---

# Three guard design decisions before build (#452, #282, #275)

> **Plan PR (draft).** No implementation. Each of the three issues carries an
> undecided design question that has to be answered before code is worth
> writing — a one-line fix that over-suppresses (#452), a block-tier guard with
> an unscoped predicate (#282), and a premise that understates the work by
> three capabilities and one governance collision (#275).
>
> **Refs (never `Closes` — this is a plan, not the fix):** `cameronsjo/cadence-hooks#452`,
> `cameronsjo/cadence-hooks#282`, `cameronsjo/cadence-hooks#275`, and the
> plugin-side counterpart `cameronsjo/cadence#360`.
>
> **Verified against** `origin/main` at `3b22ffb` (2026-07-28). Every file:line
> below was read in a clean worktree of that commit, not from the issue bodies.
> Where an issue's claim survived verification it is marked *confirmed*; where
> it did not, the correction is called out.
>
> **Ruling landed 2026-07-29** on #275 (allowlist writes are permanently
> human-only — see the Ruling section below) and on tier posture across all
> three guards (nudge first, block is a separate later step — see Shared tier
> policy below). Four of the original twelve open questions are resolved
> outright by that ruling, one more is resolved by the shared tier policy, and
> one new question opens in its place. **Seven questions remain genuinely
> open** — see Still open at the end.

---

## Ruling — #275: allowlist writes are permanently human-only

**Settled 2026-07-29.** Claude may verify guardrails allowlist state doctor-side,
but must never write it, at any scope, ever.

**Rationale:** a mechanism that lets the guarded party widen its own allowlist
is circular — the whole point of the guard is to constrain what Claude can do,
so letting Claude expand the boundary that constrains it defeats the guard.
This repo already treats bootstrap as the weakest link in the guard chain; a
Claude-writable allowlist would make bootstrap the weakest link on an ongoing
basis instead of a one-time exposure. The ruling also forecloses the
project-scope hazard §3(d) below flagged as a question needing verification: a
repo shipping its own `.claude/settings.json` `env` block could otherwise
widen the guards' allowlist for anyone who clones it. With writing foreclosed
at every scope, that hazard doesn't need Claude Code's project-`env` trust
model resolved first — there is nothing to write regardless of scope.

**This resolves outright:**

- **May Claude write allowlist keys? No.** Human-only, permanently. (Was Q8.)
- **May keys be written at project scope? Moot.** No writing at any scope, so
  the scope question doesn't arise. (Was Q12.)
- **Should a new subcommand be modelled on `migrate-config`, vs a `configure`
  sub-step? Moot as a writer question.** Neither shape is needed because
  nothing writes. If a read-only verifier subcommand is still wanted beyond
  folding into `doctor` (Option 3 below), that's a separate ask this plan does
  not currently call for. (Was Q10.)
- **Ship doctor-side verification as an independent first slice? Yes — and
  it is now this plan's lead deliverable for #275**, decoupled entirely from
  the writer question: Option 3 below ships regardless of how, or whether,
  writing ever gets solved. (Was Q11.)

**This opens one new question in its place:** given human-only, does
cadence#360 thin `guardrails-init` to an invoker, or retire it? See Q9 in
Still open below — a directly relevant owner ruling on cadence#360 already
exists and is folded into the recommendation there.

---

## Shared tier policy (applies to all three guards)

**Ship at nudge tier first. Escalation to a block is a later, separately
justified step**, not a default. Each guard section below references this
policy rather than re-deriving its own answer:

- **#452** is structurally nudge-only already — the polish-gate consumers
  (`nudge_polish_before_pr.rs`, `log_polish_nudge.rs`) have no block path, so
  this policy is a statement of the existing shape, not a new choice.
- **#282** — see §2(c). The issue proposes a block; this policy is why the
  recommendation ships nudge instead, with the polish gate's CP1→CP2 pattern
  as the model for a later escalation.
- **#275** has no guard tier as such (it's a config writer/verifier, not a
  gate on an action) — noted here only for completeness.

---

## 1. #452 — polish-anchor retargeting

### (a) Verified current state

`crates/core/src/shell.rs:331-340` — `segment_ship_anchor`, the whole anchor decision:

```rust
match invocation.subcommand {
    "ready" => Some("ready"),
    "create" if !tokens.iter().any(|t| t == "--draft" || t == "-d") => Some("create"),
    "merge" if invocation.targets_the_current_branch() => Some("merge"),
    _ => None,
}
```

*Confirmed.* `ready` (:335) and `create` (:336) never read the invocation at
all beyond its subcommand. Only `merge` (:337) consults retargeting.

The field they ignore is already computed for all three. `gh_pr_invocation`
(`shell.rs:534-569`) sets `retargeted` from two channels: an inline
`GH_REPO=`/`GH_HOST=` assignment in the skipped prefix region (:542-544), and a
global `--repo`/`-R` in any spelling (:552-556). `GhPrInvocation::targets_the_current_branch()`
(:404-406) is the only consumer:

```rust
!self.retargeted && operands_are_flags_only(self.operands)
```

**Consumers are nudge-only, and the marker lookup is purely local.**
`crates/cadence/src/nudge_polish_before_pr.rs:82-84` calls
`polish_marker_present(command, input.cwd)`; the marker is keyed on
`(git_common_dir, branch)` resolved from the cwd (:33-49) and never consults
the repo `gh` will act on. `crates/metrics/src/log_polish_nudge.rs` is a
Logger. Neither can block. So the cost of a wrong verdict is a nudge naming the
wrong branch plus a `polish_nudges.jsonl` row attributed to a branch that never
shipped — the denominator for the polish quiet-week measurement (#409).

**The issue's premise is confirmed.** The three shapes it measured
(`GH_REPO=other/repo gh pr create`, `GH_REPO=other/repo gh pr ready 12`, and the
flag spellings) do anchor today, and the marker they resolve is the cwd's.

**Bonus finding — confirmed: `merge` over-suppresses today.** `is_repo_flag`
(`shell.rs:358-360`) matches the flag regardless of its *value*, so
`gh pr merge -R cameronsjo/cadence` run from a worktree of
`cameronsjo/cadence` is suppressed even though the cwd's branch is exactly the
branch being merged and the marker key is correct. Pinned by
`shell.rs:1893-1911`. `operands_are_flags_only` suppresses it a second time
(:443 returns false on `is_repo_flag`), so this is belt-and-suspenders
over-suppression, not an oversight in one predicate.

### The correction that changes the fix

**The brief's recommended shape — gate create/ready on
`!env_retargeted && operands_are_flags_only(operands)` — is broken, and so is
the issue's "plausibly a one-line extension".** `operands_are_flags_only`
(`shell.rs:419-449`) returns false on *any* token that does not start with `-`
(:443), explicitly including a flag's value — the doc comment says so at
:374-378 ("`gh pr merge --squash -b "some message"` reads as argument-bearing
and does not anchor").

That predicate is **merge-shaped**. The three subcommands have different
operand grammars:

| Subcommand | Operand grammar | `operands_are_flags_only` verdict |
|---|---|---|
| `merge` | optional PR selector, flags mostly valueless (`--squash`, `--auto`) | usually true — works |
| `create` | all flags, most value-bearing (`--title x`, `--body-file f`) | **false for nearly every real invocation** |
| `ready` | optional PR number | **false whenever the number is given** |

Applying it to `create` would suppress `gh pr create --title x` — i.e. take the
create anchor dark. Applying it to `ready` would suppress `gh pr ready 12`,
which is the spelling this repo's own guard *advises*
(`crates/guardrails/src/warn_gh_merge_preflight.rs:56`: "run `gh pr ready <n>`
first").

Measured against the suite: **17 of the 21 positive create/ready assertions in
`shell.rs` flip**, plus three in `nudge_polish_before_pr.rs` (:232, :328, :345).
Only four survive (`shell.rs:1702, 1711, 1852, 2001` — the valueless-flag and
no-operand forms).

A second datum cuts the same way: `shell.rs:1785-1790`
(`is_polish_ship_anchor_matches_global_flag_form`) already asserts that a
`--repo`/`-R` create/ready **does** anchor. Those assertions were written for
#303 to prove the walk finds the subcommand past global flags, so their
*intent* was not "a retargeted create must nudge" — but the behavior is on the
record, and any option that suppresses on `-R` flips three of them.

### (b) Design space

**Option 1 — extend the merge gate to all three subcommands.** The "one-line
fix" as filed. *Failure mode:* the anchor blackout above (17 assertions, and in
practice nearly every `gh pr create`). This is not a small change dressed as a
small change; it is a near-total loss of the anchor.

**Option 2 — split the field, suppress on the env channel only.** Replace
`retargeted: bool` with `env_retargeted: bool` + `repo_flag: bool`. Gate
`create`/`ready` on `!env_retargeted` alone; leave `merge` on its existing
predicate. ~10-15 lines. *Rationale:* the two channels differ
**distributionally**, not semantically — `gh` treats `GH_REPO=` and `--repo` as
the same base-repo override, but a `GH_REPO=` prefix is the scripted,
cwd-agnostic spelling (the issue's own measured wrong-branch rows), while a
`-R` flag on a create is the fork→upstream or explicit-own-repo spelling where
the head branch *is* the cwd's branch and the marker key is right. The latter is
this ecosystem's dominant shape — `gh pr create -R cameronsjo/cadence --draft
--title x --body-file …` appears verbatim as a fixture at
`crates/guardrails/src/warn_pr_issue_link.rs:194`. *Verified test cost: zero.*
No assertion pins `GH_REPO=… gh pr create`; the `GH_REPO` tests
(`shell.rs:1912-1915`) are merge-only.

**Option 3 — resolve the flag's value against the cwd's remotes.** Suppress
only on a genuine mismatch. The machinery exists: `host_and_repo_from_url`
(`shell.rs:578`), `resolve_from_git_remotes`
(`crates/guardrails/src/guard_gh_write.rs:586`, currently private to that
module), `GitState::resolve`. Most precise, and it is the only option that also
fixes `merge`'s over-suppression. *Costs:* a git subprocess per anchor
evaluation (marginal — the check already pays one for the marker), a fail-open
rule for an unresolvable remote, and lifting a private helper into `core`.

**Option 4 — WONTFIX.** Nudge-only; document the miss alongside the four
families `shell.rs:478-504` already enumerates.

**Option 5 (micro) — narrow the `ready` case.** Suppress `ready` only when it
carries a positional *and* is env-retargeted. Catches
`GH_REPO=other/repo gh pr ready 12` without touching bare `gh pr ready <n>`.
Composable with Option 2.

### (c) Recommendation

**Option 2 now; Option 3 only if the ledger justifies it.** (Consistent with
the shared tier policy above: this guard is nudge-only by construction, so no
tier decision applies here — only which shapes it fires on.) Option 2 fixes
every shape the issue actually measured, breaks no test, and preserves the
`-R`-create nudge that the ecosystem's own dominant spelling depends on. Add
Option 5 if the `ready` positional case is judged worth the extra branch.

Fixing `merge`'s over-suppression is **Option 3 territory and should not ride
this change** — it is a separate behavior change to a predicate three security
reviews have already tuned, and it flips ~10 existing assertions of its own.
File it as its own issue.

### (d) What breaks if we guess wrong

The error directions are **not symmetric**, and the dangerous one is
over-suppression. If we take Option 1, the polish gate silently stops firing on
most PRs while `polish_nudges.jsonl` keeps producing rows — the #409 denominator
collapses and adherence *reads as improved because measurement stopped*. That
is a metric that gets better by going blind, and nothing in the ledger
distinguishes it from a genuine improvement.

Over-nudging costs one wrong-branch nudge and one mis-attributed row: visible,
cheap, reversible. Under-nudging is invisible. Given a nudge-only guard, prefer
the visible error.

---

## 2. #282 — plugin-root guard

### (a) Verified current state

**No such guard exists.** Nothing in `crates/*/src/` or `src/` implements a
plugin-root path block; the only `plugins/`-aware code is incidental
(`crates/core/src/pathclass.rs:558` uses a plugin-cache path as a test probe;
`crates/rules/src/validate_skill_frontmatter.rs:79-87` classifies skill paths).
*Confirmed.*

Existing machinery a guard would build on:

- `crates/core/src/paths.rs` — `find_git_root` (:86), `is_within` (:106),
  `read_untrusted_config` (:127).
- `crates/core/src/pathclass.rs` — `normalize` (:125), `classify` (:152).
- `crates/guardrails/src/guard_dotfiles.rs` — the template for a pure decision
  function (`judge_dotfile`, :33) behind an **opt-in env var**
  (`CADENCE_GUARD_DOTFILES=1`, :9).
- `crates/rules/src/validate_skill_frontmatter.rs:79-87` — `classify_path`,
  and a cautionary example: it is substring-based (`path.contains("/skills/")`),
  which is exactly the shape that must *not* be reused here.

**The CI counterpart is real and its header documents the trap verbatim.**
`cameronsjo/cadence` `.github/workflows/plugin-runtime-only.yml`:

```sh
cruft=$(git ls-files ':(glob)plugins/*/docs/*' ':(glob)plugins/*/scripts/*')
```

with the comment: "The `:(glob)` magic pathspec is mandatory here: under it `*`
does NOT cross `/` … A bare glob would sweep in the ~20 legitimate
`skills/<skill>/scripts/` files (git pathspec `*` crosses `/`) and fail
forever." *Confirmed — the asymmetry bit CI as described.*

**The monorepo does carry a marketplace manifest, and it enumerates plugin
roots exactly.** `cameronsjo/cadence` `.claude-plugin/marketplace.json` lists
each plugin with `"source": "./plugins/<name>"`. This matters: the manifest is
not merely an identity signal, it is a precise list of the directories the
guard cares about — which removes the pattern-guessing problem rather than
solving it.

### (b) Design space — question (a), the `*`-crosses-`/` asymmetry

The hook receives an **absolute** path; CI gets repo-relative paths free from
`git ls-files`. That conversion (`find_git_root`, `paths.rs:86`) is a step CI
never had to take and is where a bug would hide.

**Option A1 — substring test** (`contains("/plugins/") && contains("/docs/")`).
*Failure mode:* this is the CI bug in Rust dress. It matches
`plugins/cadence/skills/writing-skills/scripts/gen.py` — the ~20 legitimate
runtime assets. **Reject.**

**Option A2 — segment-index rule.** Split the repo-relative path on `/`;
require `segments[0] == "plugins"`, `segments.len() >= 4`, and
`segments[2] ∈ {"docs", "scripts"}`. Reproduces `:(glob)` semantics exactly, no
pattern engine, trivially unit-testable with the ~20 known-legitimate paths as
negative fixtures. **Recommend.**

**Option A3 — regex with explicit `[^/]+`.** Correct but harder to eyeball, and
a five-line split needs no pattern at all.

### (b) Design space — question (b), the scoping predicate

**Option B1 — repo identity** (remote is `cameronsjo/cadence`). *Failure
modes:* brittle across forks, renames, and the pending private→public flip
(cadence#350); a contributor's fork silently goes unguarded; needs a git
subprocess per Write/Edit.

**Option B2 — marketplace manifest.** Require `.claude-plugin/marketplace.json`
at the repo root and match the target against its parsed `plugins[].source`
list. *Strongest*, because it eliminates the pattern question — the guard
compares against declared roots instead of guessing them. Also covers
`cadence-lab` (its own 4-plugin marketplace) for free. *Failure modes:* it is
untrusted repo content (route through `read_untrusted_config`,
`paths.rs:127`); it costs a read + JSON parse per Write/Edit unless the cheap
segment test gates it; and a `plugins/*/` repo with no manifest, or one whose
manifest names different paths, goes unguarded.

**Option B3 — structure only.** Any repo where the path is
`plugins/<name>/{docs,scripts}/`. No I/O. *Failure mode:* a Vim, Obsidian,
Terraform, or Jenkins plugin monorepo is a real and common shape, and at block
tier this is a hard stop on someone else's legitimate layout with no bypass but
`CADENCE_BYPASS`.

**Option B4 — opt-in env var** (`guard_dotfiles` precedent). Zero false
positives by construction; costs a settings entry and stays invisible until
someone enables it.

### (c) Recommendation

**B2 as the predicate, with A2's segment test as the cheap pre-filter** — the
segment test runs first and rejects almost everything at zero I/O cost; only a
candidate hit pays for the manifest read. **Ship at nudge tier first, per the
shared tier policy above.**

The issue proposes a block, but the `.gitignore` and the `plugin-runtime-only`
CI check already cover the *shipping* risk; this guard's value is local,
pre-commit feedback. A nudge captures that at zero false-block cost, and
escalation can follow the CP1→CP2 pattern the polish gate already documents
(`nudge_polish_before_pr.rs:58-60`) — a later, separately justified step, not
part of this slice.

**Open sub-question:** the plugin *cache*
(`~/.claude/plugins/cache/<marketplace>/<plugin>/`) is itself a
plugins-shaped tree, and editing it is separately forbidden by the meta-repo
CLAUDE.md. The index-2 segment rule does **not** match it — the cache puts
`docs` at index 3 (`plugins/cache/<plugin>/docs`) — so it is out of scope
unless deliberately added.

### (d) What breaks if we guess wrong

- **B3 at block tier** hard-blocks legitimate work in any unrelated
  `plugins/`-shaped repo. The failure is loud but un-dismissable, and it lands
  on a third party's layout that was never ours to police.
- **B1 scoped too tight** produces the opposite and worse failure: the guard
  silently never fires, we believe the belt-and-suspenders is in place, and CI
  is doing all the work alone. A guard that cannot fire is indistinguishable
  from a guard that found nothing.
- **A1 substring matching** blocks ~20 known-legitimate runtime assets on day
  one. This one at least fails loudly and immediately.

---

## 3. #275 — configure identity

### (a) Verified current state

`src/configure.rs` is **206 lines** and does exactly one thing:

- `find_settings_path()` (:15-32) walks up from the cwd to the first `.git` and
  returns `<root>/.claude/settings.json` — **project scope**, falling back to
  the cwd when no git root is found.
- It reads and writes exactly **one key**, `CADENCE_DISABLE` (read :46-47,
  write :88-91, removal + `env`-block cleanup :81-86), merging into the `env`
  block without clobbering.
- It is **interactive**: `dialoguer::MultiSelect` (:169-179).
- `pub fn run(list_only: bool, hooks: &[HookEntry]) -> !` — a **diverging**
  function that `process::exit`s on every path (:145, :177, :199, :203).
- Its **only** non-interactive path is `--list` (:143-146 → `print_config`
  :110).
- It **spawns no subprocess at all**.

*All confirmed.*

**The constraint the issue does not mention, and it is the load-bearing one:**
`configure` is **disabled under Claude Code**. `src/main.rs:779-793`:

```rust
if under_claude_code() && !list {
    eprintln!("cadence-hooks: `configure` is disabled under Claude Code.\n\
               This would let the agent edit .claude/settings.json and disable hooks.\n\
               Run it yourself from a terminal, or use `configure --list` to see current state.");
    process::exit(1);
}
```

`under_claude_code()` (:44-48) reads `CLAUDECODE`. The subcommand is also hidden
from `--help` under Claude Code (:642).

**The skill it should absorb** (`cameronsjo/cadence`
`plugins/cadence-guardrails/skills/guardrails-init/SKILL.md`) writes
**user-level** `~/.claude/settings.json`, runs `gh api user --jq .login`, uses
`AskUserQuestion` twice (additional owners, additional repos), migrates legacy
`GIT_GUARDRAILS_ALLOWED_*` keys forward, and then self-destructs from the
plugin cache.

**The keys are read from the process environment, not from a file** —
`env_allow_entries("CADENCE_ALLOWED_OWNERS")` at `guard_push_remote.rs:240-241`,
`guard_gh_write.rs:1712-1713`, `inject_gh_context.rs:38-39`.

**cadence#360 is OPEN** and explicitly blocked on this issue ("Blocked on the
CLI side: cameronsjo/cadence-hooks#275"). Both sides are waiting on the other's
contract. *Verified 2026-07-28.*

### The premise correction

#275 reads as "teach an existing config-writer one more key." It is actually
**four new capabilities in a module that has none of them**, plus a governance
collision:

1. A **second, differently-scoped settings target** (user-level
   `~/.claude/settings.json`) in a module whose only path resolver is
   project-scoped (:15-32) and which has no notion of scope at all.
2. A **subprocess** (`gh api user`) where the module spawns nothing.
3. A **non-interactive mode** beyond `--list` — required, because the
   interactive path is forbidden to Claude.
4. A **composable return type** — `run() -> !` exits on every path, so a
   `configure guardrails` sub-step needs the signature reworked.

**The governance collision was the actual decision, and it is now ruled** (see
the Ruling section above). `configure` is deliberately forbidden to Claude
*because it edits settings*. Writing `CADENCE_ALLOWED_OWNERS` is **widening
the guards' own allowlist** — the most self-modification-shaped write in the
product. But the skill it would replace is invoked *by* Claude. The ruling
resolves this by keeping the capability human-only, permanently. That does
**not** foreclose cadence#360 thinning the skill to a one-line invoker, as
originally feared here — a thinned skill still refuses under Claude Code via
the CLI's own existing gate (`main.rs:779-793`), so the invoker and the
refusal live in one place instead of two. See Q9 in Still open below.

### (b) Design space

**Option 1 — `configure guardrails` sub-step, human-only.** Keeps the existing
gate intact. Does **not** force cadence#360 to retire the skill — see Q9 in
Still open below: cadence#360 already carries an owner ruling to thin, not
retire, and this option is compatible with that ruling because the sub-step
inherits `main.rs:779-793`'s existing refusal under Claude Code regardless of
who invokes it.

**Option 2 — a separate non-interactive subcommand**, e.g.
`cadence-hooks configure-identity --owner <o> [--repo <o/r>]…`, modeled on
**`migrate-config`** (`src/migrate.rs`) rather than on `configure`.
`migrate-config` is the existing precedent for a non-interactive, idempotent,
never-clobbering, report-producing config subcommand
(`src/migrate.rs:1-22` states those safety properties explicitly), it is not
gated under Claude Code (`main.rs:803-805`), and it sits in the
`CADENCE_BYPASS`-exempt set alongside `configure`/`doctor` (`main.rs:564`).
Whether Claude may run it is then a separate, explicit decision rather than an
inherited one.

**Option 3 — verification only.** Leave the write in the skill; teach `doctor`
to check the wiring (keys present, owners non-empty). Smallest slice, and it
splits cleanly along the trust line: *reading and validating* is safe for
Claude, *writing* is not. #275's own text already asks for this half.

**Option 4 — WONTFIX.** The skill works; the complaint is a typing aesthetic
from the 2026-07-10 audit.

### (c) Recommendation

**Option 3, now settled as the plan's lead deliverable per the ruling above —
not conditional on anything else.** Doctor-side verification is independently
useful, unblocks drift visibility immediately, carries zero governance risk,
and ships regardless of how the writer question resolves, because per the
ruling above there is no writer question left to resolve: writing is
foreclosed at every scope, permanently.

**Explicitly do not extend `configure` itself** to write these keys — that
door is closed by the ruling, not just by the project-scoped resolver and
`-> !` signature that already fought the change. Option 2 (a dedicated
non-interactive subcommand) is moot as a *writer* — see the Ruling section
above.

### (d) What breaks if we guess wrong

- **Bolting user-scope writes into `configure` without ruling on scope** leaves
  `find_settings_path()` ambiguous: a future reader cannot tell which file a
  given key lands in, and the two keys in the module would obey different
  rules for no visible reason.
- **A project-scoped allowlist write is a security question, not a style
  question — this is why the ruling above forecloses it outright.** If
  `CADENCE_ALLOWED_OWNERS` could be written at project scope, a repo shipping
  its own `.claude/settings.json` `env` block could widen the guards'
  allowlist for anyone who opens it. The ruling settles this by removing
  writing at every scope, so Claude Code's project-`env` trust model no longer
  needs confirming to close the hole — there's nothing left that could open
  it.
- **Retiring the skill instead of thinning it** would contradict the existing
  cadence#360 owner ruling (2026-07-27: "thin it, do not retire it") without a
  new ruling to justify the reversal, and would lose the discoverable setup
  path in favor of a command a first-time user has no way to find.

---

## Resolved

Five of the original twelve questions are settled and are not open questions
anymore. Kept here, numbered as originally filed, for traceability — they do
not appear again below.

- **Q6 (#282 — nudge vs block tier)** — RESOLVED by the shared tier policy
  above: nudge first, escalation later and separately justified.
- **Q8 (#275 — may Claude write allowlist keys)** — RESOLVED by the ruling
  above: no, permanently human-only.
- **Q10 (#275 — subcommand modelled on `migrate-config`, or a `configure`
  sub-step)** — RESOLVED by the ruling above: moot as a writer question.
- **Q11 (#275 — ship doctor-side verification as a first slice, decoupled
  from the writer decision)** — RESOLVED by the ruling above: yes, and it is
  now the plan's lead deliverable for #275.
- **Q12 (#275 — may allowlist keys be written at project scope)** — RESOLVED
  by the ruling above: moot, no writing at any scope.

---

## Still open — 7 of the original 12

Each phrased so a sentence answers it. One question (Q9) is new, opened by the
ruling above; the rest carry over unresolved from the original plan.

**#452 — polish-anchor retargeting**

1. For `gh pr create`/`gh pr ready`, should an inline `GH_REPO=`/`GH_HOST=`
   prefix suppress the nudge while a `--repo`/`-R` flag keeps nudging?
   *(Recommend yes — Option 2.)*
2. Should `--repo`/`-R` be resolved against the cwd's remote so only a genuine
   mismatch suppresses, or is that more machinery than a nudge-only guard
   deserves? *(Recommend defer.)*
3. `gh pr merge -R <the cwd's own repo>` is suppressed today even though the
   branch is correct — fix it in a separate issue, or leave it?
4. `gh pr ready <n>` from an unrelated branch resolves the marker on the wrong
   branch: accept as a documented miss, or suppress numbered-ready only when it
   is also env-retargeted?

**#282 — plugin-root guard**

5. Scope the guard by marketplace manifest, repo identity, bare structure, or
   an opt-in env var? *(Recommend manifest, with a segment-test pre-filter.)*
7. Is the plugin cache (`~/.claude/plugins/cache/`) in scope for this guard, a
   separate one, or out of scope?

**#275 — configure identity**

9. Given human-only (Q8, resolved above), does cadence#360 thin
   `guardrails-init` to an invoker, or retire it for a documented terminal
   command? *(Recommend thin, not retire. cadence#360 already carries an
   owner ruling — 2026-07-27, decided item-by-item on a decision dashboard:
   "Thin it, do not retire it… keep the familiar entry point, but have it call
   the standalone program so configuration has exactly one owner." That ruling
   predates today's human-only decision but is not in tension with it: the
   subcommand the skill would invoke — Option 1's `configure guardrails`
   sub-step, per `main.rs:779-793` — already refuses under Claude Code
   regardless of who invokes it. Thinning the skill to a one-line invocation
   of that subcommand doesn't reopen human-only; it centralizes the one
   owning implementation in the CLI and lets the CLI's existing refusal do
   the enforcement instead of duplicating it in skill prose.)*
