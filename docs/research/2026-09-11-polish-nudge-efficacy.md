# Polish-nudge efficacy — 2026-09-11 measurement

Follow-up to `docs/plans/2026-06-20-hooks-sweep-stale-and-nudge-efficacy.md` (originally
tracked as `cameronsjo/claude-configurations#151`, since renamed
`cameronsjo/cadence-ecosystem`). That issue is now closed and unrelated (a
`check-idle-return` retirement) — `gh issue list -R cameronsjo/cadence-hooks --state open
--search "polish nudge"` finds no open issue for this specific measurement. Related open
issues exist (`cadence-hooks#537`, `#631`, `#452` — anchor mis-keying; `#787` — no
dispositioned-skip record; `#826` — no end-to-end test), but none is this measurement's
tracker. Not filing a new one, per instructions.

## Method

Script: `scripts/analysis/polish-nudge-efficacy.py`. Rerun with:

```bash
python3 scripts/analysis/polish-nudge-efficacy.py --sample 30 --seed 11 --tier2-out /tmp/tier2-sample.json
```

- **Tier 1 (deterministic):** reads the `cadence`/metrics install's `polish_nudges.jsonl`
  (the local Claude Code config directory's `cadence/metrics/` subdirectory — see
  `CLAUDE_CONFIG_DIR` in this repo's `crates/metrics/src/common.rs`), the metrics logger's
  own denominator. Every row is a fired ship-anchor nudge (`create`,
  `ready`, or `merge`) that reached the **silent-allow** path or the **nudge** path — the
  logger records both, so a row does not mean "the user was nagged," only "the gate fired
  and made a decision." Computes skip rate (`polished: false`), marker-absent rate
  (`markerPresent: false`), and the agreement between those two independent signals.
- **Tier 2 (transcript sample):** a seeded random sample of 30 skip candidates
  (`polished: false`). For each, the script finds every ship-anchor `gh pr
  create`/`ready`/`merge` Bash call in that row's transcript and picks the one whose own
  timestamp is closest to the row's logged `ts` — not the first match in the file, which
  the docs-polish review of this doc's first draft caught misattributing text between two
  different rows that shared a transcript. It returns the assistant text immediately
  preceding that specific call, read by hand for whether a reason was stated and, if so,
  whether it is legitimate or a reworded-away rationalization.

## Data window and what could not be measured

- `polish_nudges.jsonl` covers **2026-07-26 to 2026-09-10** (1,739 rows). The cadence
  v0.32→v0.33 reword this measurement targets landed **2026-06-19 ~20:24 CDT** — over five
  weeks before this log starts. **There is no before/after comparison from the JSONL**: the
  entire live window is "after." Part of that gap has a specific, verified cause, not just
  "the logger didn't exist yet": this repo's own `CLAUDE.md` records that `log-polish-nudge`
  was wired with a hooks.json pipe-alternation bug that made it **silently dead from
  2026-06-27 to 2026-07-25** (cadence#593) — it existed but never fired for a month, on top
  of not existing before 2026-06-27 at all.
- The plan's fallback was a transcript-based before/after split via `commits.jsonl` as an
  index. `commits.jsonl`'s `committed` flag is untrustworthy since 2026-05-28 (ADR-0022,
  `cadence-ecosystem`) and, more basically, the pre-boundary side needs full transcript
  mining across the whole ecosystem corpus with no deterministic index at all — out of
  scope for this pass. **The before/after rate is not measurable from what's live today;
  this is a limit of the instrumentation timeline, not a finding about the reword.**
- Tier 2 is a 30-row sample, not a census, and reads only the ~2000 characters immediately
  preceding the matched ship command — a reason stated earlier in the same turn can still
  be missed. Of the 30 sampled rows, 8 had no readable transcript file at all (rotated or
  moved) and 5 more had a readable transcript with zero matching ship-anchor calls in it (a
  session/transcript-path mismatch, a different failure mode than a missing file) — 17
  resolved to real context.

## Results

### Tier 1 — skip rate and marker-present rate

| Metric | Value |
|---|---|
| Total nudge-fire rows | 1,739 |
| Anchor kinds | `create` 1,431 · `ready` 276 · `merge` 2 · no `anchor` key 30 |
| Skip candidates (`polished: false`) | 309 (17.8% of all rows) |
| Marker absent (`markerPresent: false`) | 1,030 (59.2% of all rows) |
| `polished`/`markerPresent` agreement | 50.3% |
| Rows logged on branch `main`/`master` | 573 (33.0% of all rows) |
| Skip rate, excluding `main`/`master` rows | 114 / 1,166 = **9.8%** |
| Marker-absent rate, excluding `main`/`master` rows | 649 / 1,166 = **55.7%** |

The 30 rows with no `anchor` key are all timestamped before 2026-07-27 — the earliest rows
written right as `log-polish-nudge` came back alive (cadence#593 above) predate the `anchor`
field's own schema; they are a schema-evolution artifact, not a resolution failure, and are
excluded from the anchor-kind breakdown's three named buckets.

**The `main`/`master`-branch rows are a confound, not a genuine skip signal.** `cadence-hooks`
open issues `#537`, `#631`, and `#452` already describe the anchor keying itself off the
session's Bash cwd branch rather than the PR's actual head branch — a shared-main
meta-repo checkout logs `branch: "main"` even when the real PR shipped from a worktree on a
different branch. 195 of the 309 skip candidates (63%) carry `branch: main` or `master`.
Excluding those rows drops the skip rate from 17.8% to 9.8% — the more honest number, though
still likely inflated by the same mis-key on cases where the worktree's own branch happens
not to be `main`.

**`polished` and `markerPresent` agree only half the time — read neither alone.** These are
two independent instruments over the same underlying claim ("was polish run for this
branch"): a transcript scan for a polish-workflow invocation (`polished`), and a
branch-scoped marker file `record-polish` writes (`markerPresent`). They agree on only
50.3% of rows, and `markerPresent` is *absent* on 59.2% of all rows (55.7% even outside the
`main`/`master` confound) — most rows have no marker regardless of what the transcript scan
says, so `markerPresent` cannot be read as corroborating "most branches got a recorded
polish run." Both the 9.8% skip rate and the marker-absent rate carry real measurement
uncertainty from this disagreement, independent of anything about the reword.

### Tier 2 — stated-reason sample (n=30, 17 with resolvable context)

Of the 17 sampled skip rows with resolvable, timestamp-matched context, **12 were on a
`main`/`master` branch** (the mis-key confound above) and are set aside as not genuine skip
decisions. Of the remaining **5 non-`main`-branch rows with context**:

| Classification | Count |
|---|---|
| Silent (no reason stated for skipping polish in the visible window) | 5 |
| Legitimate (stated: trivial/already-polished) | 0 |
| Rationalized (stated: a closed loophole — "just docs", "already reviewed") | 0 |

None of the 5 stated an explicit reason for skipping `/polish` in the text immediately
preceding the matched ship command — the preceding text was about an unrelated step
(worktree setup, an issue-adjudication note, a release-PR announcement, a deploy note, a
release-recipe upkeep note), not a disposition of polish. This reads as **silent skips still
happening**, which is what the v0.33.0 "don't skip silently" mandate was meant to close —
but n=5 is far too small to generalize from, and the 2000-character context window may be
cutting off a reason stated earlier in the same turn.

## Verdict

**Not settled, and the live data can't settle it.** The core comparison the methodology
needed — skip rate and rationalization mix before vs. after the 2026-06-19 reword — has no
before-side data: `log-polish-nudge` did not exist before 2026-06-27 and was silently dead
until 2026-07-25 (cadence#593), so the queryable metrics window opens over five weeks after
the boundary. What the current window does show:

- A **9.8%** skip rate once the branch-mis-key confound is set aside (17.8% raw) — most
  ship anchors are preceded by a recorded polish run, by the transcript-scan signal.
- A very small (n=5), non-generalizable sample found **zero legitimate or rationalized
  stated reasons** — every sampled skip's visible context was silent on polish disposition
  entirely, which is a candidate finding against the "don't skip silently" mandate but far
  too thin to call a trend.
- The **50% disagreement** between `polished` and `markerPresent` means the skip rate itself
  has real measurement uncertainty independent of the reword question.

Next steps this measurement surfaces, for someone to pick up (not filed as issues per
instructions): fix the branch-mis-key confound (`#537`/`#631`/`#452`) before this rate means
anything cleanly; a larger, wider-context Tier 2 sample once that's fixed; and if the
before/after comparison still matters, it needs either historical transcript mining across
the whole 2026-06-19-to-2026-07-26 gap or accepting that boundary is unmeasurable and
resetting the baseline to whenever `polish_nudges.jsonl` started recording reliably
(2026-07-26).
