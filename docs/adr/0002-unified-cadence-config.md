# ADR-0002: One per-repo guard config — `.claude/cadence.json`

## Status

Accepted (2026-07-10). Implements cadence-hooks#153. Freezes the schema for
cadence-hooks#216 (per-nudge suppression), which is built after cadence-hooks#164
(the path classifier, draft PR #268) lands.

## Context

Two guards had independently grown a per-repo config file, and the two files had
converged on the same shape without ever being designed together:

- `.claude/redaction.json` softens `redact-external-content` (audience tier,
  category ceilings, extra patterns, an allowlist).
- `.claude/terminology.json` softens the `terminology` block (path/term
  exemptions).

Both discover the git root via `core::paths::find_git_root`, read through the
hardened `read_untrusted_config` (1 MiB cap, regular-file-only — #157/#194),
deserialize with serde `camelCase`, live at `<git-root>/.claude/`, and fail open
via `unwrap_or_default()` (ADR-0001).

As more guards gain per-repo knobs, the count of top-level `.claude/*.json`
files grows one-per-guard. Each new file is another thing a user must discover,
another root the loader must probe, another entry in `.gitignore` reasoning.
Converging is cheapest now, at two files, than later at N.

Two issues drive the change and share one schema:

- **#153** — unify the two files into a single namespaced `.claude/cadence.json`.
- **#216** — replace the all-or-nothing `CADENCE_NO_*` env toggles with
  glob-matched per-nudge suppression keyed by guard name (path-scoped, like the
  rules engine).

## Decision

### 1. One file with named sections (#153, built now)

A single `.claude/cadence.json`, each guard reading its own top-level section:

```jsonc
{
  "version": 1,
  "terminology": { "exemptions": [ /* verbatim from terminology.json */ ] },
  "redaction":   { "originAudience": "...", "categories": {},
                   "additionalPatterns": [], "allowlist": [] },
  "nudges": {                        // #216 — reserved, see §3; ignored by the
    "backstop-warn":  { "suppress": true },        // loader shipped now
    "warn-overshare": { "suppress": ["docs/**"] }
  }
}
```

A shared generic reads the file once and deserializes one guard's slice, so each
guard keeps its **existing** `*Config` struct — no types move across crates:

```rust
pub fn load_cadence_section<T: Default + DeserializeOwned>(root: &Path, section: &str) -> T
```

Fail-open at every step (ADR-0001): a missing file, an unreadable/oversized/
special file, non-UTF-8, a top-level parse failure, an absent section, or a
section that does not shape-match `T` all yield `T::default()`. The loader
**ignores unknown top-level keys** — a repo may hand-author `nudges` (§3) ahead
of the loader that reads it without breaking. The `version: 1` envelope makes
adding a section later a non-breaking additive change.

Only `version` + `terminology` + `redaction` ship in the first build. `nudges`
is documented here as reserved and built with #216.

### 2. Hard cut, with a migration command and a doctor net (#153)

Once shipped, `cadence.json` is the **only** file read; legacy
`redaction.json` / `terminology.json` are ignored.

- `cadence-hooks migrate-config` converts a repo in one step: it merges each
  legacy file into its section, never clobbers a section already present, and
  renames the consumed legacy file to `*.json.migrated` (reversible breadcrumb)
  rather than deleting. Idempotent; refuses to proceed on a non-object
  `cadence.json` rather than destroy content.
- `cadence-hooks doctor` warns (never errors) when an orphaned legacy file is
  present or `cadence.json` fails to parse — so the hard cut is **not silent**.
  This is the mitigation for the one real downside of a hard cut (a repo's
  softening quietly stops applying); it removes the need for dual-read
  complexity.

### 3. Cross-cutting suppression lives in a `nudges` map (#216, FROZEN — built after #164)

`terminology` and `redaction` are bespoke rich sections; per-nudge suppression
is cross-cutting and belongs in one map. The design below is **frozen** so the
peer lanes (#164 classifier, #234 enforce-worktree) can build to a stable
contract, and is implemented after #164 lands so it consumes that classifier
instead of duplicating path logic.

- **Keyed by registry hook name** — `HookEntry.name` in `src/registry.rs`, the
  one stable, centrally-enumerated identifier (not `Check::name()`, not
  `rule_id`). This is the same name `cadence-hooks list` and `doctor` already
  cross-reference.
- **`suppress` is `true`** (boolean — for pathless/session guards like
  `backstop-warn`) **or `[glob, ...]`** (path-scoped — for tool-call guards
  carrying a file path). Glob semantics reuse **#164's path classifier** once it
  lands (repo-relative vs basename, gitignore-style `**`), mirroring
  terminology's existing `glob_match` rather than re-implementing it.
- **Doctor validates every `nudges` key** against the `HOOKS` slice and
  **rejects** a key that names a hard block or a `PROTECTED_GUARDS` member — a
  repo config can *never* silence a security guard or a hard block.
- **Declarative suppressibility marker on `HookEntry`.** Nudge-vs-block is
  currently a runtime `Outcome` only, not declarative. #216 adds a
  `suppressible: bool` (or `severity`) field to `HookEntry` so "is this a
  suppressible nudge?" is schema-checkable. *This is the field #164/#234 should
  be aware of — coordinate before either lands.*
- **Env vars become emergency overrides, not the primary surface.**
  `CADENCE_NO_OUTRO_BACKSTOP` and peers stay readable; precedence is env **or**
  config suppresses. Block bypasses (`CADENCE_NO_ENFORCE_WORKTREE`,
  `CADENCE_ALLOW_*`) stay **env-only** — they gate blocks, out of #216's
  nudge-only scope.
- **`feedbackFooter`** (the `CADENCE_NO_FEEDBACK_FOOTER` analogue) is
  cross-cutting on *all* block messages, not a per-guard nudge, so it is an
  optional top-level boolean, built with #216.

## Options considered (#153)

| Option | Shape | Verdict |
|---|---|---|
| **A** | Keep the files separate | Rejected — the N-files-per-guard growth is the problem; keeping them separate keeps it. |
| **B** | **One file with named sections + `version` envelope** | **Chosen.** Single diff surface, one thing to discover, one root probe; the `version` envelope gives a clean evolution path. |
| **C** | A `.claude/cadence/*.json` directory | Rejected — just relocates the N-files problem and centralizes merge conflicts in one directory; a single file with a `version` field wins on diff/ownership. |

## Consequences

- **Positive.** One config surface; each guard's schema stays in its own crate
  (no cross-crate type move); adding a section or the `nudges` map later is
  additive under `version: 1`; the hard cut avoids dual-read complexity while
  the doctor warning keeps it honest.
- **Negative / cost.** A repo that reads N sections re-reads (and re-parses) the
  file N times per tool event — acceptable at N≈2 under a 1 MiB cap, and it
  keeps each guard's read independent and fail-open. Dogfood repos need a
  one-time migration (owner-controlled; see the release order below).

## Alternatives declined

- **Deprecation window / dual-read** — a hard cut is simpler; the one dogfood
  consumer (the meta-repo) is owner-controlled, and the doctor warning covers
  the silent-loss risk without dual-read machinery.
- **Moving `TerminologyConfig`/`RedactionConfig` into `core`** — the generic
  `load_cadence_section` keeps each guard's struct in place; guards still own
  their schemas.
- **Building #216's glob suppression now** — would duplicate the path
  classification #164 is about to centralize; freeze the schema, build after
  #164.
- **Global `~/.claude/cadence.json` layering** — both current configs are
  repo-only; YAGNI until a guard needs a user-global default.

## Release sequencing (two-repo companion gating)

1. Merge + release the cadence-hooks binary (loader + `migrate-config` + doctor
   + this ADR).
2. In each dogfood repo, write `cadence.json` **first**, then upgrade the binary,
   then rename the legacy file — a zero-gap order: the old binary ignores the
   unknown `cadence.json` and still reads the legacy file; the new binary reads
   `cadence.json`.
3. Update the cadence plugin's redaction/terminology skill docs + schema
   (`cadence.schema.json`, `cadence.json` guidance).
