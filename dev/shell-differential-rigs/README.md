# Shell differential rigs — prototypes

Raw probe harnesses from the #490/#491/#496/#497 work (PR #511). **Preserved as
input to #510**, which is the issue about landing a *proper* harness in the test
suite. These are prototypes, not that harness.

## Why they were kept

Across two rounds, this parser shipped Criticals that the full unit suite,
clippy, fmt, and three end-to-end probe scripts all passed. Both were found by a
fresh reviewer running rigs like these against **real bash** as the oracle.

The evidence for keeping them is specific: round 2 passed 3,769 tests **and its
own differential reporting 20/20 with zero misses**, while five live guard
bypasses sat in the diff. Neither of the two Criticals appeared in any of six
harnesses — grepping all fifty-one hand-built rows for the triggering shape
(a `)` inside a `${…}` default) returns zero.

That is the argument #510 makes: a harness whose rows grow by adversarial search
rather than by authorship.

## What's here

| File | What it does |
|---|---|
| `shellcluster-regression.sh` | The bypass rows from rounds 1 and 2, plus controls |
| `shellcluster-adversarial.sh` | Braces, ANSI-C quoting, CRLF, backslash runs 0–4, wrapper walks |
| `shellcluster-differential.sh` | The original #490/#491/#496 class |
| `shellcluster-direction.sh` | Unbalanced openers/closers — proves which way each malformed input fails |
| `shellcluster-crit2.sh` | The comment-continuation (`#;\`) family |
| `shellcluster-isolate.sh` | Narrows the trailing-backtick residual to `guard-rm` operand parsing |
| `oracle.py`, `run1.py`–`run3.py` | Bash-as-oracle comparison drivers |
| `fuzz.py`, `fuzz2.py` | Random-fragment sweeps; ~16k fragments across 5 seeds in use |
| `probe-guards.sh`, `probe-radius.sh`, `probe-499.sh` | Per-guard blast-radius probes |
| `probe_windows.py`, `probe_root_default.py` | Fixture carve-out probes from #403 |
| `harness/` | A workspace-detached bin crate path-depending on `crates/core` |

## Caveats — read before trusting any of them

- **`shellcluster-adversarial.sh` exits 1 today.** One row (`hash inside
  backticks multiline`) is a known pre-existing miss, tracked in #509. That is
  expected, not a regression.
- **`harness/` path-depends on `crates/core` and must be rebuilt** after any
  change to the parser, or its results are stale. Its `Cargo.toml` path was
  written for an out-of-tree location and needs fixing before use here.
- **Each rig's row set is the class its author thought to sample.** A green run
  proves the enumerated classes are closed and says nothing about the rest —
  which is precisely how both Criticals reached a pushed branch.
- **`timeout` does not exist on macOS.** A sweep using it exits 127 on every
  seed and reads identically to a clean run. One fuzz pass was reported clean
  this way before the logs were read.
- Absolute home paths were rewritten to `$HOME` before commit. Some rigs take
  `BIN=<path>` to point at any binary, which is what makes baseline
  classification a one-liner.

## Not wired into anything

Nothing here runs in CI, and nothing depends on it. It is reference material
for whoever builds the real thing.
