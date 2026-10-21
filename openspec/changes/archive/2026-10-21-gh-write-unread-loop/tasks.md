## 1. Guard

- [x] 1.1 Judge each gh write in a loop the loop parser cannot read, as outside a loop, instead of blocking the loop
- [x] 1.2 Nudge only on a judged write with no `-R`, `GH_REPO` or literal `repos/<owner>/<repo>/…` path
- [x] 1.3 Under `CADENCE_GH_STRICT_LOOPS=1`, block such a loop when a write has no `-R` or literal path
- [x] 1.4 Pin the relaxed and strict verdicts, padded past 12 KB, from an owned checkout and from `/tmp`

## 2. Docs

- [x] 2.1 Update the loop and strict-loops paragraphs in `docs/configuration.md`
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
