## 1. Rule

- [x] 1.1 `judge` returns a `Finding` (`label`, `Exposure::Printed | Exposed`); `run` blocks on `Printed`, asks on `Exposed`
- [x] 1.2 `reaches_context` threaded through child scripts: inherited by `-c`/`eval` scripts and by substitutions in an `echo`/`printf` argument word or as the whole first word (`printed_bodies`); false for other substitutions and process substitutions
- [x] 1.5 Code review round 1: a first word that only starts with `$` names a command (keeps the ask); `printf -v`, redirect words and their targets, and process-substitution words are not printed arguments
- [x] 1.3 Grouped scripts and segments with an unmatched `)` keep the ask
- [x] 1.4 Block message: Found/Fix, consumer forms, never the command text

## 2. Tests

- [x] 2.1 Each printed shape blocks; each consumer shape keeps its ask; contained shapes stay silent
- [x] 2.2 Each staged red once: a pipe counted as printing, no producer ever printed, `echo` arguments never printed, a lone first-word substitution never printed, `printf -v` read as printing

## 3. Measurement

- [x] 3.1 `scripts/secret-dump-compare.py` and `scripts/testdata/secret-value-commands.txt`; run against a binary built from `origin/main`

## 4. Docs

- [x] 4.1 `docs/hooks.md`, `docs/configuration.md` (the rule, the limit, the existing escape, the comparison), registry and CLI descriptions, CHANGELOG
