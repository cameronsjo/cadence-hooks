## Context

`guard-secret-dump` already finds bare-value producers through a per-executable table (`producer()`) and already walks child scripts (`$(…)`, backticks, `<(…)`, `sh -c`, `eval`). What it lacked was a reading of where the value goes: every exposed producer asked.

## Decisions

### One rule, judged per script

Each script is judged with one flag, `reaches_context`: does this script's stdout end up in the command's output?

```text
top-level command ............................ reaches_context = true
sh -c / bash -c / eval script ................ inherits its segment's output
$(…) / `…` in an echo/printf argument word ... inherits its segment's output
$(…) / `…` that is the whole first word ...... inherits its segment's output
$(…) / `…` anywhere else ..................... false (captured by a consumer)
<(…) / >(…) .................................. false (a consumer reads it)
```

`printed_bodies` reads the argument words. It skips redirect words and their targets (`echo hi 2>"$(…)"`), process-substitution words (`echo <(…)` prints a `/dev/fd` path), and every argument of `printf -v` (which assigns). "Whole first word" means the first word, after runners and assignments are peeled, is exactly one substitution: `"$(op read …)"` and `X=1 "$(op read …)"` block, while `$HOME/bin/tool --token "$(op read …)"` and `"$TOOL" login -p "$(…)"` are a command named by a variable taking the value as an argument, and keep the ask. Code review round 1 narrowed both readings from a first draft that treated any segment starting with `$` as command position and every substitution in an `echo`/`printf` segment as printed.

A segment prints when `reaches_context` holds, it is not piped into the next stage, its stdout is not redirected to a real file, and the script holds no `{ … }`/`( … )` group. A producer in a printing segment is `Printed` (block). Otherwise today's containment test decides between `Exposed` (ask) and silent.

### Tables, not spellings

Two small tables carry everything tool-specific:

- the producer table (`producer()`), one row per executable, saying which invocation prints a bare value; unchanged by this change;
- `ARGUMENT_PRINTERS` (`echo`, `printf`, not `printf -v`): commands whose output is their arguments.

No consumer is listed. A consumer that prints (`cat`, `tee`, `base64 -d`) keeps the ask: decision 5 of the brief, a cooperative model's honest mistake is the threat model, and growing a list of printing consumers is the denylist ADR-0046 rules out.

### Fail directions

- Parse uncertainty never upgrades to a block: a grouped script, a substitution the top-level splitter cut at its inner pipe (`echo $(op read … | sha256sum)` splits into a piped segment), and a segment with more `)` than `(` all keep the ask.
- The hook still fails open (ADR-0001): no command, allow.
- The block is never confirm-tier: a retry cannot undo a leak.

### Escape

No new escape. The guard is not in `PROTECTED_GUARDS`, so `CADENCE_DISABLE=guard-secret-dump` in the hook's environment switches it off, and `CADENCE_BYPASS=1` switches off every guard.

## Measurement

`scripts/secret-dump-compare.py` scores the four secret hooks on a base and a head binary over the everyday commands of `scripts/testdata/confirm-tier-commands.txt` and the classed shapes of `scripts/testdata/secret-value-commands.txt` (P printed, C consumer, Q quiet). Only ASK to BLOCK by `guard-secret-dump` may move, on a P row or on an unclassed row listed for a person to read.
