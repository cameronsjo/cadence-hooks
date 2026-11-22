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

## Review round 1 (cameronsjo/cadence-hooks#1663)

The PR's review moved these decisions into `openspec/specs/secret-reads/spec.md` directly, in the same PR, since this change was archived there:

- A pass-through table (`cat`, `tee`, `head`, `tail`, `base64`, `xxd`, `od`, `jq`, `yq`, `gojq`, `jaq`, `tr`, `sed`, `cut`): a pipeline whose later stages are all in it prints the value, and so does a value fed to one by a here-string, `<(…)` or heredoc body. A stage outside the table keeps the ask.
- A clipboard flag on `pass`, `gopass`, `lpass` is a consumer.
- One rule for structured output: a form blocks when its value reaches the context unmasked. A test proves `redact-secret-output` masks the default JSON of `az account get-access-token` and `aws secretsmanager get-secret-value`, so those keep the ask; `aws ssm get-parameter --with-decryption`, `az keyvault secret show` and `op item get --reveal` are not masked and block.
- `op inject` with no output file, and a producer behind the `perl -e 'alarm N; exec @ARGV'` runner, block when printed and otherwise keep main's verdict.
- A closed stdout and a stdout sent after a stderr already in a file keep the ask; zsh `print` is an argument printer.
- The comparison fails on any everyday move without an `A` line, and gains an `L` class for stated limits.

## Review round 2 (cameronsjo/cadence-hooks#1663)

Also recorded in the main spec directly:

- One rule for structured output: a form blocks when its value reaches the output, and keeps main's verdict only where a test proves the redactor masks it. `CLOUD_READS` is the per-subcommand table of value fields and proven-masked formats; a `--query` for another field and `-o none` keep main's verdict.
- A help or version call on any producer is never printed.
- kubectl selectors block only when they reach the data, the annotations, the whole metadata or a whole object.
- `kubectl get secret -o json|yaml` printed blocks (plain `-o yaml` moves from allow to block on purpose). Whole `.metadata` and `.metadata.annotations` reach the data: the `last-applied-configuration` annotation can hold it.
- Output-format variables (`AWS_DEFAULT_OUTPUT`, `AZURE_CORE_OUTPUT`) are read like the flag, and `head`/`tail -c` no longer keep key names.

## Review round 3 (cameronsjo/cadence-hooks#1663): the taint rule

The round-2 code decided whether a later pipeline stage was safe by enumerating safe filter shapes (a jq path naming no value field after a cloud read or `op item get`, and a names-only allowlist for a Secret's json or yaml). The round-3 reviews found three holes with one cause: that list never finishes. A field step after `--query SecretString --output text` reopened the value, `select(…)`, `sort_by`, `map(select(…))`, `.metadata.name, .`, `getpath` and `tojson` passed the allowlist while printing whole Secrets, and a jsonpath `{.data}` into `jq 'map_values(@base64d)'` only asked. The operator replaced the enumeration on 2026-11-22:

- Whether a producer form's output carries a value is decided at the producer, as before: the per-executable rows, `CLOUD_READS`, the kubectl selectors that reach data, and the redactor tests for the masked forms.
- From there every later `jq`, `gojq`, `jaq`, `yq` or pass-through stage keeps the value, whatever its filter says. The guard reads no filter text to call a stage safe. The pipeline blocks when such a stage ends it and prints, and keeps main's verdict when a consumer or a file comes after.
- The kubectl names-only allowlist is gone. Names and metadata come from kubectl's own selectors (`-o name`, a jsonpath, custom-columns or go-template naming only metadata, `type`, `kind` or counts) and `kubectl describe secret`, which keep main's verdict; the kubectl block message says so.
- Accepted on purpose: a filter that selects no value now blocks (`kubectl get secret s -o json | jq '.metadata.name'`, `aws secretsmanager get-secret-value … | jq -r .ARN`, `op read … | jq keys`). The comparison corpus classes these `T`, each with its reason; `--query <field>` or a kubectl selector is the replacement.
- The one filter still read is `jq .` (no other filter) after the two masked cloud reads, for the masked-format rule: a test proves the redactor masks the re-indented, `-c`, `-C`, `--tab`, `-S` and `--indent 4` output; any other option (`--stream`) blocks.

## Review round 4 (cameronsjo/cadence-hooks#1663)

The operator approved one narrow round on 2026-11-22:

- `sed -n` and `tail -n +K` are no longer read as dropping the value. Under the taint rule every pass-through stage keeps it; a multi-line value's later lines, or the line a `sed -n …p` script picks, are printed.
- The round-3 kubectl resource-type reader skipped only the options it listed, so an unlisted option before the type (`--as admin`, `-L app`) hid a Secret read that main asked about. The reader does not grow its list: when it meets an option it does not know before the type, it follows both readings (a flag, or an option that takes the next word) and blocks when either one's type names a Secret. A first draft fell back to main's any-word rule there, which the delta's security review showed blocks `kubectl get --show-labels pods -n secrets -o yaml`; main's rule is for asks only. The positional reading only withholds a block: every ask still follows main's rule, so `kubectl -n secrets get configmaps -o json | jq .` keeps main's ask. No command main asked about passes.
- Accepted on purpose, as the taint rule's consequence: a `sed -n` script that writes a file and prints nothing (`sed -n '/x/w out.txt'`) blocks, because the script is not read. The corpus classes it `T`.
