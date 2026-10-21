## Why

`redact-secret-output` read a bare `pass:` anywhere on a line as a key, so prose such as `+ // one record per pass: x` or `the second pass: done` was masked (cameronsjo/cadence-hooks#1449). The first fix kept a mid-line `pass:` only in key position and passed everything else through. Review found that too wide: grep, `cat -n` and `git blame` put a prefix before a YAML `pass:` key (`config/db.yml:3:  pass: <secret>`), Go's `%+v` prints `{User:admin Pass:<secret>}`, an `openssl` continuation line reads `-passout pass:<secret>`, and a qualifier before the name (`DB pass: <secret>`, `Admin pass: <secret>`) is the usual way a credential is labelled. Each of those printed the secret.

## What Changes

- A mid-line bare `pass:` is in key position when two or more blanks or a tab come right before it, or when the word before it ends in `:` (a `file:line:` prefix or a label) or starts with `-` (a flag such as `-passout`, or a dash). A field's value before it counts as before, now also when an opener is glued to the field (`{User:admin`, `&{User:admin`). The other key positions stay: line start after blanks, markers or comment leaders, and after `{ , ; & ? ( [` or a quote.
- Out of key position, a bare `pass:` is no longer skipped. It is read as a weak name: its value masks only when it looks like a credential (one word of at least 8 characters that is not a plain word, number, duration or identifier). So `DB pass: <secret>` masks, and `the second pass: done` passes through.
- Every other name, and the `pass=`, quoted and JSON forms, keep their rules.

Surfaces: `redact-secret-output` (PostToolUse, Bash), which values it masks. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-reads`: "Mask secrets in Bash output" gains scenarios for a bare `pass:` in prose (kept), behind a `file:line:` prefix (masked), in a map (masked), and after a qualifier word with a credential-shaped value (masked).

## Impact

`crates/cadence/src/redact_secret_output.rs`, `CHANGELOG.md`.
