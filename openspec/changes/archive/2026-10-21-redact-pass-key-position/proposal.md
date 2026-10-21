## Why

`redact-secret-output` read a bare `pass:` anywhere on a line as a key, so prose such as `+ // one record per pass: x` or `the second pass: done` was masked (cameronsjo/cadence-hooks#1449). Skipping a mid-line `pass:` unless it is a key would leak, though: grep, `cat -n` and `git blame` put a prefix before a YAML `pass:` key (`config/db.yml:3:  pass: <secret>`), Go's `%+v` prints `{User:admin Pass:<secret>}`, an `openssl` continuation line reads `-passout pass:<secret>`, and a qualifier before the name (`DB pass: <secret>`, `Admin pass: <secret>`) is the usual way a credential is labelled.

## What Changes

- A mid-line bare `pass:` is in key position when only blanks, markers or comment leaders come before it on its line; when it follows `{ , ; & ? ( [` or a quote; when two or more blanks or a tab come right before it; when the word before it ends in `:` (a `file:line:` prefix or a label) or starts with `-` (a flag such as `-passout`, or a dash); or when it follows a field's value (`user: admin pass:`, `user=admin pass:`, with an opener glued to the field: `{User:admin`, `&{User:admin`).
- Out of key position, a bare `pass:` is not skipped. Its unquoted value keeps the rules a bare `pass` has in key position (the short count skip, the value test) and, on top of them, masks only when its first word that holds a letter or a digit looks like a credential (at least 8 characters, not a plain word, number, duration or identifier; an identifier is letters with `_ . : < > & '` only, so a hyphen or a digit keeps a word from being an identifier). A mark, a cell border, an arrow, an emoji or a closing HTML tag (`</b>`) before the secret is not a word; when no word holds a letter or a digit, the first word is judged. The unquoted value runs to the end of the line, so a note after that word does not change the verdict. When the first word is not a credential only it is spent, so a later secret-named field on the line is still read. So `DB pass: <secret>`, `Admin pass: <secret> (change on first login)`, `Admin pass: hunter2, DB pass: <secret>` and `**DB pass:** <secret>` mask, and `the second pass: done` passes through.
- A quoted value after a bare `pass:` is not judged by its first word. Every other name, and the `pass=` and JSON forms, keep their rules.

Surfaces: `redact-secret-output` (PostToolUse, Bash), which values it masks. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-reads`: "Mask secrets in Bash output" gains scenarios for a bare `pass:` in prose (kept), behind a `file:line:` prefix (masked), in a map (masked), and after a qualifier word with a credential-shaped first word in the value: alone, with a note after it, with a mark before it, or after a field that is not a credential (masked).

## Impact

`crates/cadence/src/redact_secret_output.rs`, `CHANGELOG.md`.
