## Why

With the shell standing inside a vault, `trash-guard` blocks a deletion whose operand is a variable it cannot resolve. That is right for `rm "$X"`, but not for a variable the same command assigned from `mktemp`: `t=$(mktemp); echo x > "$t"; rm -f "$t"` and `tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT` blocked. `mktemp` only ever makes a new path, so deleting what it returned deletes no vault file.

`command_segments` already writes such a variable into later segments as the call (`rm -f "$(mktemp)"`). The operand walk read that operand as unresolvable, and read the segments that make and fill the path (`t=$(mktemp)`, `mktemp`, `echo x > …`, `trap …`) as siblings that could re-point an operand, so it kept the cwd verdict.

Under cadence-ecosystem ADR-0046 rule 2 a guard blocks only a vault deletion it read exactly, and only a costly one. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), item "trash-guard: block only literal paths inside the vault; an unresolved path allows".

## What Changes

- From a cwd inside the vault, an operand that is a bare `$(mktemp …)` or backtick `mktemp` (which is what a variable assigned from one reads as), quoted or not, holds no vault file. The call's options, template and `TMPDIR` are not checked: `mktemp` creates its path new (with `-u` it names one that does not exist), so even `mktemp -p .` or a template in the shell's directory returns nothing the vault held before. The call is read only over plain words: a `/`, a quote, a `$`, a nested substitution or anything before `mktemp` is not read. An unquoted call is read whole from its words, because the tokenizer cuts it at its blanks and a segment's last `)` is trimmed as a group closer. Unquoted, the shell splits and globs what the call prints, so a call with `--help` or `--version` (text, not a path) is not read there: `rm -f $(mktemp --help)` keeps the block.
- The segments that make or fill the path pass in the operand walk: an assignment of such a call (and the `*` the walk lists beside it), the call itself with no redirect, an inert verb whose every redirect writes such a path, and a `trap` whose action hands its commands only variables. The trap's commands are segments of the walk too and are judged there like any other.
- Kept: a variable assigned again, in any way a segment shows (`t=note.md`, `t+=…`, `read t`); an assignment that may not have run or may not have changed the value (`t=${t:-$(mktemp)}`, `[ -z "$t" ] && t=$(mktemp)`, `printf -v t …`, and a bare `t=*`, which is a glob); a suffix (`"$t"/x`); an operand that is not the path alone; a sibling that is not inert (`mv`, `cp`, `ln`, `cd`, `TMPDIR=.`, `export TMPDIR=.`); and a `trap` whose action hands a command a path or a redirect, so `trap 'rm -f /tmp/a' EXIT; rm /tmp/b` stays as it was.
- Not changed: the directory walk that places a deletion after a `cd` (`cd /tmp && t=$(mktemp) && rm "$t"` keeps the cwd verdict), and any other sibling that is not inert (`curl`, `python3`, `git`).

Surfaces: `trash-guard` (PreToolUse, Bash) and its exit code (2 to 0 for a fresh `mktemp` path). No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `obsidian-vault`: "A fresh mktemp path holds no vault file" is added. No existing line goes false.

## Impact

`crates/obsidian/src/trash_guard.rs`, `CHANGELOG.md`.
