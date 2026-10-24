## Why

With the shell standing inside a vault, `trash-guard` blocks a deletion whose operand is a variable it cannot resolve. That is right for `rm "$X"`, but not for a variable the same command assigned from `mktemp`: `t=$(mktemp); echo x > "$t"; rm -f "$t"` and `tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT` blocked. A bare `mktemp` makes a new path under the temp directory, so deleting it cannot delete a vault file.

`command_segments` already writes such a variable into later segments as the call (`rm -f "$(mktemp)"`). The operand walk read that operand as unresolvable, and read the segments that make and fill the path (`t=$(mktemp)`, `mktemp`, `echo x > …`, `trap …`) as siblings that could re-point an operand, so it kept the cwd verdict.

Under cadence-ecosystem ADR-0046 rule 2 a guard blocks only a vault deletion it read exactly. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), item "trash-guard: block only literal paths inside the vault; an unresolved path allows".

## What Changes

- From a cwd inside the vault, an operand that is a bare `$(mktemp …)` or backtick `mktemp` (which is what a variable assigned from one reads as) is outside the vault. The call must have no `-p`, `--tmpdir` (or an abbreviation of it) or `/`, and no template unless `-t` is given: a template without `-t` is made in the shell's directory.
- The segments that make or fill the path pass in the operand walk: an assignment of such a call (and the `*` the walk lists beside it), the call itself, an inert verb whose every redirect writes such a path, and a `trap` whose action only deletes variables.
- Kept: a `TMPDIR` anywhere in the command; a variable assigned again, in any way a segment shows (`t=note.md`, `t+=…`, `read t`); an assignment that may not have run or may not have changed the value (`t=${t:-$(mktemp)}`, `[ -z "$t" ] && t=$(mktemp)`, `printf -v t …`); a suffix (`"$t"/x`); an operand that is not the path alone; a `mv`, `cp`, `ln` or `cd` sibling; and a `trap` whose action deletes anything but variables, so `trap 'rm -f /tmp/a' EXIT; rm /tmp/b` stays as it was.
- Not changed: the directory walk that places a deletion after a `cd` (`cd /tmp && t=$(mktemp) && rm "$t"` keeps the cwd verdict), and any other sibling that is not inert (`curl`, `python3`, `git`).

Surfaces: `trash-guard` (PreToolUse, Bash) and its exit code (2 to 0 for a fresh `mktemp` path). No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `obsidian-vault`: "A fresh mktemp path is outside the vault" is added. No existing line goes false.

## Impact

`crates/obsidian/src/trash_guard.rs`, `CHANGELOG.md`.
