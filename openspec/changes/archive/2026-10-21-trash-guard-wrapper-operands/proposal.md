## Why

With the shell standing inside a vault, `trash-guard` judges `rm -f /tmp/x` by its operand and allows it. The same deletion behind a wrapper blocked: `flock /tmp/l rm -f /tmp/x`, `script -q -c 'rm -f /tmp/x' /dev/null`, `sh -c 'rm -f /tmp/x'`, `watch -x rm -f /tmp/x`, `runuser -u app -- rm -f /tmp/x` and `env -S 'A=1' rm -f /tmp/x`. The operand walk only judged a segment whose head is a deleting verb, and a wrapper segment is neither that nor inert, so the walk gave up and the cwd verdict stood. The wrapper's script is listed as segments of its own, so the walk already holds the deletion; it just never looked at it.

Under cadence-ecosystem ADR-0046 a guard blocks only on what it read exactly, and a deletion aimed outside the vault is not the vault harm. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), item "trash-guard: block only literal paths inside the vault; an unresolved path allows".

## What Changes

- From a cwd inside the vault, a segment that is a script wrapper (a shell's `-c`, `env -S`, `script -c`, `flock`, `watch`, `su`/`runuser`) no longer ends the operand walk. Its script's own segments are judged operand by operand, the way a bare deletion is. The same holds for the directory walk that places a deletion after a `cd`.
- A wrapper still keeps the cwd verdict when it is behind `xargs`, when core read no script out of it, when any segment of its script is not in the walk's list (nesting past what core expands, in a command where the guard read another deletion; a deletion nested deeper with none beside it is never read, and is allowed), and, in the directory walk, when it mentions `cd`, `pushd` or `popd`, because the walk places a wrapper's whole script where the wrapper starts.
- `find`, `git`, `tmux`, `eval` and `trap` are not script wrappers here and keep the cwd verdict, as do `ln` and `mv` siblings, a `cd` sibling the walk cannot place, and a deletion the guard reads as aimed into the vault. A directory option or login shell (`env -C`, `env --chdir`, `su -`, `su -l`, `runuser -l`, `sudo -i`) is not followed, the same as for a bare deletion.
- MODIFY "What the guard cannot read is allowed": its example of a runner option the guard cannot classify named `env -S 'rm x'`, which core has read since cameronsjo/cadence-hooks#1144 and which blocks. The example is now `nice --bogus rm x`. Its other two examples blocked too: core reads a literal substitution such as `$(echo rm) x`, and a `trap` that installs a handler is judged. They are now `$(which rm) x` and `trap 'rm x'` with no signal, which installs nothing.
- ADD "A deletion behind a wrapper is judged like a bare one" and "What a wrapper does not hand to the operand walk".

Surfaces: `trash-guard` (PreToolUse, Bash) and its exit code (2 to 0 for a wrapped deletion whose every operand is an absolute path outside the vault). No message text changes. No hooks.json change in cameronsjo/cadence.

The harm ADR-0046 rule 2 names, vault deletions, is not widened: every shape that blocked because the deletion is aimed into the vault still blocks.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `obsidian-vault`: two new requirements for a deletion behind a wrapper, and a corrected example in "What the guard cannot read is allowed".

## Impact

`crates/obsidian/src/trash_guard.rs`, `CHANGELOG.md`.
