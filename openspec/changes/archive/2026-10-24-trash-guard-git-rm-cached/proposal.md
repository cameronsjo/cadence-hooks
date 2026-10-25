## Why

`git rm --cached note.md` takes the path out of the index and leaves the file on disk. With the shell standing inside a vault, `trash-guard` blocked it anyway: it read every `git rm` as a deletion. `git rm -r --cached sub/`, `git rm --cached -r .` and `git -C . rm --cached note.md` blocked too. They delete no vault file, so the block buys no recoverability and sends an everyday untracking command to `.trash/`.

Under cadence-ecosystem ADR-0046 rule 2 a guard blocks only a costly harm it read exactly. A vault deletion is one; an index-only `git rm` is not. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), item "trash-guard: block only literal paths inside the vault".

## What Changes

- `git rm` with `--cached` among its options is not a deletion. `--cached` counts in any order with `-r`, `-q` and `-f`, before any `--` or `--end-of-options`, and as any unambiguous prefix of it (`--cach`, `--c`), as git reads it. A later `--no-cached` (or `--no-c`) undoes it, and the last of the two wins.
- Every place the guard reads `git rm` goes through one test, so the rule holds for the bare command, behind a runner (`sudo`, `xargs`), behind a wrapper (`sh -c`, `flock`), as a `find -exec` action, and for an operand outside the vault.
- Unchanged: a plain `git rm`, `git rm -r`, a `git rm -- --cached` (a file named `--cached`) and `git rm --cached --no-cached note.md` still block, and so does a deleting command beside an index-only `git rm`.
- Words inside a command substitution or backticks are not `git rm`'s: in `git rm -f note.md $(git diff --name-only --cached)` the `--cached` belongs to `git diff`, and the command still blocks. Core's new `git_rm_option_words` yields the words git reads as typed, and every `git rm` option reader iterates them.
- Not read: the value of an option that takes a separate word (`--pathspec-from-file --cached` reads the file `--cached`), and a word whose value is known only at run time (a substitution or an unresolved variable that would print `--no-cached` or `--`). ADR-0046 rule 1 leaves such spellings out.

Surfaces: `trash-guard` (PreToolUse, Bash) and its exit code (2 to 0 for an index-only `git rm`). No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `obsidian-vault`: "Deleting commands in the vault block" names `git rm` as `git rm` without `--cached`, and "A git rm that leaves the file on disk is allowed" is added.

## Impact

`crates/obsidian/src/trash_guard.rs`, `crates/core/src/shell.rs` (the new `git_rm_option_words`), `docs/hooks.md`, `CHANGELOG.md`.
