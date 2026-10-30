## MODIFIED Requirements

### Requirement: Deleting commands in the vault block
`trash-guard` SHALL block (exit 2) a Bash command that runs `rm`, `git rm` (without `--cached`), `unlink`, `shred`, `truncate`, `find ... -delete` or `find ... -exec rm` on a vault file: a relative operand from a cwd inside the vault, an operand naming a vault path (quoted or not), an ancestor of the vault, or a path that reaches the vault through `..` or a symlinked parent. The message MUST contain `Obsidian vault detected` and suggest `mkdir -p <vault>/.trash && mv <file> <vault>/.trash/`.

#### Scenario: Relative delete inside the vault
- **WHEN** the cwd is `/vault/notes` and a Bash call runs `rm old.md`
- **THEN** the hook exits 2 and stderr names `.trash`

#### Scenario: Absolute vault path from outside
- **WHEN** the cwd is `/home/me` and a Bash call runs `rm "/vault/Field Reports/old.md"`
- **THEN** the hook exits 2

#### Scenario: Ancestor of the vault
- **WHEN** the vault is `/home/me/Documents/vault` and a Bash call runs `rm -rf ~/Documents`
- **THEN** the hook exits 2

## ADDED Requirements

### Requirement: A git rm that leaves the file on disk is allowed
A `git rm` with `--cached` among its options takes the path out of the index and leaves the file on disk, so `trash-guard` SHALL allow it. Git reads `--cached` in any order with `-r`, `-q` and `-f`, ahead of any `--` or `--end-of-options`, and as an unambiguous prefix (`--cach`); a later `--no-cached` undoes it. The rule holds for the bare command, behind a runner or wrapper, as a `find -exec` action, and from outside the vault. A word known only when the shell runs is not read.

#### Scenario: Index-only git rm in the vault
- **WHEN** the cwd is the vault and a Bash call runs `git rm --cached note.md`, `git rm -r --cached sub/` or `git -C . rm --cached note.md`
- **THEN** the hook exits 0

#### Scenario: git rm that deletes the file
- **WHEN** the cwd is the vault and a Bash call runs `git rm note.md`, `git rm -- --cached` or `git rm --cached --no-cached note.md`
- **THEN** the hook exits 2

#### Scenario: A deleting command beside it
- **WHEN** the cwd is the vault and a Bash call runs `git rm --cached note.md; rm note.md`
- **THEN** the hook exits 2

#### Scenario: A --cached inside a command substitution
- **WHEN** the cwd is the vault and a Bash call runs `git rm -f note.md $(git diff --name-only --cached)`
- **THEN** the hook exits 2

#### Scenario: A command substitution beside a --cached
- **WHEN** the cwd is the vault and a Bash call runs `git rm --cached note.md $(git ls-files -d)`
- **THEN** the hook exits 0, and a `--no-cached` or `--` the substitution may print is not read
