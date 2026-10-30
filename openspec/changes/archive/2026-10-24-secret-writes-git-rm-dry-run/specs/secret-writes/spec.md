## ADDED Requirements

### Requirement: A git rm dry run is allowed
A `git rm` dry run prints what it would remove and changes neither the index nor the file, so `prevent-secret-writes` SHALL NOT read its operands as write targets. Git reads `-n` or `--dry-run` in any order with the other options, ahead of any `--` or `--end-of-options`. `-n` can share a word with `-r`, `-q` and `-f` (`-rn`), and `--dry-run` can be an unambiguous prefix (`--dry`); a later `--no-dry-run` undoes it.

#### Scenario: Dry run of a secret file
- **WHEN** a Bash command runs `git rm -n .env`, `git rm --dry-run .env` or `git rm -rn .env`
- **THEN** the hook allows

#### Scenario: git rm that deletes the file
- **WHEN** a Bash command runs `git rm .env`, `git rm -- -n .env` or `git rm -n --no-dry-run .env`
- **THEN** the hook blocks

#### Scenario: A deleting command beside it
- **WHEN** a Bash command runs `git rm -n .env; rm .env`
- **THEN** the hook blocks
