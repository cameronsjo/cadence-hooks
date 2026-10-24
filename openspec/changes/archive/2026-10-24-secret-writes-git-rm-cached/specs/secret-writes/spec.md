## ADDED Requirements

### Requirement: A git rm that leaves the file on disk is allowed
A `git rm` with `--cached` among its options takes the path out of the index and leaves the file on disk, so `prevent-secret-writes` SHALL NOT read its operands as write targets. Git reads `--cached` in any order with `-r`, `-q` and `-f`, ahead of any `--` or `--end-of-options`, and as an unambiguous prefix (`--cach`); a later `--no-cached` undoes it. The test MUST be the same one `trash-guard` reads `git rm` with.

#### Scenario: Untracking a secret file
- **WHEN** a Bash command runs `git rm --cached .env`, `git rm --cached -r .env` or `git -C . rm --cached .env`
- **THEN** the hook allows

#### Scenario: git rm that deletes the file
- **WHEN** a Bash command runs `git rm .env`, `git rm -- --cached .env` or `git rm --cached --no-cached .env`
- **THEN** the hook blocks

#### Scenario: A deleting command beside it
- **WHEN** a Bash command runs `git rm --cached .env; rm .env`
- **THEN** the hook blocks
