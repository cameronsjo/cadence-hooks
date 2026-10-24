## MODIFIED Requirements

### Requirement: Writer verbs targeting a secret file block
`prevent-secret-writes` SHALL block a Bash command whose writer verb would create, overwrite, or delete a secret file (but see "A git rm that leaves the file on disk is allowed"), after peeling command runners (`sudo`, `env`, `nice`, `timeout`, `xargs`, `command`, `exec`, `time`). A copy from a secret file to a non-secret destination SHALL be allowed by this guard, since the read is `prevent-secret-leaks`' concern, and a quoted filename that only mentions a secret word MUST be allowed.

#### Scenario: Deleting, truncating, and teeing
- **WHEN** a Bash command runs `sudo rm ~/.ssh/id_rsa`, `truncate -s0 .env`, `tee .pgpass`, `shred .env`, or `git rm .env`
- **THEN** the hook blocks each one

#### Scenario: Copy and move destinations
- **WHEN** a Bash command runs `cp .env.example .env`, `mv x .env`, `install x .env`, `dd of=.env`, or `rsync x .env`
- **THEN** the hook blocks each one

#### Scenario: In-place editors, downloaders, and find
- **WHEN** a Bash command runs `sed -i s/a/b/ .env`, `curl -o .env https://x`, `find . -name .env -delete`, or `find . -name .env -exec rm {} \;`
- **THEN** the hook blocks each one

#### Scenario: Copying out and prose
- **WHEN** a Bash command runs `cp .env /tmp/notes.txt` or `rm "notes about .env stuff.txt"`
- **THEN** `prevent-secret-writes` allows

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
