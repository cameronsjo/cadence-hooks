## MODIFIED Requirements

### Requirement: A script the guard does not read is allowed
`prevent-secret-leaks` MUST allow a `-c` script behind a wrapper the guard does not peel (`parallel`, `fd -x`/`-X`), like the bare `parallel cat .env ::: a`. A script piped into a shell (`bash -s` with operands) is not read either. A command behind `flock` or BSD `script` is read with its words whole, so a read there MUST block.

#### Scenario: Script the guard does not read
- **WHEN** a Bash command runs `parallel sh -c 'cat .env' ::: a`, `fd -x sh -c 'cat .env'` or `echo 'cat .env' | bash -s x`
- **THEN** the hook allows

#### Scenario: Bare command behind flock or script
- **WHEN** a Bash command runs `flock /tmp/l cat .env`, `flock /tmp/l -c 'cat .env'` or `script -q /dev/null cat .env`
- **THEN** the hook blocks

#### Scenario: Shell script behind flock or script
- **WHEN** a Bash command runs `flock /tmp/l sh -c 'cat .env'` or `script -q /dev/null sh -c 'cat .env'`
- **THEN** the hook blocks
