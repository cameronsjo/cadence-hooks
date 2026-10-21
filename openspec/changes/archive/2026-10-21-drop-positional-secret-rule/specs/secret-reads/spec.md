## REMOVED Requirements

### Requirement: Secret names in untraced command shapes block
**Reason**: cadence-ecosystem ADR-0046 rule 1 puts function and positional-parameter indirection out of scope, so a command no longer blocks for its shape. cameronsjo/cadence-hooks#1465 removed the function half and cameronsjo/cadence-hooks#1468 removes the positional half.
**Migration**: None. The reader rules judge every command, as "A literal read blocks whatever the command's shape" says.

## ADDED Requirements

### Requirement: A literal read blocks whatever the command's shape
`prevent-secret-leaks` SHALL judge a Bash command by the reads the reader rules find, so a literal read SHALL block whether or not the command defines a shell function or sets positional parameters, including one in a `-c` script behind a shell option cluster. A secret named only as an argument (`$1`, `"$@"`, `$0`) MUST be allowed.

#### Scenario: Script behind an option cluster
- **WHEN** a Bash command runs `bash -eo pipefail -c 'cat .env'`
- **THEN** the hook blocks

#### Scenario: Literal read beside a shape
- **WHEN** a Bash command runs `f(){ cat .env; }; f` or `set -- a b; cat .env`
- **THEN** the hook blocks

#### Scenario: Secret passed as an argument
- **WHEN** a Bash command runs `bash -c 'cat "$1"' _ .env`, `set -- .env; cat "$1"` or `f(){ cat "$1"; }; f .env`
- **THEN** the hook allows, since a read through an argument is indirection the guard does not trace

#### Scenario: Shapes with no secret
- **WHEN** a Bash command defines a function or sets positional parameters and names no secret file
- **THEN** the hook allows

### Requirement: A script the guard does not read is allowed
`prevent-secret-leaks` MUST allow a `-c` script behind a wrapper the guard does not peel, or whose operands it re-joins without their quotes (`parallel`, `fd -x`/`-X`, `bash -s` with operands, `flock FILE CMD…`, BSD `script FILE CMD…`), like the bare `parallel cat .env ::: a`. A script piped into a shell is not read either. A bare command behind `flock` or BSD `script` is read, so it MUST block.

#### Scenario: Script the guard does not read
- **WHEN** a Bash command runs `parallel sh -c 'cat .env' ::: a`, `fd -x sh -c 'cat .env'`, `echo 'cat .env' | bash -s x`, `flock /tmp/l sh -c 'cat .env'` or `script -q /dev/null sh -c 'cat .env'`
- **THEN** the hook allows

#### Scenario: Bare command behind flock or script
- **WHEN** a Bash command runs `flock /tmp/l cat .env`, `flock /tmp/l -c 'cat .env'` or `script -q /dev/null cat .env`
- **THEN** the hook blocks
