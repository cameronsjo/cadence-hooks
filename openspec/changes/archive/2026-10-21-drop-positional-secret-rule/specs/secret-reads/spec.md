## REMOVED Requirements

### Requirement: Secret names in untraced command shapes block
**Reason**: cadence-ecosystem ADR-0046 rule 1 puts function and positional-parameter indirection out of scope, so a command no longer blocks for its shape. cameronsjo/cadence-hooks#1465 removed the function half and cameronsjo/cadence-hooks#1468 removes the positional half.
**Migration**: None. The reader rules judge every command, as "A literal read blocks whatever the command's shape" says.

## ADDED Requirements

### Requirement: A literal read blocks whatever the command's shape
`prevent-secret-leaks` SHALL judge a Bash command by the reads the reader rules find, so a literal read SHALL block whether or not the command defines a shell function or sets positional parameters, including one in a `-c` script behind a shell option cluster. A secret named only as an argument (`$1`, `"$@"`, `$0`) MUST be allowed. A `-c` script that `parallel` or `fd -x`/`-X` runs, and a script piped into a shell, are not read and MUST be allowed, like the bare `parallel cat .env ::: a`.

#### Scenario: Script behind an option cluster
- **WHEN** a Bash command runs `bash -eo pipefail -c 'cat .env'`
- **THEN** the hook blocks

#### Scenario: Literal read beside a shape
- **WHEN** a Bash command runs `f(){ cat .env; }; f` or `set -- a b; cat .env`
- **THEN** the hook blocks

#### Scenario: Secret passed as an argument
- **WHEN** a Bash command runs `bash -c 'cat "$1"' _ .env`, `set -- .env; cat "$1"` or `f(){ cat "$1"; }; f .env`
- **THEN** the hook allows, since a read through an argument is indirection the guard does not trace

#### Scenario: Script the guard does not read
- **WHEN** a Bash command runs `parallel sh -c 'cat .env' ::: a`, `fd -x sh -c 'cat .env'` or `echo 'cat .env' | bash -s x`
- **THEN** the hook allows

#### Scenario: Shapes with no secret
- **WHEN** a Bash command defines a function or sets positional parameters and names no secret file
- **THEN** the hook allows
