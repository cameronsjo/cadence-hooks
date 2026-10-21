## MODIFIED Requirements

### Requirement: Secret names in untraced command shapes block
When a Bash command sets positional parameters (`set --`, an `sh -c` script with words after it), `prevent-secret-leaks` SHALL block if any word in it names a secret file, because the guard does not trace how such a command uses its arguments. The stderr reason MUST name the secret and the shape. The same shapes with no secret name SHALL be allowed. Defining a shell function MUST NOT change the verdict: the reader rules judge the command as they would without it.

#### Scenario: Positional argument
- **WHEN** a Bash command runs `bash -c 'cat "$1"' _ .env`
- **THEN** the hook blocks and stderr says the command `sets positional parameters`

#### Scenario: Literal read in a function body
- **WHEN** a Bash command runs `f(){ cat .env; }; f`
- **THEN** the hook blocks

#### Scenario: Function argument
- **WHEN** a Bash command runs `f(){ cat "$1"; }; f .env`
- **THEN** the hook allows, since a read through an argument is indirection the guard does not trace

#### Scenario: Function with no secret
- **WHEN** a Bash command defines a function and names no secret file
- **THEN** the hook allows
