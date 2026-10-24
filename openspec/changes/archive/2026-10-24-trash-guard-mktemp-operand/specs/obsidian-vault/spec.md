## ADDED Requirements

### Requirement: A fresh mktemp path holds no vault file
From a cwd inside the vault, `trash-guard` SHALL read a bare `$(mktemp …)` operand, or a variable the command assigned from one or a backtick `mktemp`, quoted or not, as a fresh path holding no vault file, whatever its options, template or `TMPDIR`, and allow deleting it and what makes or fills it. A call it does not read, a reassignment to anything else, an assignment that may be skipped, a suffix, an operand that may be a vault file and a sibling that is not inert MUST keep the block.

#### Scenario: Fresh path made, filled and deleted
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp); echo x > "$t"; rm -f "$t"`, `tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT`, `t=$(mktemp); rm -f $t` or `t=$(mktemp -p .); rm "$t"`
- **THEN** the hook exits 0

#### Scenario: A call the guard does not read
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp -p /tmp); rm "$t"` (a `/` in the call), `t=$(TMPDIR=. mktemp); rm "$t"` (a word before `mktemp`) or `rm -f $(mktemp --help)` (the call prints text, not a path)
- **THEN** the hook exits 2

#### Scenario: A variable that may not hold the fresh path
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp); t=note.md; rm "$t"`, `t=$(mktemp -d); trap 'rm -rf $t' EXIT; t=*` or `tmp=$(mktemp -d); mv note.md "$tmp"; rm -rf "$tmp"`
- **THEN** the hook exits 2
