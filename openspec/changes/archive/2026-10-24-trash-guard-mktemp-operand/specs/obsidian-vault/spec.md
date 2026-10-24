## ADDED Requirements

### Requirement: A fresh mktemp path holds no vault file
From a cwd inside the vault, `trash-guard` SHALL read a variable assigned in the same command from a bare `$(mktemp …)` or backtick `mktemp`, and a `$(mktemp …)` operand, quoted or not, as the path `mktemp` just made, and allow its deletion and the commands that make or fill it. `mktemp` only ever makes a new path, so this holds whatever the call's options, template or `TMPDIR`. A call with a `/`, a quote, a `$`, a nested substitution or anything before `mktemp` is not read. A reassignment (a bare `*` included), an assignment that may not have run, a suffix after the variable, another operand, and a sibling that is not inert (one that moves, copies or links files, a `cd`, a `TMPDIR` assignment) MUST keep the block.

#### Scenario: Fresh path made, filled and deleted
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp); echo x > "$t"; rm -f "$t"`, `tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT`, `t=$(mktemp); rm -f $t` or `t=$(mktemp -p .); rm "$t"`
- **THEN** the hook exits 0

#### Scenario: A variable that may not hold the fresh path
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp); t=note.md; rm "$t"`, `t=$(mktemp -d); trap 'rm -rf $t' EXIT; t=*` or `tmp=$(mktemp -d); mv note.md "$tmp"; rm -rf "$tmp"`
- **THEN** the hook exits 2
