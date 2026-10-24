## ADDED Requirements

### Requirement: A fresh mktemp path is outside the vault
From a cwd inside the vault, `trash-guard` SHALL read a variable assigned in the same command from a bare `$(mktemp …)` or backtick `mktemp` as a path under the temp directory, and allow its deletion and the commands that make or fill it. The call MUST have no `-p`, `--tmpdir` or `/`, and no template unless `-t` is given. `TMPDIR` in the command, a reassignment, an assignment that may not have run, a suffix after the variable, and a sibling that moves, copies or links files MUST keep the block.

#### Scenario: Fresh path made, filled and deleted
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp); echo x > "$t"; rm -f "$t"` or `tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT`
- **THEN** the hook exits 0

#### Scenario: A path that may be in the vault
- **WHEN** the cwd is the vault and a Bash call runs `t=$(mktemp -p .); rm "$t"`, `TMPDIR=.; t=$(mktemp); rm "$t"` or `t=$(mktemp); t=note.md; rm "$t"`
- **THEN** the hook exits 2
