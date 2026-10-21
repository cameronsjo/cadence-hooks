## MODIFIED Requirements

### Requirement: What the guard cannot read is allowed
`trash-guard` SHALL block only on a verb and operand it read exactly. A verb built by substitution (`$(echo rm) x`), a body the guard does not treat as executed (a `trap` handler), a deleting binary outside its verb list (`srm`), a runner option it cannot classify (`nice --bogus rm x`), and a relative delete after a `cd` it cannot place (`cd "$D"`, `cd -`) MUST be judged on what was read and otherwise allowed.

#### Scenario: Unlisted deleting binary
- **WHEN** the cwd is the vault and a Bash call runs `srm note.md`
- **THEN** the hook exits 0

#### Scenario: Plain cd moves the operand
- **WHEN** the cwd is `/home/me` and a Bash call runs `cd /vault && rm note.md`
- **THEN** the hook exits 2, judging `note.md` inside the vault

## ADDED Requirements

### Requirement: A deletion behind a wrapper is judged like a bare one
From a cwd inside the vault, `trash-guard` SHALL judge a deletion that a script wrapper runs by its operands, as it judges the bare deletion. The wrappers are a shell's `-c` (`sh`, `bash`, `zsh`, `dash`), `env -S`, `script -c`, `flock`, `watch` and `su`/`runuser`, behind a runner prefix such as `sudo` or nested in one another. A wrapped deletion whose every operand is an absolute path outside the vault MUST be allowed, and one read as aimed into the vault SHALL block.

#### Scenario: Wrapped delete outside the vault
- **WHEN** the cwd is the vault and a Bash call runs `flock /tmp/l rm -f /tmp/x`, `sh -c 'rm -f /tmp/x'` or `watch -x rm -f /tmp/x`
- **THEN** the hook exits 0

#### Scenario: Wrapped delete of a vault file
- **WHEN** the cwd is the vault and a Bash call runs `sh -c 'rm -f note.md'` or `runuser -u app -- rm -f /vault/note.md`
- **THEN** the hook exits 2

#### Scenario: Wrapped delete after a plain cd
- **WHEN** the cwd is the vault, `/tmp` exists, and a Bash call runs `cd /tmp && sh -c 'rm -rf build'`
- **THEN** the hook exits 0

### Requirement: What a wrapper does not hand to the operand walk
A deletion behind a wrapper SHALL keep the cwd verdict, and so block, when the wrapper sits behind `xargs`, runs `find`, `git rm` or `eval`, changes directory before it deletes, follows a sibling that could re-point an operand (`ln`, `mv`, `cd`), or has a script the guard did not read in full (nested past what it expands, or using a variable the command assigned first).

#### Scenario: Wrapper changes directory itself
- **WHEN** the cwd is the vault and a Bash call runs `cd /tmp && sh -c 'cd /vault; rm x.md'`
- **THEN** the hook exits 2

#### Scenario: Sibling re-points an operand
- **WHEN** the cwd is the vault and a Bash call runs `ln -s /vault /tmp/l; sh -c 'rm -rf /tmp/l/note.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapped delete behind xargs
- **WHEN** the cwd is the vault and a Bash call runs `echo note.md | xargs flock /tmp/l rm`
- **THEN** the hook exits 2
