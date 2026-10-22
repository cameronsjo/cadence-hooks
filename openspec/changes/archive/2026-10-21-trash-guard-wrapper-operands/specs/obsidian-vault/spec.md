## MODIFIED Requirements

### Requirement: What the guard cannot read is allowed
`trash-guard` SHALL block only on a verb and operand it read exactly. A verb built by a substitution the guard cannot read (`$(which rm) x`), a body bash does not run (`trap 'rm x'` with no signal, which installs nothing), a deleting binary outside its verb list (`srm`), a runner option it cannot classify (`nice --bogus rm x`), and a relative delete after a `cd` it cannot place (`cd "$D"`, `cd -`) MUST be judged on what was read and otherwise allowed.

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
A deletion behind a wrapper SHALL keep the cwd verdict, and so block, when the wrapper sits behind `xargs`, runs `find`, `git rm` or `eval`, runs `cd`, `pushd` or `popd` inside its script, follows `ln`, `mv`, or a `cd` the walk cannot place, or has a script too deeply nested to read in full beside a deletion the guard did read. After a `cd`, so SHALL one where the wrapper or a command in its script has a directory or login option (`env -C`, `su -l`, `sudo -i`).

#### Scenario: Wrapper changes directory itself
- **WHEN** the cwd is the vault and a Bash call runs `cd /tmp && sh -c 'cd /vault; rm x.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapper moves by its own option
- **WHEN** the cwd is the vault, `/tmp` exists, and a Bash call runs `cd /tmp && env -C /vault sh -c 'rm x.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapper runs find
- **WHEN** the cwd is the vault and a Bash call runs `runuser -u root find . -exec rm {} +`
- **THEN** the hook exits 2

#### Scenario: Sibling re-points an operand
- **WHEN** the cwd is the vault and a Bash call runs `ln -s /vault /tmp/l; sh -c 'rm -rf /tmp/l/note.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapped delete behind xargs
- **WHEN** the cwd is the vault and a Bash call runs `echo note.md | xargs flock /tmp/l rm`
- **THEN** the hook exits 2
