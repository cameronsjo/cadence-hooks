# obsidian-vault Specification

## Purpose
Protection for an Obsidian vault's recoverability: `cadence-hooks obsidian trash-guard`, a PreToolUse guard that blocks deleting or truncating vault files and points to the vault's `.trash/` folder instead, and `cadence-hooks obsidian trash-guard-liveness`, a SessionStart check that the guard's routes still judge as contracted.

## Requirements

### Requirement: Scoped to a configured vault
`trash-guard` SHALL judge nothing and allow every call when `OBSIDIAN_VAULT` is unset or empty. With a vault set, it SHALL compare paths after normalizing separators and trailing slashes on both sides, so a vault spelled with backslashes matches a forward-slash path. It runs unchanged in a cloud session.

#### Scenario: No vault configured
- **WHEN** `OBSIDIAN_VAULT` is unset and a Bash call runs `rm -rf notes/`
- **THEN** the hook exits 0 with no output

#### Scenario: Vault name as a prefix of another directory
- **WHEN** `OBSIDIAN_VAULT=/vault` and a Bash call runs `rm /vault-old/x.md` from `/home/me`
- **THEN** the hook exits 0

### Requirement: Deleting commands in the vault block
`trash-guard` SHALL block (exit 2) a Bash command that runs `rm`, `git rm` (without `--cached`), `unlink`, `shred`, `truncate`, `find ... -delete` or `find ... -exec rm` on a vault file: a relative operand from a cwd inside the vault, an operand naming a vault path (quoted or not), an ancestor of the vault, or a path that reaches the vault through `..` or a symlinked parent. The message MUST contain `Obsidian vault detected` and suggest `mkdir -p <vault>/.trash && mv <file> <vault>/.trash/`.

#### Scenario: Relative delete inside the vault
- **WHEN** the cwd is `/vault/notes` and a Bash call runs `rm old.md`
- **THEN** the hook exits 2 and stderr names `.trash`

#### Scenario: Absolute vault path from outside
- **WHEN** the cwd is `/home/me` and a Bash call runs `rm "/vault/Field Reports/old.md"`
- **THEN** the hook exits 2

#### Scenario: Ancestor of the vault
- **WHEN** the vault is `/home/me/Documents/vault` and a Bash call runs `rm -rf ~/Documents`
- **THEN** the hook exits 2

### Requirement: Where a deleting verb is read
A verb SHALL count only where the shell runs it: at the head of a segment or as a `find` exec action, read past compound scaffolding (`if`, `for`, `while`, groups, `case` arms), runner prefixes and their flags (`sudo`, `xargs`, `nice`, `stdbuf`, `timeout`, `env`) and git's global options, with the verb matched case-insensitively. A re-executed operand (`eval`, `sh -c`, `bash -c`, `find -exec sh -c`) and a command or process substitution body SHALL be scanned as commands in their own right.

#### Scenario: Wrapped in a shell and a loop
- **WHEN** the cwd is the vault and a Bash call runs `for f in a; do sh -c 'rm x.md'; done`
- **THEN** the hook exits 2

#### Scenario: git global option before rm
- **WHEN** the cwd is the vault and a Bash call runs `git -C . rm note.md`
- **THEN** the hook exits 2

#### Scenario: Process substitution
- **WHEN** the cwd is the vault and a Bash call runs `cat <(rm note.md)`
- **THEN** the hook exits 2

### Requirement: Ordinary commands are allowed
`trash-guard` is wired with no prefilter, so it SHALL stay a silent allow on ordinary commands. A deleting word used as an argument, a word that merely contains `rm`, a non-deleting command naming a vault path, `mv` into `.trash/`, `find` without `-delete`, and a delete whose every operand resolves outside the vault MUST all be allowed, even from a cwd inside the vault.

#### Scenario: Look-alike commands in the vault
- **WHEN** the cwd is the vault and a Bash call runs `npm run format`, `terraform destroy` or `echo RM note.md`
- **THEN** the hook exits 0 with no output

#### Scenario: Moving to the trash
- **WHEN** the cwd is the vault and a Bash call runs `mv old.md .trash/`
- **THEN** the hook exits 0

#### Scenario: Delete outside the vault from inside it
- **WHEN** the cwd is the vault and a Bash call runs `rm /tmp/scratch.txt`
- **THEN** the hook exits 0

### Requirement: What the guard cannot read is allowed
`trash-guard` SHALL block only on a verb and operand it read exactly. A verb built by a substitution the guard cannot read (`$(which rm) x`), a body bash does not run (`trap 'rm x'` with no signal, which installs nothing), a deleting binary outside its verb list (`srm`), a runner option it cannot classify (`nice --bogus rm x`), and a relative delete after a `cd` it cannot place (`cd "$D"`, `cd -`) MUST be judged on what was read and otherwise allowed.

#### Scenario: Unlisted deleting binary
- **WHEN** the cwd is the vault and a Bash call runs `srm note.md`
- **THEN** the hook exits 0

#### Scenario: Plain cd moves the operand
- **WHEN** the cwd is `/home/me` and a Bash call runs `cd /vault && rm note.md`
- **THEN** the hook exits 2, judging `note.md` inside the vault

### Requirement: Clobbering redirects over vault files
`trash-guard` SHALL block a `>` or `>|` redirect (including `: > file`, inside `sh -c` or a substitution, and after brace expansion of the target) whose target resolves to an existing file in the vault, with a message suggesting a move to `.trash/` and `>>` or a new filename. An append (`>>`), a redirect creating a new file, and a redirect outside the vault MUST be allowed.

#### Scenario: Truncating an existing note
- **WHEN** the cwd is the vault, `note.md` exists, and a Bash call runs `: > note.md`
- **THEN** the hook exits 2

#### Scenario: Appending is allowed
- **WHEN** the cwd is the vault and a Bash call runs `echo hi >> note.md`
- **THEN** the hook exits 0

### Requirement: Empty writes and harness deletes
`trash-guard` SHALL block a Write whose content is empty or only Unicode whitespace when the target, read lexically or through a symlinked parent, is an existing vault file. A Write with real content, or to a file that does not exist yet, MUST be allowed. It SHALL block a harness delete that names a vault path (`operation: "delete"`, such as an `apply_patch` `*** Delete File:`), but MUST NOT treat a rename or move as a delete.

#### Scenario: Empty Write over a note
- **WHEN** a Write of `""` targets an existing `/vault/note.md`
- **THEN** the hook exits 2

#### Scenario: Patch rename into the trash
- **WHEN** an `apply_patch` moves `/vault/note.md` to `/vault/.trash/note.md`
- **THEN** the hook exits 0

### Requirement: Protected guard
`trash-guard` is a protected, security-critical guard: `CADENCE_DISABLE` MUST NOT turn it off. `CADENCE_BYPASS=1` keeps its general meaning.

#### Scenario: Disable request refused
- **WHEN** `CADENCE_DISABLE=trash-guard` is set and a Bash call runs `rm note.md` from the vault
- **THEN** the hook still exits 2

### Requirement: Liveness probe at session start
`obsidian trash-guard-liveness` SHALL, at SessionStart with `OBSIDIAN_VAULT` set, run the guard's own judgement against the vault with an in-memory existence view and nudge when a probe returns the wrong verdict, naming each diverged route. The probes MUST cover `rm` from inside, `rm` of an absolute vault path from outside, `: >` over an existing file, a harness delete, an empty Write, and two controls that must allow. It MUST touch no file on disk.

#### Scenario: Healthy vault
- **WHEN** `OBSIDIAN_VAULT` names an existing directory and every route judges as contracted
- **THEN** the hook exits 0 with no output

#### Scenario: Diverged route
- **WHEN** the empty-Write route returns Allow
- **THEN** the hook exits 0 with a nudge starting `trash-guard is not judging vault deletions as contracted` that names that route

### Requirement: Liveness reporting limits
`trash-guard-liveness` SHALL be silent when `OBSIDIAN_VAULT` is unset or empty, SHALL nudge when it is set but not a directory, and MUST never block. The nudge MUST NOT echo the vault path. A vault path with characters needing shell quoting MUST skip the absolute-path probe rather than report a divergence. In a cloud session it MUST exit 0 silently.

#### Scenario: Vault is not a directory
- **WHEN** `OBSIDIAN_VAULT=/nonexistent/vault` at SessionStart
- **THEN** the hook exits 0 with a nudge saying `OBSIDIAN_VAULT` is not a directory, without printing the path

#### Scenario: Cloud session
- **WHEN** `CLAUDE_CODE_REMOTE=true` at SessionStart
- **THEN** the hook exits 0 with no output

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
A deletion the guard reads behind a wrapper SHALL keep the cwd verdict, a block, when the wrapper sits behind `xargs`, runs `find`, `git rm` or `eval`, runs `cd`, `pushd` or `popd` in its script, follows `ln`, `mv`, or a `cd` the walk cannot place, or has a script too deep to read in full beside a deletion the guard read. After a `cd`, so SHALL one where the wrapper has a directory or login option (`env -C`, `sudo -i`), and one with such an option inside or beside a wrapper.

#### Scenario: Wrapper changes directory itself
- **WHEN** the cwd is the vault and a Bash call runs `cd /tmp && sh -c 'cd /vault; rm x.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapper moves by its own option
- **WHEN** the cwd is the vault, `/tmp` exists, and a Bash call runs `cd /tmp && env -C /vault sh -c 'rm x.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapper runs find
- **WHEN** the cwd is the vault and a Bash call runs `runuser -u root find . -exec rm {} +`
- **THEN** the hook exits 2

#### Scenario: Deletion moves by its own option beside a wrapper
- **WHEN** the cwd is the vault, `/tmp` exists, and a Bash call runs `cd /tmp && flock /tmp/l echo hi; env -C /vault rm x.md`
- **THEN** the hook exits 2

#### Scenario: Sibling re-points an operand
- **WHEN** the cwd is the vault and a Bash call runs `ln -s /vault /tmp/l; sh -c 'rm -rf /tmp/l/note.md'`
- **THEN** the hook exits 2

#### Scenario: Wrapped delete behind xargs
- **WHEN** the cwd is the vault and a Bash call runs `echo note.md | xargs flock /tmp/l rm`
- **THEN** the hook exits 2

### Requirement: A git rm that leaves the file on disk is allowed
A `git rm` with `--cached` among its options takes the path out of the index and leaves the file on disk, so `trash-guard` SHALL allow it. Git reads `--cached` in any order with `-r`, `-q` and `-f`, ahead of any `--` or `--end-of-options`, and as an unambiguous prefix (`--cach`); a later `--no-cached` undoes it. The rule holds for the bare command, behind a runner or wrapper, as a `find -exec` action, and from outside the vault.

#### Scenario: Index-only git rm in the vault
- **WHEN** the cwd is the vault and a Bash call runs `git rm --cached note.md`, `git rm -r --cached sub/` or `git -C . rm --cached note.md`
- **THEN** the hook exits 0

#### Scenario: git rm that deletes the file
- **WHEN** the cwd is the vault and a Bash call runs `git rm note.md`, `git rm -- --cached` or `git rm --cached --no-cached note.md`
- **THEN** the hook exits 2

#### Scenario: A deleting command beside it
- **WHEN** the cwd is the vault and a Bash call runs `git rm --cached note.md; rm note.md`
- **THEN** the hook exits 2
