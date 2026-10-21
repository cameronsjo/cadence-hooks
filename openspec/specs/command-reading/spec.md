# command-reading Specification

## Purpose
The shared rules every Bash-reading guard follows when it reads a `tool_input.command` line, for example `cadence-hooks cadence git-safety`, `cadence-hooks cadence prevent-secret-leaks`, `cadence-hooks cadence prevent-secret-writes`, `cadence-hooks cadence prevent-secret-push`, `cadence-hooks guardrails guard-push-remote`, `cadence-hooks guardrails enforce-worktree` and `cadence-hooks obsidian trash-guard`. They set which parts of a command a guard sees as commands to judge, which parts it sees as data, and what it does with a part it cannot read. Under cadence-ecosystem ADR-0046 a guard blocks only on what it read exactly, and allows what it could not read.

## Requirements

### Requirement: Every segment is judged
A guard SHALL split a command at `;`, `&&`, `||`, `|`, `&` and unquoted newlines, and at the keywords of `if`, `for`, `while` and `case` bodies, and SHALL judge every resulting command. A dangerous command in any one segment MUST block the whole command line, whatever runs before or after it and whether or not the earlier segments would succeed. A command line made only of ordinary segments MUST be allowed.

#### Scenario: Dangerous command after a harmless one
- **WHEN** `cadence git-safety` reads `echo hi && git reset --hard`
- **THEN** it blocks

#### Scenario: Dangerous command in an unreachable branch
- **WHEN** `cadence git-safety` reads `true || git reset --hard` or `while false; do git reset --hard; done`
- **THEN** it blocks, because the guard judges what is written, not whether it would run

#### Scenario: Ordinary compound command is allowed
- **WHEN** `cadence git-safety` reads `git status; ls -la && npm test` or `git log --oneline | head`
- **THEN** it exits 0

### Requirement: Nested commands are reached
A guard SHALL read the commands inside subshells `( … )`, brace groups `{ …; }`, command substitutions `$( … )` and backticks (unquoted or inside double quotes), process substitutions `<( … )`, and shell function bodies, and SHALL judge them as commands. Nesting up to at least eight levels deep, in any mix of these shapes, MUST still be reached. A single-quoted string is data and its contents MUST NOT be judged as a command.

#### Scenario: Substitution several levels deep
- **WHEN** `cadence git-safety` reads `cat <(echo $(echo $(echo $(git reset --hard))))`
- **THEN** it blocks

#### Scenario: Function body
- **WHEN** `cadence git-safety` reads `f(){ git reset --hard; }; f`
- **THEN** it blocks

#### Scenario: Single-quoted substitution is text
- **WHEN** `cadence git-safety` reads `echo '$(git reset --hard)'`
- **THEN** it exits 0

#### Scenario: Deep but harmless nesting
- **WHEN** `guardrails enforce-worktree` reads `git status` nested six levels inside `$( … )` and `<( … )`
- **THEN** it exits 0

### Requirement: Wrappers and runners are seen through
A guard SHALL judge the command a wrapper or runner executes, including leading `VAR=value` assignments, `env`, `sudo` with its flags, `nice`, `nohup`, `time`, `timeout`, `command`, `exec`, `xargs`, `find -exec`, the script argument of `bash -c` and `sh -c` (also after `--`), and a here-string given to a shell. A command word spelled with a leading backslash or as an absolute path SHALL read as the command it names, and an `eval` of a literal string SHALL read as that string.

#### Scenario: Shell script argument
- **WHEN** `cadence git-safety` reads `sh -c -- "git reset --hard"`
- **THEN** it blocks

#### Scenario: Runner with flags
- **WHEN** `cadence git-safety` reads `sudo -E git reset --hard`, `timeout 5 git reset --hard` or `echo . | xargs git reset --hard`
- **THEN** it blocks

#### Scenario: Path spelling of the command word
- **WHEN** `cadence git-safety` reads `/usr/bin/git reset --hard` or `\git reset --hard`
- **THEN** it blocks

#### Scenario: Here-string and eval
- **WHEN** `cadence git-safety` reads `bash <<< 'git reset --hard'` or `eval "git reset --hard"`
- **THEN** it blocks

### Requirement: Quoting follows bash
A guard SHALL remove quotes the way bash does before judging a word, so `".env"`, `'.env'`, `.e"n"v` and `$'--hard'` each read as the plain word. Text that bash passes to a command as one quoted argument, such as a commit message or an `echo` string, MUST be treated as data and MUST NOT be judged as a command.

#### Scenario: Quoted dangerous text in a message
- **WHEN** `cadence git-safety` reads `git commit -m "git reset --hard"`
- **THEN** it exits 0

#### Scenario: Quotes inside a word
- **WHEN** `cadence prevent-secret-leaks` reads `cat .e"n"v`
- **THEN** it blocks as a read of `.env`

### Requirement: Comments are not commands
An unquoted `#` that begins a word SHALL start a comment that runs to the end of its line, and a guard MUST NOT judge comment text. A `#` glued inside a word, or inside quotes, MUST NOT start a comment.

#### Scenario: Trailing comment
- **WHEN** `cadence git-safety` reads `echo hi # git reset --hard`
- **THEN** it exits 0

#### Scenario: Comment after a real command
- **WHEN** `cadence git-safety` reads `git reset --hard # (unbalanced`
- **THEN** it blocks

### Requirement: Heredoc bodies are data
A heredoc body handed to a command that is not a shell SHALL be read as data: a guard MUST NOT judge its lines as commands or brace-expand it. Body boundaries SHALL follow bash: quoted and escaped delimiters, `<<-`, line continuations, an unterminated body running to the end, and an indented or carriage-return terminator being body text. A script fed to a shell on stdin is outside the shared reading: a guard MAY leave it unjudged and MUST NOT refuse it for that.

#### Scenario: Data heredoc
- **WHEN** `cadence prevent-secret-leaks` reads `cat > notes.txt <<EOF` with a body line `cat .env`
- **THEN** it exits 0

#### Scenario: Command after a heredoc
- **WHEN** `cadence git-safety` reads a heredoc to `cat` followed on the next line, after the terminator, by `git reset --hard`
- **THEN** it blocks

#### Scenario: Script fed to a shell on stdin
- **WHEN** `cadence git-safety` reads `cat <<EOF | bash` with a body line `git reset --hard`
- **THEN** it exits 0, an accepted miss under ADR-0046

#### Scenario: Minified JSON body
- **WHEN** `cadence git-safety` reads `cat <<'EOF' > data.json` with a body of minified JSON containing many `{` groups
- **THEN** it exits 0

### Requirement: Escapes and continuations follow bash
A backslash-newline SHALL join two lines into one command before reading. An escaped operator character SHALL be read with bash's parity: in `\>|` an odd count of backslashes leaves a real pipe, and an even count leaves a literal backslash followed by a clobber redirect, which runs nothing.

#### Scenario: Continued line
- **WHEN** `cadence git-safety` reads `git \` followed on the next line by `reset --hard`
- **THEN** it blocks

#### Scenario: Odd backslashes leave a pipe
- **WHEN** `cadence prevent-secret-leaks` reads `echo hi \>| cat .env`
- **THEN** it blocks

#### Scenario: Even backslashes leave a redirect
- **WHEN** `cadence prevent-secret-leaks` reads `echo hi \\>| cat .env`
- **THEN** it exits 0

### Requirement: Brace expansion within bounds
A guard SHALL brace-expand an unquoted word the way bash does and judge each resulting word, as long as the expansion stays within a fixed work bound. A word whose expansion would exceed the bound SHALL be left unexpanded, and its unseen words MUST NOT be judged or refused by the shared reading. Ordinary expansions (`mkdir -p src/{a,b,c}`, `for i in {1..4096}`, `touch file{1..5000}.txt`) MUST be allowed by every guard that finds nothing dangerous in them.

#### Scenario: Expansion spells a dangerous command
- **WHEN** `cadence git-safety` reads `git reset --ha{r,}d`
- **THEN** it blocks

#### Scenario: Ordinary expansion
- **WHEN** `cadence git-safety`, `cadence prevent-secret-writes` or `guardrails guard-push-remote` reads `mkdir -p src/{a,b,c}`
- **THEN** it exits 0

### Requirement: Variables are not guessed
A guard SHALL substitute a variable only when the same command assigned it a literal value earlier in the same shell scope, and a `cd` or `git -C` target held in such a variable SHALL read as that literal. A guard MUST NOT guess the value of an unset or externally set variable, MUST NOT follow aliases, and MUST judge such a word only on what is written. An assignment made inside a subshell MUST NOT reach later segments of the parent.

#### Scenario: Literal assigned in the command
- **WHEN** `cadence git-safety` reads `R=--hard; git reset $R`
- **THEN** it blocks

#### Scenario: Unknown variable
- **WHEN** `cadence git-safety` reads `git reset $UNKNOWN`
- **THEN** it exits 0

#### Scenario: Alias
- **WHEN** `cadence git-safety` reads `alias g=git; g reset --hard`
- **THEN** it exits 0

### Requirement: Directory changes are tracked
A guard whose verdict depends on the repository a command runs in SHALL resolve each segment's working directory from the payload `cwd`, then any `cd` earlier in the same command (assuming it succeeds, including before `||`), then any `git -C` on the segment itself. A `cd` inside a subshell, substitution or `bash -c` script MUST NOT move the outer segments. A directory it cannot resolve MUST NOT be guessed; what the guard then does is in that guard's own spec.

#### Scenario: cd before a command
- **WHEN** `guardrails enforce-worktree` reads `cd /wt && git commit -m 'x'` with payload `cwd` `/cwd`
- **THEN** it judges the commit as landing in `/wt`, not `/cwd`

### Requirement: What cannot be read is allowed
When part of a command cannot be read, such as a brace word past the expansion bound, a `#` glued into a substitution, an unmodeled function header or a bash 5.3 `${ …; }` substitution, the guard SHALL judge the parts it did read and MUST allow the rest. The shared dispatch MUST NOT refuse a command for being hard to read, and a literal dangerous command beside an unreadable part MUST still block. Spellings only a deliberate attacker would type (ADR-0046 rule 1) SHALL NOT count as defects.

#### Scenario: Unreadable shape alone
- **WHEN** `cadence git-safety`, `cadence prevent-secret-writes` or `cadence prevent-secret-leaks` reads `echo ${ date; }` or `@(){ echo hi; }; @`
- **THEN** it exits 0

#### Scenario: Literal danger beside an unreadable shape
- **WHEN** `cadence prevent-secret-leaks` reads `echo ${ date; }; cat .env`
- **THEN** it blocks

#### Scenario: Attacker-only spelling
- **WHEN** a guard misses a command spelled with brace padding, non-bash blanks, an `eval` flood, positional-parameter indirection or `pus{h..h}`
- **THEN** the miss is out of scope and no fix is owed

### Requirement: Reading finishes in time
A guard's reading work SHALL be bounded so that large or repetitive commands (brace floods, nested heredoc floods, long `cd` chains) finish well inside the hook timeout. A dangerous command at the end of such a flood MUST still block before the deadline rather than fail open by timing out.

#### Scenario: Brace flood before a secret read
- **WHEN** `cadence prevent-secret-leaks` reads thousands of `echo {1..4096};` segments followed by `cat .env`
- **THEN** it blocks within the hook timeout

### Requirement: Words an exec wrapper runs stay whole
`flock FILE CMD…`, BSD `script FILE CMD…`, `watch -x`, `runuser -u USER CMD…`, the words after `env -S STRING`, and a tmux shell command given as several words exec their words as they are. A guard SHALL read each of those words whole, so a `-c` script behind them is one script and a quoted `;` is part of one argument. `watch` without `-x`, and a tmux shell command given as one word, run under `sh -c`, and a guard SHALL read that string as the shell splits it.

#### Scenario: Script behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l sh -c 'cat .env'`, `script -q /dev/null sh -c 'cat .env'`, `watch -x sh -c 'cat .env'`, `env -S 'sh -c' 'cat .env'` or `tmux new -d sh -c 'cat .env'`
- **THEN** it blocks

#### Scenario: Quoted semicolon behind an exec wrapper
- **WHEN** `cadence prevent-secret-leaks` reads `flock /tmp/l echo 'x; cat .env'`, `watch -x echo 'x; cat .env'` or `runuser -u app -- echo 'x; cat .env'`
- **THEN** it exits 0

#### Scenario: watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch echo 'x; cat .env'`
- **THEN** it blocks

#### Scenario: Shell script behind watch without -x
- **WHEN** `cadence prevent-secret-leaks` reads `watch sh -c 'cat .env'`, which runs `sh -c cat .env` and reads no file
- **THEN** it exits 0
