## RENAMED Requirements

- FROM: `### Requirement: Ask before a bare secret value is printed`
- TO: `### Requirement: A bare secret value is judged by where it goes`

## MODIFIED Requirements

### Requirement: A bare secret value is judged by where it goes
On PreToolUse for Bash, `guard-secret-dump` SHALL judge each producer whose output is a bare secret value with no name beside it (the producer table) by where the value goes, including producers inside substitutions, `sh -c`, and `eval`. It SHALL block (exit 2) when the value would be the command's own output: the producer's segment ends its pipeline and does not send stdout to a real file (`>&2`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/fd/*` still print), or the value is a substitution in an argument word of `echo` or `printf` (not `printf -v`, a redirect word or its target, or a process-substitution word) or is the whole first word, in a segment that prints, or a `sh -c`/`eval` script prints it to a segment that prints. The block MUST NOT be in the confirm tier. It SHALL return ask when the value goes to a consumer: a pipe into another program, a substitution used as an argument (of a command named by a variable too), an assignment, `printf -v` or an inline environment prefix, a here-string, or a process substitution. It MUST stay silent when the producer's pipeline sends stdout to a real file or ends in a hash (`shasum` family, `md5sum`, `b2sum`, `cksum`). A script holding a `{ … }` or `( … )` group, or a segment with more `)` than `(`, MUST NOT block; it keeps the ask. The block message SHALL begin `BLOCKED: guard-secret-dump`, name the producer label and never the command text, and name consumer forms in one sentence: a pipe into the program that needs the value, the clipboard, and the tool's reference form. The guard has no escape variable of its own; it is not protected, so `CADENCE_DISABLE=guard-secret-dump` and `CADENCE_BYPASS=1` switch it off.

#### Scenario: Bare-value producers
- **WHEN** a Bash command runs `op read op://v/i/f`, `op read op://v/i/f >&2`, `security find-generic-password -s x -w`, `op item get x --reveal`, or `cd /repo && op read op://v/i/f`
- **THEN** the hook exits 2 with `BLOCKED: guard-secret-dump` on stderr

#### Scenario: Printed through an argument printer or a script
- **WHEN** a Bash command runs `echo "$(op read op://v/i/f)"`, `printf '%s\n' "$(pass show x)"`, `"$(op read op://v/i/f)"`, `bash -c 'op read op://v/i/f'`, or `eval 'pass show x'`
- **THEN** the hook blocks

#### Scenario: Value handed to a consumer
- **WHEN** a Bash command runs `op read op://v/i/t | gh auth login --with-token`, `security find-generic-password -s x -w | pbcopy`, `GH_TOKEN="$(op read op://v/i/t)" gh api user`, `curl -H "Authorization: Bearer $(op read op://v/i/f)" https://x`, `docker login --password-stdin <<< "$(op read op://v/i/f)"`, or `echo "$(op read op://v/i/f)" | docker login --password-stdin`
- **THEN** the hook returns ask with a reason containing `guard-secret-dump:`

#### Scenario: Grouped script
- **WHEN** a Bash command runs `{ op read op://v/i/f; } > token.txt`
- **THEN** the hook returns ask

#### Scenario: Hashed or saved value
- **WHEN** a Bash command runs `kubectl get secret s -o jsonpath='{.data.k}' | base64 -d | shasum` or `op read op://v/i/f > token.txt`
- **THEN** the hook allows silently

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash command runs `kubectl get pods` or `op run -- gh api user`
- **THEN** the hook allows silently

## ADDED Requirements

### Requirement: The producer table
`guard-secret-dump` SHALL recognize a bare-value producer by one row per executable, after command runners are peeled, and MUST NOT judge a program outside the table a producer. Two builtins, `echo` and `printf` (not `printf -v`), SHALL be the only commands treated as printing their arguments.

#### Scenario: 1Password and Keychain rows
- **WHEN** a Bash command runs `op read <ref>` (unless `-o`/`--out-file` names a real file), `op item get <item> --reveal`, or `security find-generic-password` / `find-internet-password` with a short-flag cluster holding `w`
- **THEN** each is a producer

#### Scenario: Cluster and cloud rows
- **WHEN** a Bash command runs `kubectl get secret` with `-o jsonpath|go-template|template|custom-columns` or `--template` (or `-o json|yaml` piped into `jq`/`yq`), `vault read|kv get -field`, `aws secretsmanager get-secret-value`, `aws ecr get-login-password`, `aws ssm get-parameter --with-decryption`, `aws configure get <secret key>`, `az keyvault secret show`, `az account get-access-token`, `gcloud secrets versions access`, or `gcloud auth print-access-token`
- **THEN** each is a producer

#### Scenario: Password-manager rows
- **WHEN** a Bash command runs `pass <name>` or `pass show <name>`, `gopass show`, `bw get password`, `lpass show --password`, `doppler secrets get --plain`, or `heroku auth:token`
- **THEN** each is a producer

#### Scenario: Not a producer
- **WHEN** a Bash command runs `op item get db --fields username`, `security find-generic-password -s x`, `vault kv get secret/x`, or `aws configure get region`
- **THEN** the hook allows silently

### Requirement: The limit of the value rule
`guard-secret-dump` SHALL judge only what one command's text shows. A consumer that itself prints the value (`… | cat`, `cat <<< "$(op read …)"`), a later command that prints a variable (`X=$(op read …); echo $X`), and a print inside a script file are outside it, and MUST keep the ask or pass rather than block.

#### Scenario: Later print of a variable
- **WHEN** a Bash command runs `X=$(security find-generic-password -s x -w); echo $X`
- **THEN** the hook returns ask
