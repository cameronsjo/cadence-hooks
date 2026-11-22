# container-removal Specification

## Purpose
A guard on Bash commands that remove a Docker container: `cadence-hooks guardrails guard-container-rm` blocks the first attempt at a `docker rm` or `docker container rm`, naming what it removes, and passes the identical command again once (the confirm tier). It replaces a settings ask rule, whose dialog auto mode never answers (cameronsjo/cadence-hooks#1661).

## Requirements

### Requirement: Container removal asks first
On PreToolUse for Bash, `guard-container-rm` SHALL block a command holding a segment that removes a Docker container, and SHALL be in the confirm tier. A segment removes a container when, after the shared runner peel and the `perl -e '…exec @ARGV'` peel, its command word is `docker` and the first word after Docker's global options is `rm`, or is `container` followed by `rm` or `remove`. A removal segment carrying `--help` or `-h` removes nothing and MUST be allowed.

#### Scenario: A plain removal
- **WHEN** a Bash command is `docker rm web`
- **THEN** the guard blocks with a message naming `web` and the `Are you sure?` line

#### Scenario: Through a wrapper
- **WHEN** a Bash command is `sudo docker rm web`, `bash -c 'docker rm web'`, `perl -e 'alarm 60; exec @ARGV' docker rm web`, or `docker ps -q | xargs docker rm`
- **THEN** the guard blocks

#### Scenario: Other Docker commands pass
- **WHEN** a Bash command is `docker ps -a`, `docker logs web`, `docker run --rm alpine true`, `docker stop web`, `docker restart web`, `docker kill web`, `docker image rm alpine`, `docker rmi alpine`, `docker compose down`, `docker compose rm`, `docker system prune`, `docker volume rm v`, or `docker network rm n`
- **THEN** the guard allows without a message

#### Scenario: Prose about a removal
- **WHEN** a Bash command is `echo 'docker rm web'` or `git commit -m 'docs: docker rm web'`
- **THEN** the guard allows

#### Scenario: Help
- **WHEN** a Bash command is `docker rm --help` or `docker container rm -h`
- **THEN** the guard allows

### Requirement: Docker global options
Before reading the subcommand, `guard-container-rm` SHALL skip Docker's global options. An option that takes a value (`--config`, `-c`/`--context`, `-H`/`--host`, `-l`/`--log-level`, `--tlscacert`, `--tlscert`, `--tlskey`) MUST be skipped with its value when the value is a separate word; any other option word is skipped alone.

#### Scenario: Global options before the subcommand
- **WHEN** a Bash command is `docker --context prod rm web`, `docker -H tcp://h:2375 rm web`, or `docker --debug rm web`
- **THEN** the guard blocks

#### Scenario: A global option value that spells a subcommand
- **WHEN** a Bash command is `docker --context rm ps`
- **THEN** the guard allows: `rm` is the context's name and `ps` the subcommand

### Requirement: Container removal message
The block message SHALL name the containers the segment removes (its non-option operands, redirections dropped), say when names come only at run time (`xargs docker rm`, `docker rm $(docker ps -aq)`, a variable), without reading a substitution's own words as names or flags, and say when `-f`/`--force` or `-v`/`--volumes` is present.

#### Scenario: Forced removal through the management command
- **WHEN** a Bash command is `docker container rm -f web db`
- **THEN** the guard blocks, naming `web` and `db` and saying `-f` stops a running container first

### Requirement: Confirmed container removal
`guard-container-rm` SHALL key its confirmation on the whole command (every segment, spaces and tabs collapsed, ends trimmed) beside the removals it read, as `guard-op-vault-scan` and `guard-held-close` key theirs. No repository or working directory is part of the key. A retry of the same command in the same session and agent within ten minutes SHALL pass once with a `confirmed` bypass row; any other difference MUST NOT pair.

#### Scenario: The same command again
- **WHEN** `docker rm -f web` blocks in session S1 and S1 then runs `docker rm -f web` in a new tool call
- **THEN** the second attempt is allowed with a `confirmed` bypass row, and a third attempt blocks again

#### Scenario: A changed command
- **WHEN** `docker rm web` blocks in session S1 and S1 then runs `docker rm db`, `docker rm -f web`, or `docker --context prod rm web`
- **THEN** the second attempt blocks with the `Are you sure?` line

#### Scenario: Expired
- **WHEN** `docker rm web` blocked more than ten minutes before the retry
- **THEN** the retry blocks with the `Are you sure?` line

#### Scenario: No session id
- **WHEN** a payload with no `session_id` runs `docker rm web`, and the same payload is sent again
- **THEN** both attempts block, ending with `A second attempt will be blocked too:`

### Requirement: Container removal fail direction
`guard-container-rm` SHALL allow a command it cannot read, such as a command word behind a variable it cannot resolve. It is not a protected or security-critical guard, so `CADENCE_DISABLE` naming it switches it off.

#### Scenario: A variable command word
- **WHEN** a Bash command is `$DOCKER rm web` with `DOCKER` set outside the command
- **THEN** the guard allows

#### Scenario: Disabled by name
- **WHEN** `CADENCE_DISABLE` names `guard-container-rm`
- **THEN** `docker rm web` is allowed

### Requirement: Container removal limit
The guard reads command text only, so a removal the text does not spell out is not seen: one inside a script file, a request to the Docker API over its socket, or a command sent to another host. The threat model is a cooperative model making an honest mistake (cadence-ecosystem ADR-0046), so these MUST NOT be chased.

#### Scenario: A remote removal over ssh
- **WHEN** a Bash command is `ssh host 'docker rm web'`
- **THEN** the guard allows: the remote command is one quoted argument to `ssh`, not a segment the guard reads

#### Scenario: A script file
- **WHEN** a Bash command is `bash ./cleanup.sh` and the script removes containers
- **THEN** the guard allows
