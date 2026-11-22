## Why

The operator's user settings carry an ask-type permission rule for the container-removal command. Every `docker rm` stops at a permission dialog that auto mode does not answer, and a session sat blocked on one overnight with nobody at the keyboard. The operator works increasingly from a phone and asked for a guard that assumes a cooperative model and asks "are you sure?" instead (cameronsjo/cadence-hooks#1661, its "Candidates for the tier" item on container removal). The confirm tier shipped in 0.135.0 (cameronsjo/cadence-hooks#1658) fits: the first attempt blocks with a message, and an identical retry in the same session passes once.

## What Changes

- ADD a new guard, `guardrails guard-container-rm`, on PreToolUse for Bash. It judges a segment that removes a container (`docker rm`, `docker container rm`, `docker container remove`), with or without `-f`/`--force`, through the wrappers the shell parsing already peels. It is confirm tier: the first attempt blocks naming what it removes, and an identical retry passes once.
- The confirm key is the whole command, normalized only for spaces and tabs, beside the removals read, as `guard-op-vault-scan` and `guard-held-close` key theirs. No repository is part of the key: a container is not in a repository, and those two guards key no repository either.
- Everything else Docker does passes untouched: `stop`, `restart`, `kill`, `run --rm`, `image rm`, `rmi`, `compose down`/`rm`, `system prune`, volume and network removal.
- A command the guard cannot read allows (ADR-0046 rule 3). The stated limit: the guard reads the command text, so a removal sent through `eval`, a script file, the Docker API over a socket, or `ssh host 'docker rm …'` is not seen.
- `scripts/confirm-tier-compare.py` scores the new guard (absent on the base binary, so its baseline is allow everywhere) and fails unless the only first-attempt moves are the listed container removals.

## Capabilities

### New Capabilities

- `container-removal`: the confirm-tier guard on Bash commands that remove a Docker container.

### Modified Capabilities

None. The `hook-protocol` Confirm tier requirement names no guards, and this guard follows it unchanged.

## Impact

- `crates/guardrails/src/guard_container_rm.rs` (new), `crates/guardrails/src/lib.rs`, `crates/guardrails/src/guard_op_vault_scan.rs` (its exec-wrapper peel becomes crate-visible for reuse).
- `src/main.rs`, `src/registry.rs`, `tests/hook_registration_audit.rs` (a `PENDING_WIRING_HOOKS` entry until the cadence plugin wires it), `tests/confirm_tier.rs`.
- `scripts/confirm-tier-compare.py`, `scripts/testdata/confirm-tier-commands.txt`, `scripts/testdata/container-rm-expected-blocks.txt` (new).
- `docs/hooks.md`, `docs/configuration.md`, `CHANGELOG.md`.
- Outside this repo, not changed here: the `cadence-guardrails` plugin's `hooks.json` needs a PreToolUse Bash entry for the subcommand before it runs in any session, and the operator removes the settings ask rule only after a release carries this guard.
