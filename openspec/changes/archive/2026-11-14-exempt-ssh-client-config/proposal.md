## Why

Since cameronsjo/cadence-hooks#1431, `redact-external-content` exempts a Write or Edit from its identity scan only in fixed local locations: a dotfile directly in the home directory, `~/.config`, `~/.local`, `~/.cache`, or a temp dir. `~/.ssh/config`, `~/.aws/config` and `~/.kube/config` are none of those, and their names have no extension, so they also read as prose drafts. An edit that adds a work host to any of them blocks.

The operator ruled on these three: `~/.ssh/config` is local client config and should be exempt; the AWS and Kubernetes configs stay scanned.

## What Changes

- `~/.ssh/config`, as that exact resolved path under the account home (from the user database, never `HOME`), is a fixed local location and is read as config rather than a prose draft. Every other check still applies: outside any repo, sync tree or remote mount, one hard link, every symlink resolved.
- Not exempt: any other path under `~/.ssh` (`~/.ssh/config.d/…`, `~/.ssh/known_hosts`, `~/.ssh/config.toml`), a path with a `..` component (`~/.ssh/../.aws/config`), a `~/.ssh/config` that is a symlink resolving anywhere else, and `~/.aws/config` and `~/.kube/config`.

Surfaces: `redact-external-content` (PreToolUse, Write/Edit) exit code 2 → 0 for a term introduced into `~/.ssh/config`. No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: "Identity scan of file writes" adds `~/.ssh/config` to the proven-local locations, and the new "SSH client config is the one exempt file under ~/.ssh" requirement limits it to that exact file.

## Impact

`crates/cadence/src/redact_external_content.rs`, `crates/cadence/src/redact_external_content/context.rs`, `CHANGELOG.md`.
