## Why

`redact-external-content` built the identity term-source path from the `HOME` environment variable. A repo's `.claude/settings.json` `env` block reaches every hook process and can set `HOME`, so a repo that pointed `HOME` at a directory with no term source made the tier load zero terms and allow every post with no identity scan (cameronsjo/cadence-hooks#1617). The same function already refused `CADENCE_REDACTION_TERMS` and `XDG_CONFIG_HOME` for this reason; `HOME` was the variable left in. The Write/Edit exemption in the same guard already reads the home directory from the account database (#1429).

## What Changes

- The term source is `<account home>/.config/cadence/redaction.toml`, where the account home comes from the user database (`getpwuid_r`), never from `HOME`. A failed lookup reads as an absent file.
- A term source that exists but cannot be read (permissions on it or its directory, a dangling link, not a regular file, over the size cap) now blocks a post or commit message, with a message naming the path, how to fix it, and that removing the file runs the machine without the tier on purpose. The file being there means the machine is set up to scan, so an unreadable one is a disarm.
- Kept: an absent file, a malformed one, and one with zero terms leave the tier inert, as before, so a machine with no term source is not blocked. Write/Edit scanning is unchanged on an unreadable source: the egress boundary is the post (ADR-0003).
- `redact-scan --status` and `--validate-config` name the account-home path.

Surfaces: `redact-external-content` (PreToolUse, Bash) exit code 0 → 2 for a post when the term source is unreadable; new block text. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: "Identity tier blocks work-identifiable terms" reads the account home instead of `$HOME`. "Identity tier fails open on its own failure" no longer covers an unreadable term source; the new "Unreadable term source blocks posts" requirement does.

## Impact

`crates/cadence/src/redact_external_content.rs`, `crates/cadence/src/redact_external_content/identity.rs`, `tests/terms_source_home.rs`, `CHANGELOG.md`.
