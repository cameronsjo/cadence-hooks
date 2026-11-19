## 1. Mechanism

- [x] 1.1 `core::confirm`: key digest, pending/consumed marker keyed by `tool_use_id`, ten-minute window, fail directions, armed and unavailable lines
- [x] 1.2 `HookInput::tool_use_id` (lenient) and `BypassKind::Confirmed` (`confirmed`)

## 2. Guards

- [x] 2.1 `enforce-worktree`: primary-checkout block through the tier; a pass arms the dismiss snooze through one shared writer
- [x] 2.2 `guard-op-vault-scan`: keyed by the scans and `--vault`
- [x] 2.3 `guard-held-close`: keyed by the held entries hit
- [x] 2.4 `guard-browser-device`: left on its own marker (per-session handshake, not per action)
- [x] 2.5 Phone line on the hard blocks whose escape needs a keyboard

## 3. Tests

- [x] 3.1 Per moved guard: first blocks, second passes once, third blocks (enforce-worktree: rides the snooze), another session / agent / target blocks, no session id blocks, expired blocks
- [x] 3.2 Core: sibling processes of one call, junk / symlink / other-key markers, shared marker dir, failed writes
- [x] 3.3 Each staged red once

## 4. Docs

- [x] 4.1 `docs/hooks.md`, `docs/configuration.md`, CHANGELOG
- [x] 4.2 Archive this change in the PR
