## Why

`log-session` read the commits ledger at every `SessionEnd` to count the session's commits, and `log-commit` read it at every commit to find the previous `lastMessageId` (cameronsjo/cadence-hooks#1589). Most sessions never commit, so most of those reads found nothing. Separately, review of #1598 found the bypass dedupe key lossy: `my.app` and `my_app` shared a claim, and the tool was not part of the key.

## What Changes

- Per-session commit state lives at `<state>/commits/<session>/`: `count` gets one byte appended per commit, so concurrent commits lose no increment and the count is the file length. `last` holds the newest `lastMessageId`. Both are `0600` and never opened through a symlink.
- `log-session-start` creates an empty `count`, so a session that never commits reads zero with no ledger read. `log-commit` takes the previous `lastMessageId` from `last` and updates both after its row lands. `log-session` reads `count` before clearing the directory at `SessionEnd`.
- A session with no `count`, one that started before this change, falls back to the existing bounded ledger read in both loggers.
- The bypass claim name encodes each part injectively (letters and digits kept, every other byte `_` plus two hex digits), joins the parts with `-`, adds the tool, and above 200 bytes keeps a 160-byte prefix plus a 64-bit FNV-1a hash.

## Impact

- Code: `crates/metrics/src/session_commits.rs` (new), `log_commit.rs`, `log_session.rs`, `log_session_start.rs`, `log_bypass.rs`.
- Existing claims written by the previous name scheme are ignored, so a session that straddles the upgrade may log one more `CADENCE_ALLOW_MAIN` row.
