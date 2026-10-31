## 1. Commit counter

- [x] 1.1 `session_commits` module: start, record, count, last message id; append-only count, `0600`, no symlinks
- [x] 1.2 `log-session-start` starts the counter; `log-commit` reads and updates it; `log-session` reads it before clearing state
- [x] 1.3 Fall back to the bounded ledger read when a session has no counter

## 2. Bypass key

- [x] 2.1 Encode claim-name parts injectively, add the tool, cap the name length with a hash

## 3. Tests

- [x] 3.1 Concurrent commits lose no increment; a symlinked counter is not followed; the counter wins over the ledger at SessionEnd
- [x] 3.2 Stage the counter ignored, the tool dropped, and the lossy encoding once; each fails its test
