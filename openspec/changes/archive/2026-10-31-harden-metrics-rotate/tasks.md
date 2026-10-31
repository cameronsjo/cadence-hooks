## 1. Fixes

- [x] 1.1 Refuse to append to an archive that does not decode to the end
- [x] 1.2 Shared lock for `metrics cat`
- [x] 1.3 Twice-the-cap per-segment bound for the SessionStart run
- [x] 1.4 Refuse to run off Unix
- [x] 1.5 Retry the run lock past a forked child's brief hold
- [x] 1.6 Validate the manifest's archive name; cap decoding in recovery
- [x] 1.7 Parse `ts` for `--since`

## 2. Tests and docs

- [x] 2.1 Tests for each fix; stage the damaged-archive and shared-lock breaks once
- [x] 2.2 Update `docs/configuration.md` and the CHANGELOG bullets
