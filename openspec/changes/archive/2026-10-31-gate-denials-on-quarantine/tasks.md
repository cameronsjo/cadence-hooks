## 1. Fixes

- [x] 1.1 Hold `denials` archiving until a quarantine record exists; record every real quarantine run
- [x] 1.2 Salvage commands in the damaged-archive messages, verified on a truncated archive
- [x] 1.3 `cat` failures: unreadable `archive/`, named read errors, unlocked fallback
- [x] 1.4 Tie a manifest's op to its segment and archive

## 2. Tests and docs

- [x] 2.1 Tests for each fix, each break staged once
- [x] 2.2 `docs/configuration.md`, help text and CHANGELOG
