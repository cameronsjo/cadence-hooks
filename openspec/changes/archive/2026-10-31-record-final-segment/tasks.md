## 1. Fixes

- [x] 1.1 Record the segment's final bytes before rewriting it; match it as finished
- [x] 1.2 Move whole rows only; refuse a split row
- [x] 1.3 Forward paths finish through recovery's judgement
- [x] 1.4 No salvage commands for a non-UTF-8 directory

## 2. Tests and docs

- [x] 2.1 Kills inside recovery for both ops, torn rows, a forward late append; each break staged once
- [x] 2.2 `docs/configuration.md` and CHANGELOG
