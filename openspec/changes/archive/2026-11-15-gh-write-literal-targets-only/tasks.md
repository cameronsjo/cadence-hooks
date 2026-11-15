## 1. Guard

- [x] 1.1 Allow every write whose target the guard cannot read, and keep the literal unowned, URL and fork blocks
- [x] 1.2 Allow `gh api` writes outside `repos/<owner>/<repo>/…` and drop the GraphQL classifier
- [x] 1.3 Drop the loop gate, the unread-loop nudge and `CADENCE_GH_STRICT_LOOPS`
- [x] 1.4 Drop the `GH_HOST`/`GH_REPO` export tracking, the brace, size, nesting and directory-count refusals
- [x] 1.5 Delete the tests that pinned only those shapes; flip table rows to allow; keep every literal-unowned test

## 2. Docs

- [x] 2.1 Rewrite the gh-write resolution section of `docs/configuration.md` and drop the `CADENCE_GH_STRICT_LOOPS` row
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
