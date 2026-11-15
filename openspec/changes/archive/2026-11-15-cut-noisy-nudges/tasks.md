## 1. Behavior

- [x] 1.1 Replace `warn-alias-parsing` and `warn-curl-alias` with a shared retired stub that allows silently, keeping their clap variants and registry rows
- [x] 1.2 Remove git-safety's unseen-execution nudge and the script-reading code only it used; flip its nudge tests to silent allows and keep a script beside a git command blocking or nudging
- [x] 1.3 Gate `warn-overshare` on a per-session, per-repo session marker, with a test that a second firing allows and a test that the key changes with repo and session

## 2. Docs

- [x] 2.1 Update docs/hooks.md rows and the overshare paragraph, and CLAUDE.md's pipeline example
- [x] 2.2 Stage the CHANGELOG.md bullets under [Unreleased]
