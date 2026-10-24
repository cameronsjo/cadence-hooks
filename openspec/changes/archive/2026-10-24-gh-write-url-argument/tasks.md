## 1. Guard

- [x] 1.1 Read a PR or issue URL argument on the `gh pr` and `gh issue` write verbs that take one, skipping each verb's value-taking flags as gh defines them
- [x] 1.2 Judge that repo on the URL's host before `-R`, `GH_REPO` and the checkout
- [x] 1.3 Block an unowned one with a fix that names no target
- [x] 1.4 Pin the URL reader, the argument scan and the verdicts from an owned checkout, an unowned one and `/tmp`
- [x] 1.5 Under `gh issue transfer`, judge the URL as well as the `-R` or checkout

## 2. Docs

- [x] 2.1 Add the URL argument to the resolution order in `docs/configuration.md`
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
