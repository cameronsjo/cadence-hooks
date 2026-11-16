## 1. Behavior

- [x] 1.1 Rewrite `guard-push-remote` as a nudge that judges only pushes the walk read exactly, and delete the chain, loop, literal-loop, unparsed and directory-check arms
- [x] 1.2 Remove the guard from `SECURITY_CRITICAL_HOOKS` and `PROTECTED_GUARDS`
- [x] 1.3 Pin the nudge, the silent shapes, the probe cap and the probe timeout in the guard's tests and `tests/deadline_failopen.rs`; move the loop-parser containment tests in `tests/failopen_telemetry.rs` to `guard-gh-write`

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
- [x] 2.2 Update the guard's row in docs/hooks.md, the block example in docs/testing.md, and the `developing-guards` skill examples
