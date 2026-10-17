# Opt-in timing budgets (#1366)

Codex makes the selected flood-test wall-clock checks opt-in through
`CADENCE_TIMING_TESTS=1`. Default tests retain every semantic assertion and both
input sizes used by the scaling helper. Existing time and scaling limits stay
unchanged. Changes are limited to tests, test helpers, CI, and documentation.

- [x] Merge `origin/main` into `fix/macos-test-flakes`.
- [x] Demonstrate deterministic failures for the missing opt-in behavior.
- [x] Gate the selected flood budgets and shared scaling helper consistently.
- [x] Add release, single-threaded budget checks to existing CI runners.
- [x] Document the opt-in and add an Unreleased changelog entry.
- [x] Remove the gates temporarily, prove red, and restore the fix.
- [x] Run formatting and CI-equivalent clippy.
- [x] Compare every other observed failure on a clean main checkout and this tree.
- [x] Remove the temporary baseline worktree after comparison.
- [x] Review the net diff and verify production code is unchanged.

The selected tests are the wall-clock flood assertions in `core::push`, the bare
hook heredoc integration test, the ship-judging flood, the posted-stdin flood, and
all callers of `test_builders::assert_scales_linearly`. Production guard logic is
outside this task.

## Validation

Ten deterministic helper tests passed with and without the opt-in. The staged
break failed three tests before the fixed source was restored. Formatting,
CI-equivalent clippy, and workflow validation passed. The local full debug suite
was interrupted after unrelated failures; it is not recorded as a full pass.

Clean-main comparisons used `e8a618aa54fd43e34c17b792fb4a17be84429f9a` in
`/tmp/cos-1366-base`, with matching serial test filters and environment on this
branch. Seven cadence timing tests and the wired heredoc deadline test failed
on both trees; the remaining secret-dump timing test passed on both. The local
registration audit also failed on both because it reads live Claude settings.
No branch-only failure was found. The orchestrator owns the separate registration
issue. The draft PR lists each reproduced failure by name.

CI runs the full normal workspace suite and the full release workspace suite
with `CADENCE_TIMING_TESTS=1` and one test thread on its existing Linux and Windows
runners. Git, the draft PR, and the requested final report record delivery and
hosted-check results. Codex will leave the PR open and draft.

Deviation: the first PR CI run failed in the release step, because five tests
that arm the debug-only `CADENCE_TEST_PANIC` trigger cannot pass under
`--release`. They now carry `#[cfg_attr(not(debug_assertions), ignore)]`; the
debug suite still runs them.
