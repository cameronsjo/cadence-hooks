# Test Audit Report -- cadence-hooks

**Scope:** full (all crates)
**Date:** 2026-04-04
**Tool coverage:** Manual analysis (cargo-llvm-cov not installed)

## Summary

- Source files: 33 | Test files: 28 inline + 2 integration | Ratio: 1.1:1
- Overall coverage: N/A (cargo-llvm-cov not installed)
- Test functions: 894
- Untested functions: 8 (high risk: 2, medium: 3, low: 1, skip: 2)
- Quality issues: 5 (P0: 0, P1: 1, P2: 2, P3: 2)

## Coverage Gaps (by risk)

### High Risk Untested

| Function | File | Classification | Why It Matters |
|----------|------|---------------|----------------|
| `NudgeUpgradeAfterPush::run()` repo detection | `crates/guardrails/src/nudge_upgrade_after_push.rs` | I/O boundary | Only 6 tests; none verify cameronsjo/cadence-hooks repo detection, URL normalization (.git suffix), or bare `git push` branch resolution. Core differentiating logic untested. |
| `MarkdownLint::run()` linting path | `crates/cadence/src/markdown_lint.rs` | I/O boundary | Guard logic has 8 tests but markdownlint CLI invocation, temp file creation, and output parsing completely untested. Silent failure if tool missing. |

### Medium Risk Untested

| Function | File | Classification | Why It Matters |
|----------|------|---------------|----------------|
| `CheckIdleReturn::run()` file I/O | `crates/guardrails/src/check_idle_return.rs` | I/O boundary | Marker file creation/reading untested. `idle_outcome()` pure logic solid (11 tests). |
| `WarnMainBranch::run()` session scoping | `crates/guardrails/src/warn_main_branch.rs` | State machine | Code comment documents bug: uses PID instead of PPID. Marker-based one-warning-per-session logic untested. |
| `WarnDocsUpdate` git integration | `crates/cadence/src/warn_docs_update.rs` | I/O boundary | `diff_against_base()` and `find_base_branch()` git commands untested. `analyze_diff()` pure function has 8 tests. |

### Low Risk Untested

| Function | File | Classification | Why It Matters |
|----------|------|---------------|----------------|
| `WarnUntrackedFiles::run()` trigger path | `crates/guardrails/src/warn_untracked.rs` | I/O boundary | `filter_untracked()` has 10 tests but actual `git commit` trigger path untested. |

### Not Worth Unit Testing (skipped)

| Function | File | Pattern | Rationale |
|----------|------|---------|-----------|
| `main()` + clap dispatch | `src/main.rs` | Entry point / framework glue | Covered by integration tests + registration audit |
| `marker_path()`, `now_secs()` | various | Thin wrappers | Single-expression delegation. Bugs caught by compiler. |

## Quality Issues

### P0 -- Likely Catching Zero Bugs

None.

### P1 -- Masking Real Issues

**Unwrap without guard assertion**
- Files: `check_idle_return.rs` (7 sites), `warn_main_branch.rs` (3 sites)
- Pattern: `.message.as_deref().unwrap()` after outcome assertion but without asserting message is `Some`
- Impact: Panics with unhelpful backtrace instead of failing with descriptive message
- Fix: Add `assert!(result.message.is_some(), "expected nudge message")` before `.unwrap()`

### P2 -- Test Debt

**Existence-only + unwrap redundancy**
- File: `guard_gh_write.rs` (lines 333, 340, 465, 641)
- Pattern: `assert!(caps.is_some())` immediately followed by `caps.unwrap()`
- Fix: Collapse into single assertion or use `assert!(x.is_some_and(...))`

**Inconclusive test assertion**
- File: `nudge_upgrade_after_push.rs` (line 121-127)
- Pattern: Test comment says "Could be true or false depending on test env -- just verify no panic"
- Impact: Not a real assertion. Test passes regardless of behavior.

### P3 -- Deeper Analysis

**Private function testing**
- File: `validate_skill_frontmatter.rs` (lines 166-237)
- Pattern: Tests private helpers directly (`extract_frontmatter`, `classify_path`, `skill_dir_name`)
- Mitigated: Integration tests for `Check::run()` exist at line 255+

**Systematic I/O mocking gap**
- Pattern: No test doubles for `git_command()` or filesystem operations across the codebase
- Impact: Pure logic is extracted and tested, but I/O error handling is unverified
- Note: This is a deliberate architectural choice (test logic, not shell-outs). A `GitOps` trait would enable boundary testing without real repos.

## Strengths

- **894 test functions** across 30 test modules
- **Pure function isolation**: All classifiable pure functions have direct unit tests
- **Edge case hardening**: Secret patterns have 150+ tests including bypass vectors
- **Integration audit**: `hook_registration_audit.rs` prevents drift between binary, plugins, and event types (7 tests)
- **Version mismatch tests**: `version_mismatch.rs` validates fail-open on unknown subcommands (9 tests)
- **Event type cross-reference**: New test verifies HookEvent in main.rs matches hooks.json registration

## Recommended Next Steps

1. **Install cargo-llvm-cov** for quantitative coverage: `cargo install cargo-llvm-cov`
2. **Run `write-tests`** for 2 high-risk gaps (nudge_upgrade_after_push repo detection, markdown_lint integration)
3. **Fix P1 unwrap patterns**: Add `.is_some()` guards in check_idle_return and warn_main_branch tests
4. **Consider `make-testable`** for extracting git command execution behind a trait
5. **Extract shared test builders** (`make_bash`, `make_write_input`) to reduce duplication across 5+ modules
