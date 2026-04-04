# Test Audit Report — cadence-hooks

**Scope:** full (all crates)
**Date:** 2026-04-03
**Tool coverage:** Manual analysis (cargo-llvm-cov not installed)

## Summary

- Source files: 32 | Test files: 27 inline + 2 integration | Ratio: 1.1:1
- Overall coverage: N/A (cargo-llvm-cov not installed)
- Untested functions: 0 high risk, 0 medium, 0 low, 5 skip
- Quality issues: 0 P0, 0 P1, 1 P2, 2 P3

## Coverage Gaps (by risk)

### High Risk Untested

None.

### Medium Risk Untested

None.

### Low Risk Untested

None. All public functions are tested either directly (pure functions) or indirectly (via `Check::run()` implementations).

### Not Worth Unit Testing (skipped)

| Function | File | Pattern | Rationale |
|----------|------|---------|-----------|
| `pub mod` declarations | `crates/*/src/lib.rs` (4 files) | Re-export glue | Zero logic, compiler catches errors |
| `main()` + clap dispatch | `src/main.rs` | Entry point / framework glue | Covered by integration tests (`version_mismatch.rs`, `hook_registration_audit.rs`) |

### Indirectly Tested Only

| Function | File | Tested Via |
|----------|------|-----------|
| `analyze_gh_loops()` | `crates/core/src/loop_analysis.rs` | `guard_gh_write` tests |
| `analyze_push_chain()` | `crates/core/src/loop_analysis.rs` | `guard_push_remote` tests |
| `analyze_push_loops()` | `crates/core/src/loop_analysis.rs` | `guard_push_remote` tests |

These AST-parsing functions are tested through the guards that consume them. Direct unit tests would be valuable but not urgent — the fallback behavior (ParseFailed -> regex) is tested.

## Quality Issues

### P0 — Likely Catching Zero Bugs

None.

### P1 — Masking Real Issues

None.

### P2 — Test Debt

**1. Bare assertions without context messages**
- Scope: Widespread (most test modules)
- Example: `assert_eq!(result.outcome, Outcome::Allow)` without trailing message
- Impact: Low in Rust (test function names are descriptive), but failure output could be clearer
- Action: Style improvement, not functional

### P3 — Deeper Issues

**1. Duplicate `make_bash()` helper across 5+ modules**
- Files: `warn_untracked.rs`, `guard_git_init.rs`, `guard_push_remote.rs`, `prevent_secret_leaks.rs`, `prevent_secret_writes.rs`, and others
- Each module defines its own `make_bash(cmd: &str) -> HookInput` with identical logic
- Fix: Extract to a shared `#[cfg(test)]` module in `cadence-hooks-core` or a `test-utils` crate

**2. Inconsistent mock input construction**
- Three patterns: inline `HookInput { ... }`, dedicated `make_bash()`, and `make_check_input()`
- Not a correctness issue but increases cognitive load when reading tests across modules

## Strengths

- **850+ assertions** across 27 test modules — comprehensive
- **Pure function isolation**: All classifiable pure functions (`filter_untracked`, `check_terminology`, `parse_env_list`, `is_allowed`, `strip_quotes`, `repo_from_url`, etc.) have direct unit tests
- **Edge case hardening**: Secret patterns have 150+ tests including bypass vectors (tee, cp, null bytes). Shell parsing tests adversarial inputs (smart quotes, relative paths)
- **Guard clause testing**: Every `Check::run()` implementation tests early-return paths
- **Integration tests**: `version_mismatch.rs` (9 tests) validates fail-open behavior. `hook_registration_audit.rs` (6 tests) prevents drift between binary and plugin registration

## Recommended Next Steps

- **Install cargo-llvm-cov** for quantitative per-function coverage data: `cargo install cargo-llvm-cov`
- **Extract shared test builders** (`make_bash`, `make_write_input`) to reduce duplication across 5+ modules — use `write-tests` or do manually
- **Add direct tests for `loop_analysis` functions** — currently tested only through consuming guards
- **No urgent gaps** — test suite is healthy and comprehensive
