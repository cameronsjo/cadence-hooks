# Contributing

Thank you for your interest in claude-hooks. This project is currently maintained as a personal tool, but contributions are welcome.

## Getting Started

```bash
git clone https://github.com/cameronsjo/claude-hooks.git
cd claude-hooks
make ci    # Run fmt check, clippy, and tests
```

Requires Rust 2024 edition (1.85+).

## Development Workflow

1. Create a feature branch from `main`
2. Write tests first — each check should have both happy-path and edge-case coverage
3. Run `make ci` before pushing
4. Open a PR against `main`

## Code Style

- **Conventional Commits**: `type(scope): description` (e.g., `fix(cadence): scope safe-template check to target`)
- **cargo fmt** and **cargo clippy** must pass with zero warnings
- Tests are in-file `#[cfg(test)] mod tests` blocks, not separate files
- Each check implements the `Check` trait from `claude-hooks-core`

## Adding a New Hook

1. Add a module in the appropriate crate (`crates/cadence/`, `crates/guardrails/`, etc.)
2. Implement the `Check` trait
3. Export the module from the crate's `lib.rs`
4. Add a subcommand variant in `src/main.rs`
5. Write tests covering: allow, warn, block, edge cases, and bypass scenarios

## Testing Conventions

- Test names describe the scenario: `bash_cat_example_redirect_to_env_blocked`
- Document known limitations as explicit test cases with comments
- Use helper functions (`make_input`, `make_bash_input`) for test setup
- Group tests: happy path first, then unhappy path / edge cases

## License

By contributing, you agree that your contributions will be licensed under the [BSL-1.1](LICENSE).
