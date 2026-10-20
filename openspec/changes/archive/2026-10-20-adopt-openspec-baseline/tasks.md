## 1. Scaffold

- [x] 1.1 Run `openspec init --tools claude,codex` and commit the generated skills and commands
- [x] 1.2 Write the project context and artifact rules in `openspec/config.yaml`
- [x] 1.3 Pin the CLI in `scripts/openspec/` and add `scripts/openspec.sh`
- [x] 1.4 Point the generated skills at the pinned CLI with `scripts/openspec-localize.sh`, guarded by a test

## 2. Baseline specs

- [x] 2.1 Write one spec per capability listed in the proposal, from the code first and `docs/hooks.md` second, as of the phase 1 loosening (#1445)
- [x] 2.2 Pass `scripts/openspec.sh validate --all --strict`
- [x] 2.3 Archive this change so the specs land in `openspec/specs/`

## 3. Process

- [x] 3.1 Add the `openspec` job to CI
- [x] 3.2 Freeze `docs/plans/` with a test that rejects a plan dated after 2026-10-20
- [x] 3.3 Point CLAUDE.md, CONTRIBUTING.md and the README at `openspec/`
- [x] 3.4 Stage the CHANGELOG.md bullet under [Unreleased]
