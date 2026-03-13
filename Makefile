# cadence-hooks — compiled Claude Code hooks
# Run `make` or `make help` to see available targets

CARGO := cargo
BINARY := cadence-hooks

.DEFAULT_GOAL := help

## Development ─────────────────────────────────

.PHONY: build
## Build the binary (debug)
build:
	$(CARGO) build

.PHONY: release
## Build the binary (release, optimized)
release:
	$(CARGO) build --release

.PHONY: test
## Run all workspace tests
test:
	$(CARGO) test --workspace

.PHONY: check
## Run cargo check (fast compilation check)
check:
	$(CARGO) check --workspace

.PHONY: clippy
## Run clippy lints
clippy:
	$(CARGO) clippy --workspace -- -D warnings

.PHONY: fmt
## Format all code
fmt:
	$(CARGO) fmt --all

.PHONY: fmt-check
## Check formatting without modifying
fmt-check:
	$(CARGO) fmt --all -- --check

## CI ──────────────────────────────────────────

.PHONY: ci
## Run all CI checks (fmt, clippy, test)
ci: fmt-check clippy test

## Release ────────────────────────────────────

.PHONY: bump
## Bump workspace version (usage: make bump VERSION=0.4.0)
bump:
	@scripts/bump-version.sh $(VERSION)

## Installation ────────────────────────────────

.PHONY: install
## Install the binary to ~/.cargo/bin
install:
	$(CARGO) install --path .

## Help ────────────────────────────────────────

.PHONY: help
## Show this help
help:
	@printf "\n\033[1mcadence-hooks\033[0m — compiled Claude Code hooks\n\n"
	@awk '/^## / { section = substr($$0, 4) } /^\.PHONY:/ { target = $$2 } /^## [^─]/ && target { printf "  \033[36m%-16s\033[0m %s\n", target, substr($$0, 4); target = "" }' $(MAKEFILE_LIST)
	@printf "\n"
