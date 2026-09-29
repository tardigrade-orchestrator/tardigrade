# Thin wrapper around `cargo xtask`. The logic lives in xtask/, so that it runs
# identically under every CI system (ADR-0023: provider-neutral, reproducible).

.PHONY: all ci guard fmt build clean

all: ci

## ci: Definition of Done from CLAUDE.md (guard, fmt, clippy, test, deny)
ci:
	cargo xtask ci

## guard: only the guardrail check (unsafe policy)
guard:
	cargo xtask guard

## fmt: format the code (writing)
fmt:
	cargo xtask fmt

## build: build the workspace
build:
	cargo build --workspace --locked

## clean: remove build artifacts
clean:
	cargo clean
