# Makefile
.PHONY: build release clean fmt fmt-check check test doc help tasks clippy publish publish-dry-run ci msrv fuzz-build fuzz-replay fuzz

default: help
CARGO_CMD=/usr/bin/env cargo
# cargo-sweep (cargo install cargo-sweep), when installed, deletes whatever an older build
# left in target/ that this build didn't use, so only fresh release artifacts remain.
SWEEP := $(shell command -v cargo-sweep >/dev/null 2>&1 && echo cargo sweep)
MSRV?=1.88
FUZZ_SECONDS?=60
# The crate forbids `unsafe`, so AddressSanitizer would only slow the fuzzers down (about 2x); skip it.
FUZZ_FLAGS=-s none

# ----------------------------------------------------------------------------------------------------------------------
# Targets
# ----------------------------------------------------------------------------------------------------------------------

# Build the crate. Does not reformat: build targets should not rewrite sources.
build: ## Build the crate in release mode, then sweep stale artifacts
	$(if $(SWEEP),$(SWEEP) --stamp)
	${CARGO_CMD} build --release
	$(if $(SWEEP),$(SWEEP) --file)

# Full release process (ensures everything runs in the correct order)
release: fmt check clippy build test doc ## Perform a full release (fmt, check, clippy, build, test, doc)

# What CI runs: verifies formatting instead of rewriting it
ci: fmt-check check clippy test doc ## Verification-only pipeline (no source rewrites)

# Check the rust-version claim in Cargo.toml (needs rustup and the toolchain)
msrv: ## Type-check on the minimum supported Rust version (MSRV, default 1.88)
	${CARGO_CMD} +$(MSRV) check --release --all-targets --all-features --locked

# Fuzzing needs nightly and cargo-fuzz (cargo install cargo-fuzz); it is not part of `make ci`.
fuzz-build: ## Build every fuzz target (needs nightly and cargo-fuzz)
	${CARGO_CMD} +nightly fuzz build $(FUZZ_FLAGS)

fuzz-replay: ## Replay each committed fuzz corpus once (fast regression pass)
	for t in $$(${CARGO_CMD} +nightly fuzz list); do ${CARGO_CMD} +nightly fuzz run $(FUZZ_FLAGS) $$t fuzz/corpus/$$t -- -runs=0 || exit 1; done

fuzz: ## Fuzz one target: make fuzz TARGET=bdecode FUZZ_SECONDS=60
	@test -n "$(TARGET)" || { echo "usage: make fuzz TARGET=<name> [FUZZ_SECONDS=60]"; exit 1; }
	${CARGO_CMD} +nightly fuzz run $(FUZZ_FLAGS) $(TARGET) -- -max_total_time=$(FUZZ_SECONDS)

# Format the code
fmt: ## Format the code using cargo fmt
	${CARGO_CMD} fmt

# Verify formatting without rewriting (for CI / pre-push)
fmt-check: ## Fail if anything is unformatted
	${CARGO_CMD} fmt --check

# Check for errors without building. --all-targets covers bins, tests and benches.
check: ## Run cargo check --release to analyze the code without compiling
	${CARGO_CMD} check --release --all-targets --all-features --locked

# Strict linter, fails on warnings and suggests fixes
clippy: ## Run clippy and fail on warnings
	${CARGO_CMD} clippy --release --all-targets --all-features --locked -- -D warnings

# Run tests
test: ## Run all tests using cargo test --release
	${CARGO_CMD} test --release --all-features --locked

# Generate documentation. Broken intra-doc links fail the build.
doc: ## Generate project documentation using cargo doc --release
	RUSTDOCFLAGS="-D warnings" ${CARGO_CMD} doc --release --all-features --no-deps --locked

# Publish to crates.io
publish: ## Publish cloudllm_dht to crates.io
	${CARGO_CMD} publish

# Dry-run publish to crates.io
publish-dry-run: ## Dry-run publish to crates.io
	${CARGO_CMD} publish --dry-run

# Clean build artifacts
clean: ## Remove build artifacts using cargo clean
	${CARGO_CMD} clean

# Show all available tasks
help tasks: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
