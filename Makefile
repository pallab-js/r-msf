# Rust Cybersecurity Framework — Build System (Linux x86_64 only)
# Usage: make <target>

SHELL := /bin/bash
CARGO := cargo
TARGET := rcf-cli
BINARY := rcf
VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
DIST_DIR := dist

.PHONY: all build release test check clean lint bloat help
.PHONY: install dist

# ─── Default ────────────────────────────────────────────────────────
all: build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Build ───────────────────────────────────────────────────────────
build: ## Build debug binary
	$(CARGO) build -p $(TARGET)

release: ## Build release binary
	$(CARGO) build --release -p $(TARGET)

check: ## Check code compiles (fast)
	$(CARGO) check --workspace

test: ## Run all tests
	$(CARGO) test --workspace

lint: ## Run clippy with strict warnings
	$(CARGO) clippy --workspace -- -D warnings

fmt: ## Format code
	$(CARGO) fmt

format-check: ## Check formatting
	$(CARGO) fmt -- --check

# ─── Distribution ───────────────────────────────────────────────────
dist: release ## Build and package binary
	@mkdir -p $(DIST_DIR)
	@cp target/release/$(BINARY) $(DIST_DIR)/$(BINARY)-v$(VERSION)-linux-x86_64
	@echo "Built: $(DIST_DIR)/$(BINARY)-v$(VERSION)-linux-x86_64"
	@ls -lh $(DIST_DIR)/

install: release ## Install binary to /usr/local/bin
	@cp target/release/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed $(BINARY) to /usr/local/bin/"

# ─── Analysis ────────────────────────────────────────────────────────
bloat: ## Analyze binary size with cargo-bloat
	$(CARGO) bloat --release -p $(TARGET) --crates | head -30

bloat-functions: ## Analyze which functions take most space
	$(CARGO) bloat --release -p $(TARGET) -n 50 | head -60

# ─── PGO (Profile-Guided Optimization) ─────────────────────────────
PGO_DIR := /tmp/rcf-pgo-data

pgo-instrumented: ## Build with PGO instrumentation
	RUSTFLAGS="-Cprofile-generate=$(PGO_DIR)" $(CARGO) build --release -p $(TARGET)

pgo-run: ## Run instrumented binary to collect profile data
	@mkdir -p $(PGO_DIR)
	./target/release/$(BINARY) scan -t 127.0.0.1 --ports 1-100
	./target/release/$(BINARY) venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 -f c
	./target/release/$(BINARY) search scanner
	./target/release/$(BINARY) db stats

pgo-merge: ## Merge PGO data
	llvm-profdata merge -output=$(PGO_DIR)/merged.profdata $(PGO_DIR)/

pgo-optimize: ## Build with PGO optimization
	RUSTFLAGS="-Cprofile-use=$(PGO_DIR)/merged.profdata" $(CARGO) build --release -p $(TARGET)

pgo: pgo-instrumented pgo-run pgo-merge pgo-optimize ## Full PGO pipeline

size: ## Show binary size
	@ls -lh target/release/$(BINARY) 2>/dev/null | awk '{print $$5, $$9}'

deps: ## Show dependency tree
	$(CARGO) tree -p $(TARGET)

# ─── Cleanup ────────────────────────────────────────────────────────
clean: ## Clean build artifacts
	$(CARGO) clean

clean-target: ## Clean only target directory
	rm -rf target/

# ─── Quick commands ─────────────────────────────────────────────────
run: release ## Run the console
	./target/release/$(BINARY)

scan: release ## Quick scan localhost common ports
	./target/release/$(BINARY) scan -t 127.0.0.1 --ports common

venom: release ## Generate a test payload
	./target/release/$(BINARY) venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 -f c

db-stats: release ## Show database stats
	./target/release/$(BINARY) db stats

modules: release ## List all modules
	./target/release/$(BINARY) search ""
