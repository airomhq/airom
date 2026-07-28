# AIROM — build & development entry points.
#
# Self-documenting: `make help` lists every target (the `## …` comments on
# target lines are the source of truth — keep them accurate).
#
# Portability: recipes are plain POSIX sh. Variable assignment uses $(shell),
# so GNU make (the default on macOS, Linux, and CI) is expected; everything
# else avoids GNU-only functions.
#
# Release binaries are always static: CGO_ENABLED=0 is invariant P8 in
# docs/ARCHITECTURE.md and is baked into `build` and `install` below — do not
# remove it.

BINARY    = airom
MAIN_PKG  = ./cmd/airom
MODULE    = github.com/airomhq/airom

# ── Version stamp ─────────────────────────────────────────────────────────────
# Injected into the main package (cmd/airom declares `var version, commit,
# date string`; main.go hands them to internal/cli — see ARCHITECTURE.md §4).
# Overridable from the environment/CI: `make build VERSION=v0.1.0`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

BUILDFLAGS = -trimpath

# Per-target budget for the fuzz loop; raise locally for deeper runs
# (e.g. `make fuzz FUZZ_TIME=5m`). CI runs long campaigns separately.
FUZZ_TIME ?= 10s

.PHONY: all build install test cover lint fmt vet generate golden fuzz clean help

all: build ## Default target: build the binary

build: ## Build the static airom binary (CGO_ENABLED=0) at ./airom
	CGO_ENABLED=0 go build $(BUILDFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) $(MAIN_PKG)

install: ## Install airom into GOBIN with the same static build + version stamp
	CGO_ENABLED=0 go install $(BUILDFLAGS) -ldflags '$(LDFLAGS)' $(MAIN_PKG)

test: ## Run the full test suite with the race detector (§14: everything runs under -race)
	go test -race ./...

cover: ## Run tests with coverage; prints the per-function summary (HTML: go tool cover -html=coverage.out)
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint: ## Run golangci-lint (config: .golangci.yml — includes the §4 import-direction depguard rules)
	golangci-lint run

# Go sources belonging to THIS repo. A bare `.` would descend into a nested
# airom-rules checkout (gitignored, a separate module and a separate repo) and
# silently rewrite files in someone else's working tree. Plain POSIX find — no
# -printf, which is GNU-only and would silently expand to nothing on macOS.
GO_SRC := $(shell find . -name '*.go' -not -path './airom-rules/*' -not -path './.git/*')

fmt: ## Format Go sources (gofumpt when installed, gofmt otherwise)
	@test -n "$(GO_SRC)" || { echo "make fmt: no Go sources found — refusing to run a formatter with no arguments (it would read stdin and hang)"; exit 1; }
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -l -w $(GO_SRC); \
	else \
		echo "gofumpt not found; falling back to gofmt (install: go install mvdan.cc/gofumpt@latest)"; \
		gofmt -l -w $(GO_SRC); \
	fi

vet: ## Run go vet across all packages
	go vet ./...

generate: ## Run go generate (regenerates internal/detectors/all — the generated registration list, §6.2)
	go generate ./...

golden: ## Re-record golden files (writer outputs, detector fixtures). Review the diff before committing.
	UPDATE_GOLDEN=1 go test ./...

# The fuzz loop: `go test -fuzz` accepts exactly one target in one package per
# invocation, so we enumerate every package, list its Fuzz* targets, and give
# each one a short FUZZ_TIME burst. This is the smoke-test loop for local dev
# and PR CI; new failing inputs are minimized into **/testdata/fuzz/ and must
# be committed (they become regression seeds — see .gitignore).
fuzz: ## Run every Fuzz* target briefly (FUZZ_TIME per target, default 10s)
	@for pkg in $$(go list ./...); do \
		targets=$$(go test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); \
		for t in $$targets; do \
			echo "==> fuzz $$pkg $$t ($(FUZZ_TIME))"; \
			go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZ_TIME) $$pkg || exit 1; \
		done; \
	done

bench: ## Run the tracked benchmarks (throughput, assembly) — not asserted, for tracking
	go test -run '^$$' -bench . -benchmem ./internal/perf/...

test-heavy: ## Run the heavy perf trees (10x files + a 200 MB model file); slow, no -race
	AIROM_PERF_HEAVY=1 go test -run 'Heavy|BigFile' ./internal/perf/...

clean: ## Remove build artifacts, coverage output, and dist/
	rm -f $(BINARY) $(BINARY).exe coverage.out coverage.html
	rm -rf dist/ tmp/
	go clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "AIROM — make targets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
