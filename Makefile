# sqli - SQL injection assessment toolkit
#
# POSIX shell (Linux, macOS, WSL, Git Bash). On native Windows use build.ps1.
#
#   make build      compile bin/sqli
#   make test       run the full test suite
#   make check      fmt + vet + test
#   make cross      cross-compile release binaries into dist/
#   make demo       run the vulnerable demo app
#
# Override VERSION when releasing: make build VERSION=1.2.0

BINARY   := sqli
CMD      := ./cmd/sqli
VULN_CMD := ./cmd/vulnserver
BIN_DIR  := bin
DIST_DIR := dist

VERSION  ?= 1.0.0
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X github.com/akshaytheflash/antisqli/internal/version.Version=$(VERSION) \
	-X github.com/akshaytheflash/antisqli/internal/version.Commit=$(COMMIT) \
	-X github.com/akshaytheflash/antisqli/internal/version.Date=$(DATE)

GO      ?= go
GOFLAGS ?=

.PHONY: all build vulnserver install test test-short race vet fmt fmt-check check tidy clean cross demo help

all: check build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)
	@echo "built $(BIN_DIR)/$(BINARY)"

vulnserver:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -o $(BIN_DIR)/vulnserver $(VULN_CMD)
	@echo "built $(BIN_DIR)/vulnserver"

install:
	$(GO) install $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" $(CMD)

test:
	$(GO) test $(GOFLAGS) -count=1 ./...

test-short:
	$(GO) test $(GOFLAGS) -count=1 -short ./...

race:
	$(GO) test $(GOFLAGS) -count=1 -race ./...

vet:
	$(GO) vet $(GOFLAGS) ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

check: fmt-check vet test

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

cross:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST_DIR)/$(BINARY)_$${os}_$${arch}$${ext}"; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath \
			-ldflags "$(LDFLAGS)" -o "$$out" $(CMD); \
	done
	@echo "release binaries in $(DIST_DIR)/"

demo: vulnserver
	@echo "starting vulnerable demo app on http://127.0.0.1:8099"
	@echo "in another terminal: $(BIN_DIR)/$(BINARY) scan -u \"http://127.0.0.1:8099/item?id=1\" --authorized"
	@$(BIN_DIR)/vulnserver

help:
	@echo "sqli build targets:"
	@echo "  build        compile $(BIN_DIR)/$(BINARY)"
	@echo "  vulnserver   compile the demo vulnerable app"
	@echo "  install      go install the CLI"
	@echo "  test         run all tests"
	@echo "  test-short   skip timing tests"
	@echo "  race         run tests with the race detector"
	@echo "  vet          go vet ./..."
	@echo "  fmt          gofmt the tree"
	@echo "  fmt-check    fail if any file is unformatted"
	@echo "  check        fmt-check + vet + test"
	@echo "  cross        build linux/darwin/windows binaries into $(DIST_DIR)/"
	@echo "  clean        remove build artifacts"
	@echo "  demo         run the vulnerable demo app"
