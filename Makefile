# Makefile for pmux-agent

BINARY := pmux

.PHONY: build build-obfuscated test test-integration test-stress test-all clean snapshot

# Build the pmux binary (local dev)
build:
	go build -ldflags="-X main.version=dev -X main.installMethod=dev -X 'main.hmacSecret=$(PMUX_HMAC_SECRET)'" -o bin/$(BINARY) ./cmd/pmux

# Build with garble obfuscation (mirrors release pipeline)
build-obfuscated:
	garble -literals -seed=random build -trimpath -ldflags="-s -w -X main.version=dev -X main.installMethod=dev -X 'main.hmacSecret=$(PMUX_HMAC_SECRET)'" -o bin/$(BINARY) ./cmd/pmux

# Run unit tests
test:
	go test ./...

# Run integration tests (requires tmux)
test-integration:
	go test -tags=integration -race -timeout=120s ./test/integration/... -v

# Run stress tests (requires tmux, may take several minutes)
test-stress:
	go test -tags=stress -race -timeout=300s ./test/stress/... -v

# Run all tests (unit + integration + stress)
test-all: test test-integration test-stress

# GoReleaser local snapshot (test release pipeline without publishing)
snapshot:
	goreleaser release --snapshot --clean

# Clean build artifacts
clean:
	rm -rf bin/ dist/
