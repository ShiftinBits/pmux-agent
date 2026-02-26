# Makefile for pmux-agent

VERSION ?= dev
BINARY := pmux
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build build-all release test test-integration test-stress test-all clean

# Build the pmux binary
build:
	go build -o bin/$(BINARY) ./cmd/pmux

# Build for all supported platforms
build-all:
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		output=bin/$(BINARY)-$${os}-$${arch}; \
		echo "Building $${output}..."; \
		GOOS=$${os} GOARCH=$${arch} go build -ldflags="-s -w" -o $${output} ./cmd/pmux; \
	done

# Build all platforms and generate release checksums
release: build-all
	@echo "Generating checksums..."
	@cd bin && shasum -a 256 $(BINARY)-* > checksums.txt
	@echo "Release artifacts in bin/"
	@echo "Tag and push: git tag v$(VERSION) && git push origin v$(VERSION)"

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

# Clean build artifacts
clean:
	rm -rf bin/
