VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X nodetrust/internal/version.Version=$(VERSION) -X nodetrust/internal/version.Commit=$(COMMIT)

.PHONY: all build test test-sim test-py vet fmt-check tidy clean demo

all: fmt-check vet test build

# The verifier's checks on saved logs and example changes, no AWS needed.
demo:
	go run ./cmd/verifier demo

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go test -race ./...

# Unit tests against the in-memory TPM simulator (needs cgo and a C compiler).
test-sim:
	go test -race -tags simulator ./...

# Python helpers used by the infra scripts (standard library only).
test-py:
	cd infra/phase1 && python3 -m unittest -v test_ima_replay
	cd infra/phase2 && python3 -m unittest -v test_manifest
	cd infra/phase2/node && PYTHONPATH=../../phase1 python3 -m unittest -v test_ima_snapshot

vet:
	go vet ./...
	go vet -tags simulator ./...

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	go mod tidy

clean:
	rm -rf bin
