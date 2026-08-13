.PHONY: all build test vet lint boundary contracts fmt-check

all: fmt-check vet boundary contracts test build

build:
	go build ./cmd/agent-service

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed; skipping local lint"; fi

boundary:
	go run ./cmd/boundarycheck -root .

contracts:
	bash scripts/check-contract-drift.sh

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		(echo "Go files require gofmt"; gofmt -l $$(find . -name '*.go' -not -path './vendor/*'); exit 1)
