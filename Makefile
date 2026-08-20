.PHONY: all ci build test vet lint lint-strict boundary contracts fmt-check clean-checkout sbom

all: fmt-check vet boundary contracts test build

ci: fmt-check vet lint-strict boundary contracts test build

build:
	go build ./cmd/agent-service

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed; skipping local lint"; fi

lint-strict:
	@command -v golangci-lint >/dev/null 2>&1 || (echo "golangci-lint is required for CI/release verification"; exit 1)
	golangci-lint run ./...

boundary:
	go run ./cmd/boundarycheck -root .

contracts:
	bash scripts/check-contract-drift.sh

# clean-checkout proves the service builds and passes its tests from exactly
# the files a commit would carry, so nothing in the build can depend on a file
# git would not keep.
clean-checkout:
	sh scripts/clean-checkout.sh

# sbom regenerates the committed bill of materials. Drift between it and the
# module graph is a test failure, so regenerate after any dependency change.
sbom:
	@command -v cyclonedx-gomod >/dev/null 2>&1 || (echo "cyclonedx-gomod is required: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0"; exit 1)
	cyclonedx-gomod mod -json -output sbom.cdx.json .

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		(echo "Go files require gofmt"; gofmt -l $$(find . -name '*.go' -not -path './vendor/*'); exit 1)
