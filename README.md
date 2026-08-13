# anvilkit-agent-service

Go modular-monolith implementing the AnvilKit Agent Service P0 kernel. The
Platform repository pins this repository as `services/agent-service`; runtime
code never imports Platform source.

## Development

From this repository inside the Platform checkout:

```bash
make all
POSTGRES_TEST_URL='postgres://…' go test -race -count=1 ./internal/persistence
DBOS_TEST_URL='postgres://…' go test -race -count=1 ./internal/workflow/dbos
```

`make all` checks formatting, vet, module boundaries, candidate-contract drift,
race tests, and the binary build. `golangci-lint` is a separate `make lint`
target and is mandatory in CI.

## Authority boundaries

- `cmd/agent-service` is the sole composition root.
- The sixteen product modules live under `internal/`; adapters point inward to
  consumer-owned ports.
- DBOS SDK values are confined to `internal/workflow/dbos`.
- `contracts/` is a pinned generated/runtime-validation intake. Regenerate in
  `anvilkit-platform`, synchronize deliberately, then run
  `scripts/check-contract-drift.sh`.
- The Phase 0 memory schema intentionally has no tables or call sites.

Production startup is fail-closed. It requires separate migration, control,
workflow, events/authority, artifact, and evaluation database configuration;
an independent receipt journal; recovery register; authoritative time;
protected audit; signing capability; and pinned contract/policy material.
Provider availability changes eligibility and is not base liveness.
