# anvilkit-agent-service

Go modular-monolith implementing the AnvilKit Agent Service baseline kernel. The
Platform repository pins this repository as `services/agent-service`; runtime
code never imports Platform source.

## Development

From this repository inside the Platform checkout:

```bash
make all
POSTGRES_TEST_URL='postgres://…' go test -race -count=1 ./internal/persistence
DBOS_TEST_URL='postgres://…' go test -race -count=1 ./internal/workflow/dbos
```

The approved sustained durable-create proof is intentionally separate from the
normal suite:

```bash
POSTGRES_TEST_URL='postgres://…' \
DURABLE_CREATE_LOAD_TEST=1 DURABLE_CREATE_LOAD_DURATION=15m \
DURABLE_CREATE_EVIDENCE_PATH=.evidence/durable-create/create-sustained.json \
go test -race -count=1 -timeout=20m -v ./internal/persistence
```

`make all` checks formatting, vet, module boundaries, candidate-contract drift,
race tests, and the binary build. `make ci` adds a mandatory strict
`golangci-lint` pass and fails when the linter is unavailable.

## Authority boundaries

- `cmd/agent-service` is the sole composition root.
- The sixteen product modules live under `internal/`; adapters point inward to
  consumer-owned ports.
- DBOS SDK values are confined to `internal/workflow/dbos`.
- `contracts/` is a pinned generated/runtime-validation intake. Regenerate in
  `anvilkit-platform`, synchronize deliberately, then run
  `scripts/check-contract-drift.sh`.
- The foundation memory schema intentionally has no tables or call sites.

Production startup is fail-closed. It requires separate migration, control,
workflow, events/authority, artifact, and evaluation database configuration;
an independent receipt journal; recovery register; authoritative time;
protected audit; signing capability; and pinned contract/policy material.
Provider availability changes eligibility and is not base liveness.
