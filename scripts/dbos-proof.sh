#!/usr/bin/env bash
set -euo pipefail

: "${DBOS_SYSTEM_DATABASE_URL:?DBOS_SYSTEM_DATABASE_URL is required}"
: "${DBOS_JOURNAL_URL:?DBOS_JOURNAL_URL is required}"

sdk_version="v0.20.0"
proof_root="${TMPDIR:-/tmp}/anvilkit-agent-dbos-proof"
module_cache="${proof_root}/modcache"
build_cache="${proof_root}/gocache"

mkdir -p "${proof_root}"
sdk_dir="$(GOMODCACHE="${module_cache}" GOCACHE="${build_cache}" \
  go mod download -json "github.com/dbos-inc/dbos-transact-golang@${sdk_version}" | \
  sed -n 's/.*"Dir": "\([^"]*\)".*/\1/p')"

test_pattern='TestWorkflowRecovery|TestSendRecv|TestRecvStepConflict|TestChildWorkflow|TestWorkflowCancel|TestNoConcurrentWorkflowSameID|TestOnlineMigrationsAreIdempotent'
(
  cd "${sdk_dir}"
  DBOS_SYSTEM_DATABASE_URL="${DBOS_SYSTEM_DATABASE_URL}" \
    GOMODCACHE="${module_cache}" GOCACHE="${build_cache}" \
    go test -race -count=1 ./dbos -run "${test_pattern}"
)

GOMODCACHE="${module_cache}" GOCACHE="${build_cache}" \
  go run ./cmd/dbos-benchmark --concurrency 500 --rate 20 --postgres-version 17 --journal-url "${DBOS_JOURNAL_URL}"
GOMODCACHE="${module_cache}" GOCACHE="${build_cache}" \
  go run ./cmd/dbos-benchmark --concurrency 5000 --rate 200 --postgres-version 17 --journal-url "${DBOS_JOURNAL_URL}"

restart_binary="${proof_root}/dbos-restart-probe"
GOMODCACHE="${module_cache}" GOCACHE="${build_cache}" go build -o "${restart_binary}" ./cmd/dbos-restart-probe
for checkpoint in 1 2 3; do
  restart_id="restart-proof-${checkpoint}-$(date +%s)"
  "${restart_binary}" --mode start --workflow-id "${restart_id}" --checkpoint "${checkpoint}" &
  restart_pid=$!
  observed=0
  for _ in $(seq 1 100); do
    if "${restart_binary}" --mode count --workflow-id "${restart_id}" --checkpoint "${checkpoint}" --step "${checkpoint}" 2>/dev/null | grep -qx 1; then
      observed=1
      break
    fi
    sleep 0.1
  done
  if [[ "${observed}" -ne 1 ]]; then
    kill -9 "${restart_pid}" 2>/dev/null || true
    wait "${restart_pid}" 2>/dev/null || true
    echo "checkpoint ${checkpoint} was not observed" >&2
    exit 1
  fi
  kill -9 "${restart_pid}"
  wait "${restart_pid}" 2>/dev/null || true
  "${restart_binary}" --mode resume --workflow-id "${restart_id}" --checkpoint "${checkpoint}"
done
