#!/usr/bin/env bash
# Verifies the agent-service contract intake is byte-identical to the
# canonical Agent contract material in anvilkit-platform (ADR-018).
set -euo pipefail

service_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_root="${1:-$(cd "${service_root}/../.." && pwd)}"

check_file() {
  local source_path="$1"
  local pinned_path="$2"
  if ! cmp -s "${platform_root}/${source_path}" "${service_root}/${pinned_path}"; then
    echo "contract drift: ${pinned_path} differs from ${source_path}" >&2
    return 1
  fi
}

check_file packages/contracts-go/generated/agentclient/client.gen.go contracts/generated/agentclient/client.gen.go
check_file packages/contracts-go/generated/agentruntimeclient/client.gen.go contracts/generated/agentruntimeclient/client.gen.go
check_file packages/contracts-go/generated/pagixclient/client.gen.go contracts/generated/pagixclient/client.gen.go
check_file packages/contracts-go/generated/schema/contracts.gen.go contracts/generated/schema/contracts.gen.go
check_file packages/contracts-go/generated/trace.json contracts/generated/trace.json
check_file packages/contracts-go/validator/validator.go contracts/validator/validator.go
check_file contracts/agent/profile/p0-kernel-profile.json contracts/agent/profile/p0-kernel-profile.json
check_file contracts/agent/lock/contracts.lock.json contracts/agent/lock/contracts.lock.json
check_file contracts/agent/openapi/agent-runtime.openapi.json contracts/agent/openapi/agent-runtime.openapi.json

for source in "${platform_root}"/contracts/agent/schemas/*.schema.json; do
  check_file "contracts/agent/schemas/$(basename "${source}")" "contracts/agent/schemas/$(basename "${source}")"
done
for source in "${platform_root}"/contracts/agent/schemas/meta/*; do
  check_file "contracts/agent/schemas/meta/$(basename "${source}")" "contracts/agent/schemas/meta/$(basename "${source}")"
done

source_count="$(find "${platform_root}/contracts/agent/schemas" -maxdepth 1 -name '*.schema.json' | wc -l)"
pinned_count="$(find "${service_root}/contracts/agent/schemas" -maxdepth 1 -name '*.schema.json' | wc -l)"
test "${source_count}" = "${pinned_count}" || { echo "contract drift: schema count differs" >&2; exit 1; }

echo "agent-service contract intake is byte-identical to the canonical Agent contract material"
