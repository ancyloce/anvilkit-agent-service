#!/usr/bin/env bash
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
check_file packages/contracts-go/generated/pagixclient/client.gen.go contracts/generated/pagixclient/client.gen.go
check_file packages/contracts-go/generated/schema/contracts.gen.go contracts/generated/schema/contracts.gen.go
check_file packages/contracts-go/generated/trace.json contracts/generated/trace.json
check_file packages/contracts-go/validator/validator.go contracts/validator/validator.go

release_bom_source="$(find "${platform_root}/contracts/governance" -type f -name 'release-bom.json' -print -quit)"
if [[ -z "${release_bom_source}" ]] || ! cmp -s "${release_bom_source}" "${service_root}/contracts/bom/release-bom.json"; then
  echo "contract drift: contracts/bom/release-bom.json differs from the governance release BOM" >&2
  exit 1
fi

for source in "${platform_root}"/contracts/schemas/v1/*.schema.json; do
  check_file "contracts/schemas/v1/$(basename "${source}")" "contracts/schemas/v1/$(basename "${source}")"
done

source_count="$(find "${platform_root}/contracts/schemas/v1" -maxdepth 1 -name '*.schema.json' | wc -l)"
pinned_count="$(find "${service_root}/contracts/schemas/v1" -maxdepth 1 -name '*.schema.json' | wc -l)"
test "${source_count}" = "${pinned_count}" || { echo "contract drift: schema count differs" >&2; exit 1; }

echo "agent-service contract pin is byte-identical to the candidate BOM inputs"
