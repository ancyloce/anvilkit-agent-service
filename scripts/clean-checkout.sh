#!/bin/sh
# Prove the service builds and passes its tests from a clean checkout.
#
# The tree is materialised from exactly the files a commit would carry:
# tracked files plus untracked files git does not ignore. Anything the build
# depends on that is ignored — an embedded directory excluded by .gitignore,
# for example — is therefore absent from the copy and fails here, which is
# the defect this gate exists to catch.
#
# Usage: scripts/clean-checkout.sh [destination]
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

if ! command -v git >/dev/null 2>&1; then
  echo "clean-checkout: git is required" >&2
  exit 1
fi

destination=${1:-}
cleanup=""
if [ -z "$destination" ]; then
  destination=$(mktemp -d)
  cleanup=$destination
fi
mkdir -p "$destination"

trap 'if [ -n "$cleanup" ]; then rm -rf "$cleanup"; fi' EXIT INT TERM

echo "clean-checkout: materialising committable tree in $destination"
git ls-files --cached --others --exclude-standard -z |
  tar --null --files-from=- --create --file=- |
  (cd "$destination" && tar --extract --file=-)

if [ ! -f "$destination/go.mod" ]; then
  echo "clean-checkout: the committable tree has no go.mod" >&2
  exit 1
fi

cd "$destination"
# The materialised tree is deliberately not a repository, so version-control
# stamping has nothing to read and must be turned off.
GOFLAGS="-buildvcs=false"
export GOFLAGS
echo "clean-checkout: go build ./..."
go build ./...
echo "clean-checkout: go vet ./..."
go vet ./...
echo "clean-checkout: module boundary check"
go run ./cmd/boundarycheck -root .
echo "clean-checkout: go test -race -count=1 ./..."
go test -race -count=1 ./...
echo "clean-checkout: reproducible"
