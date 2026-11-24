#!/usr/bin/env bash
# Fast verification of a clashgo build: format, build, tests, vet.
# Usage: bash verify.sh [--full]   (--full adds race detection + screenshots)
set -e
cd "$(dirname "$0")"

echo "== gofmt check =="
UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then
  echo "Unformatted files:"
  echo "$UNFORMATTED"
  exit 1
fi
echo "OK"

echo "== go build =="
go build -o /tmp/clashgo-verify.exe .
echo "OK"

echo "== go test (cached, parallel per package) =="
go test ./...
echo "OK"

echo "== go vet =="
go vet ./...
echo "OK"

if [ "$1" = "--full" ]; then
  echo "== race test (concurrency-critical packages only) =="
  go test -race ./internal/guard/ ./internal/batch/ ./internal/notice/ ./internal/nodeprobe/ ./internal/safemode/ ./internal/webapi/ ./ui/
  echo "OK"
  echo "== headless screenshots =="
  go run ./cmd/shot 2>&1 | tail -1
fi

echo "ALL CHECKS PASSED"
