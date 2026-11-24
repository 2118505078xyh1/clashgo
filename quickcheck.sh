#!/usr/bin/env bash
# 快速验证：只编译 + 跑核心自研包，避免全量重编（60 包）。
# 用法: bash quickcheck.sh
set -e
cd "$(dirname "$0")"

echo "== gofmt =="
gofmt -l . | grep -v '^$' && { echo "格式问题"; exit 1; } || true

echo "== build =="
timeout 55s go build -o /tmp/clashgo-quick.exe .

echo "== core tests (自研内核 + 全部自研模块) =="
timeout 55s go test \
  ./internal/minikernel/ \
  ./internal/wgproto/ \
  ./internal/quicproto/ \
  ./internal/ssproto/ \
  ./internal/dnsproto/ \
  ./internal/yaml/ \
  ./internal/ws/ \
  ./internal/ipstack/ \
  ./internal/vproto/ \
  ./internal/enhance/ \
  ./internal/config/ \
  ./internal/profile/ \
  ./internal/validate/ \
  ./internal/webdav/ \
  -count=1

echo "QUICK CHECK PASSED"
