#!/usr/bin/env bash
# 下载 mihomo 核心到 cmd/setup/payload/core/，随安装包一起分发。
#
# mihomo 是成熟的开源代理内核（MIT），ClashGo 用它作为默认内核后端：
# Reality / XTLS Vision / uTLS 指纹等细节比自研内核更可靠。
#
# 用法：
#   bash scripts/fetch-mihomo.sh              # 下载稳定版
#   MIHOMO_VERSION=v1.19.14 bash scripts/fetch-mihomo.sh
set -e
cd "$(dirname "$0")/.."

VERSION="${MIHOMO_VERSION:-latest}"
OUT_DIR="cmd/setup/payload/core"
mkdir -p "$OUT_DIR"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
  Darwin)                 PLATFORM="darwin" ;;
  *)                      PLATFORM="linux" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/MetaCubeX/mihomo/releases/latest/download/mihomo-${PLATFORM}-${ARCH}-${VERSION}.gz"
  # latest 下载名带日期，改为走 API 解析真实文件名
  API="https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
  NAME=$(curl -sSL "$API" | grep -o '"browser_download_url": *"[^"]*mihomo-[^"]*'"'"'${PLATFORM}-${ARCH}[^"'"'"']*"'"'"'' | head -1 | sed 's/.*"browser_download_url": *"//;s/"$//')
  if [ -z "$NAME" ]; then
    echo "无法解析 mihomo 下载地址" >&2
    exit 1
  fi
  URL="$NAME"
fi

echo "== downloading mihomo =="
echo "url: $URL"
TMP="$(mktemp)"
curl -sSL -o "$TMP" "$URL"

case "$URL" in
  *.gz) gzip -dc "$TMP" > "$OUT_DIR/mihomo.exe" ;;
  *.zip) unzip -o -q "$TMP" -d "$OUT_DIR" ;;
  *)    cp "$TMP" "$OUT_DIR/mihomo.exe" ;;
esac
rm -f "$TMP"

chmod +x "$OUT_DIR/mihomo.exe" 2>/dev/null || true
ls -lh "$OUT_DIR/mihomo.exe"
echo "DONE"
