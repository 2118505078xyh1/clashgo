#!/usr/bin/env bash
# Build Windows binaries WITHOUT the console window (-H windowsgui).
set -e
cd "$(dirname "$0")"
LDFLAGS="-H windowsgui -s -w"

echo "== cleaning stale payload files =="
rm -f cmd/setup/payload/clashgo.exe~ cmd/setup/payload/*.exe~ cmd/setup/payload/*.bak

echo "== building clashgo.exe (GUI subsystem, no console) =="
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o cmd/setup/payload/clashgo.exe .

echo "== copying app icon into payload =="
cp resources/app-icon.ico cmd/setup/payload/app-icon.ico
ls -lh cmd/setup/payload/

echo "== building ClashGo-Setup.exe (GUI subsystem, no console) =="
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o dist/ClashGo-Setup.exe ./cmd/setup

echo "== installer =="
ls -lh dist/ClashGo-Setup.exe
echo "DONE"
