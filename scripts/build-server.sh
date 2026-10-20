#!/usr/bin/env bash
# Cross-compile the web server for the EC2 host (Amazon Linux 2023 on Graviton = linux/arm64).
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf build/server
mkdir -p build/server
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' -o build/server/cfcookie-server ./cmd/server
ls -lh build/server/cfcookie-server
