#!/usr/bin/env sh
set -e
command -v go >/dev/null || { echo "Go is not installed: https://go.dev/dl/"; exit 1; }
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o cryptokit .
echo "Done: ./cryptokit"
