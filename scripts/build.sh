#!/bin/sh
set -eu

mkdir -p build
go build -trimpath -ldflags="-s -w" -o build/agent-command-guard .
printf '%s\n' build/agent-command-guard
