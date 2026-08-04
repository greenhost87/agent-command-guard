#!/bin/sh
set -eu

mkdir -p build
go build -o build/bench_agent_command_guard benchmark/main.go
hook_path=$(./scripts/build.sh)
build/bench_agent_command_guard --hook-command "$hook_path" --hook-label "$hook_path" "$@"
