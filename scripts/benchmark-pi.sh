#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
./scripts/build.sh >/dev/null
exec bun --cwd adapters/pi ./benchmark.ts "$@"
