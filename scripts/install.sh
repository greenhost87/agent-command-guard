#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
args=()
if [[ $# -eq 0 ]]; then
  args=()
else
  for a in "$@"; do
    case "$a" in
      all) args+=(--codex --cursor) ;;
      codex) args+=(--codex) ;;
      cursor) args+=(--cursor) ;;
      --codex|--cursor|--pi|--help|-h|--wire-only|--local-build|--prefix|--version) args+=("$a") ;;
      --prefix=*|--version=*) args+=("$a") ;;
      *) echo "scripts/install.sh: unexpected argument \"$a\" (use --codex/--cursor/--pi)" >&2; exit 1 ;;
    esac
  done
fi
# prefix/version take a value; handle bare --prefix/--version with next arg
expanded=()
skip_next=false
for ((i=0; i<${#args[@]}; i++)); do
  if $skip_next; then skip_next=false; continue; fi
  a="${args[i]}"
  if [[ "$a" == "--prefix" || "$a" == "--version" ]]; then
    expanded+=("$a")
    if (( i+1 < ${#args[@]} )); then
      expanded+=("${args[i+1]}")
      skip_next=true
    fi
  else
    expanded+=("$a")
  fi
done
cd "$ROOT"
exec go run ./cmd/install "${expanded[@]+"${expanded[@]}"}"
