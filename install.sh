#!/usr/bin/env bash
set -euo pipefail

SOURCE="${BASH_SOURCE[0]:-$0}"
ROOT="$(cd "$(dirname "$SOURCE")" 2>/dev/null && pwd || true)"

if [[ -n "${ROOT}" && -f "${ROOT}/cmd/install/main.go" ]]; then
  cd "${ROOT}"
  exec go run ./cmd/install "$@"
fi
if [[ -n "${ROOT}" && -f "${ROOT}/scripts/install.sh" ]]; then
  exec "${ROOT}/scripts/install.sh" "$@"
fi

# Standalone / curl|bash bootstrap: download latest (or --version) tarball, extract,
# then run the packaged install-cli for harness wiring.
PREFIX="${AGENT_COMMAND_GUARD_HOME:-${HOME}/.agent-command-guard}/install"
VERSION=""
WIRE_ARGS=()
LOCAL_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { echo "install.sh: --prefix requires a path" >&2; exit 1; }
      PREFIX="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "install.sh: --version requires a version" >&2; exit 1; }
      VERSION="$2"
      shift 2
      ;;
    --local-build)
      LOCAL_BUILD=1
      shift
      ;;
    --pi|--cursor|--codex|--wire-only|-h|--help)
      WIRE_ARGS+=("$1")
      shift
      ;;
    *)
      echo "install.sh: unexpected argument \"$1\"" >&2
      exit 1
      ;;
  esac
done

if [[ "${LOCAL_BUILD}" -eq 1 ]]; then
  echo "install.sh: --local-build requires a source checkout (run ./install.sh from the repo)" >&2
  exit 1
fi

DOWNLOAD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/acg-bootstrap-XXXXXX")"
cleanup() {
  rm -rf "${DOWNLOAD_DIR}"
}
trap cleanup EXIT

API_URL="https://api.github.com/repos/greenhost87/agent-command-guard/releases/latest"
if [[ -n "${VERSION}" ]]; then
  TAG="${VERSION}"
  [[ "${TAG}" == v* ]] || TAG="v${TAG}"
  API_URL="https://api.github.com/repos/greenhost87/agent-command-guard/releases/tags/${TAG}"
fi

echo "Downloading release metadata from ${API_URL}"
TGZ_URL="$(
  curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: agent-command-guard-install' "${API_URL}" \
    | bun -e '
      const release = JSON.parse(await Bun.stdin.text());
      const asset = (release.assets ?? []).find((entry) =>
        typeof entry?.name === "string" && /^agent-command-guard-.+\.tgz$/.test(entry.name)
      );
      if (!asset?.browser_download_url) {
        throw new Error(`GitHub release ${release.tag_name ?? "?"} has no agent-command-guard-*.tgz asset`);
      }
      process.stdout.write(asset.browser_download_url);
    '
)"
TGZ_PATH="${DOWNLOAD_DIR}/package.tgz"
echo "Downloading ${TGZ_URL}"
curl -fsSL -H 'User-Agent: agent-command-guard-install' -o "${TGZ_PATH}" "${TGZ_URL}"

EXTRACT_ROOT="${DOWNLOAD_DIR}/extract"
mkdir -p "${EXTRACT_ROOT}"
tar -xzf "${TGZ_PATH}" -C "${EXTRACT_ROOT}"
PACKAGE_DIR="${EXTRACT_ROOT}/package"
if [[ ! -d "${PACKAGE_DIR}" ]]; then
  echo "install.sh: release tarball did not contain package/" >&2
  exit 1
fi

rm -rf "${PREFIX}"
mkdir -p "$(dirname "${PREFIX}")"
cp -R "${PACKAGE_DIR}" "${PREFIX}"
(
  cd "${PREFIX}"
  bun install
)

exec bun "${PREFIX}/dist/install-cli.js" --wire-only --prefix "${PREFIX}" "${WIRE_ARGS[@]+"${WIRE_ARGS[@]}"}"
