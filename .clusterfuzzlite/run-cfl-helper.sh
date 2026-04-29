#!/usr/bin/env bash
# Thin wrapper to run ClusterFuzzLite helpers inside the OSS-Fuzz container.

export LC_ALL=C

set -o errexit -o nounset -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "" ] || [ "${2:-}" = "" ]; then
  echo "Usage: $0 detect-symbolizer <sanitizer>" >&2
  exit 1
fi

operation="$1"
sanitizer="$2"
shift 2 || true

# Resolve repository root for Docker volume mounting.
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

mkdir -p "${ROOT_DIR}/.cfl-base"

docker_common=(
  --rm
  --entrypoint
  /bin/bash
  -e "SANITIZER=${sanitizer}"
  -e BASE_ROOT_DIR=/workspace/.cfl-base
  -v "${ROOT_DIR}:/workspace"
  -w /workspace
)

if [ -n "${CCACHE_DIR:-}" ]; then
  docker_common+=(-e "CCACHE_DIR=${CCACHE_DIR}")
fi
if [ -n "${CCACHE_MAXSIZE:-}" ]; then
  docker_common+=(-e "CCACHE_MAXSIZE=${CCACHE_MAXSIZE}")
fi

# Ensure the base image is quietly available to avoid progress spam from implicit pulls.
ensure_image_cached() {
  local image="$1"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull --quiet "$image"
  fi
}

case "${operation}" in
  detect-symbolizer)
    image='gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:ubuntu-24-04-v1'
    ensure_image_cached "$image"
    docker run \
      "${docker_common[@]}" \
      -e "LLVM_SYMBOLIZER_PATH=${LLVM_SYMBOLIZER_PATH:-}" \
      "$image" \
      -lc "set -euo pipefail; desired=\${LLVM_SYMBOLIZER_PATH:-}; if [ -n \"\$desired\" ] && [ -x \"\$desired\" ]; then printf '%s\n' \"\$desired\"; exit 0; fi; found=\$(command -v llvm-symbolizer || true); if [ -n \"\$found\" ] && [ -x \"\$found\" ]; then printf '%s\n' \"\$found\"; exit 0; fi; for candidate in /usr/lib/llvm-*/bin/llvm-symbolizer /usr/local/bin/llvm-symbolizer /opt/llvm/bin/llvm-symbolizer; do if [ -x \"\$candidate\" ]; then printf '%s\n' \"\$candidate\"; exit 0; fi; done; echo 'llvm-symbolizer missing in container' >&2; exit 1"
    ;;
  *)
    echo "Unknown operation: ${operation}" >&2
    exit 1
    ;;
esac
