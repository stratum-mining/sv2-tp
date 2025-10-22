#!/usr/bin/env bash
# Thin wrapper to run ClusterFuzzLite helpers inside the OSS-Fuzz container.

export LC_ALL=C

set -o errexit -o nounset -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/test/cfl-common.sh
source "${SCRIPT_DIR}/cfl-common.sh"

if [ "${1:-}" = "" ] || [ "${2:-}" = "" ]; then
  echo "Usage: $0 <operation> <sanitizer>" >&2
  echo "  Supported operations: base-install, detect-symbolizer" >&2
  exit 1
fi

operation="$1"
sanitizer="$2"
shift 2 || true

# Resolve repository root for Docker volume mounting.
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APT_VER="$(cfl_apt_llvm_version)"

mkdir -p "${ROOT_DIR}/.cfl-base" "${ROOT_DIR}/.cfl-ccache"

CCACHE_DIR_IN_CONTAINER="${CCACHE_DIR:-/workspace/.cfl-ccache}"

docker_common=(
  --rm
  --entrypoint
  /bin/bash
  -e "SANITIZER=${sanitizer}"
  -e BASE_ROOT_DIR=/workspace/.cfl-base
  -v "${ROOT_DIR}:/workspace"
  -w /workspace
)

docker_common+=(
  -v "${ROOT_DIR}/.cfl-ccache:${CCACHE_DIR_IN_CONTAINER}"
  -e "CCACHE_DIR=${CCACHE_DIR_IN_CONTAINER}"
)

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
  base-install)
    packages="$(cfl_packages_for_sanitizer "${sanitizer}")"
    CI_RETRY_EXE_CMD='bash ./ci/retry/retry --'
    image='gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1'
    ensure_image_cached "$image"
    docker run \
      "${docker_common[@]}" \
      -e "APT_LLVM_V=${APT_VER}" \
      -e "PACKAGES=${packages}" \
      -e "CI_RETRY_EXE=${CI_RETRY_EXE_CMD}" \
      "$image" \
      -lc './ci/test/01_base_install.sh'
    ;;
  detect-symbolizer)
    image='gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1'
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
