#!/usr/bin/env bash
# Thin wrapper to run ClusterFuzzLite helpers inside the OSS-Fuzz container.

export LC_ALL=C

set -o errexit -o nounset -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/test/cfl-common.sh
source "${SCRIPT_DIR}/cfl-common.sh"

if [ "${1:-}" = "" ] || [ "${2:-}" = "" ]; then
  echo "Usage: $0 <operation> <sanitizer>" >&2
  echo "  Supported operations: base-install, check-symbolizer" >&2
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
  check-symbolizer)
    image='gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1'
    ensure_image_cached "$image"
    docker run \
      "${docker_common[@]}" \
      -e "LLVM_SYMBOLIZER_PATH=${LLVM_SYMBOLIZER_PATH:-}" \
      "$image" \
      -lc "set -euo pipefail; path=\${LLVM_SYMBOLIZER_PATH:-/usr/bin/llvm-symbolizer}; if [ ! -x \"\$path\" ]; then echo \"llvm-symbolizer missing at \$path\" >&2; exit 1; fi; echo \"llvm-symbolizer present at \$path\""
    ;;
  *)
    echo "Unknown operation: ${operation}" >&2
    exit 1
    ;;
 esac
