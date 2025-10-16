#!/usr/bin/env bash
# Thin wrapper to run ClusterFuzzLite helpers inside the OSS-Fuzz container.

export LC_ALL=C

set -o errexit -o nounset -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/test/cfl-common.sh
source "${SCRIPT_DIR}/cfl-common.sh"

if [ "${1:-}" = "" ] || [ "${2:-}" = "" ]; then
  echo "Usage: $0 <base-install|build-toolchain> <sanitizer>" >&2
  exit 1
fi

operation="$1"
sanitizer="$2"
shift 2 || true

# Resolve repository root for Docker volume mounting.
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APT_VER="$(cfl_apt_llvm_version)"

mkdir -p "${ROOT_DIR}/cxx_build" "${ROOT_DIR}/.cfl-base"

docker_common=(
  --rm
  --entrypoint
  /bin/bash
  -e "SANITIZER=${sanitizer}"
  -e BASE_ROOT_DIR=/workspace/.cfl-base
  -v "${ROOT_DIR}:/workspace"
  -v "${ROOT_DIR}/cxx_build:/cxx_build"
  -w /workspace
)

case "${operation}" in
  base-install)
    packages="$(cfl_packages_for_sanitizer "${sanitizer}")"
    CI_RETRY_EXE_CMD='bash ./ci/retry/retry --'
    docker run \
      "${docker_common[@]}" \
      -e "APT_LLVM_V=${APT_VER}" \
      -e "PACKAGES=${packages}" \
      -e SKIP_LIBCPP_RUNTIME_BUILD=1 \
      -e "CI_RETRY_EXE=${CI_RETRY_EXE_CMD}" \
      gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1 \
      -lc './ci/test/01_base_install.sh'
    ;;
  build-toolchain)
    mode="$(cfl_instrumented_mode "${sanitizer}")"

    if [ -z "${mode}" ]; then
      exit 0
    fi

    packages="$(cfl_packages_for_sanitizer "${sanitizer}")"
    CI_RETRY_EXE_CMD='bash ./ci/retry/retry --'
    docker run \
      "${docker_common[@]}" \
      -e "USE_INSTRUMENTED_LIBCPP=${mode}" \
      -e "APT_LLVM_V=${APT_VER}" \
      -e "PACKAGES=${packages}" \
      -e "PIP_PACKAGES=cmake" \
      -e "CI_RETRY_EXE=${CI_RETRY_EXE_CMD}" \
      gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1 \
      -lc "rm -f /workspace/.cfl-base/ci.base-install-done; SKIP_LIBCPP_RUNTIME_BUILD=1 ./ci/test/01_base_install.sh; ./ci/test/build-instrumented-llvm.sh '${sanitizer}'"
    ;;
  *)
    echo "Unknown operation: ${operation}" >&2
    exit 1
    ;;
 esac
