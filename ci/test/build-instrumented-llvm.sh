#!/usr/bin/env bash
# Build an instrumented LLVM/libc++ toolchain for ClusterFuzzLite runs.

export LC_ALL=C

set -o errexit -o nounset -o pipefail -o xtrace

export PATH="${HOME}/.local/bin:${PATH}"

if [ -z "${USE_INSTRUMENTED_LIBCPP:-}" ]; then
  echo "Skipping instrumented LLVM build (USE_INSTRUMENTED_LIBCPP unset)"
  exit 0
fi

SANITIZER_CHOICE="${1:-address}"
BASE_ROOT_DIR="${BASE_ROOT_DIR:-$(pwd)/.cfl-base}"
CFL_TOOLCHAIN_STAMP_DIR="${CFL_TOOLCHAIN_STAMP_DIR:-/cxx_build}"
MAKEJOBS="${MAKEJOBS:--j$(nproc)}"
STAMP_FILE="${CFL_TOOLCHAIN_STAMP_DIR}/ci.build-instrumented-llvm-${USE_INSTRUMENTED_LIBCPP}"
LLVM_RUNTIMES="libcxx;libcxxabi;libunwind"

allow_compiler_rt_fuzzer_with_sanitizers() {
  local config_path="$1"
  local guard_regex='if (SANITIZER_COMMON_SUPPORTED_ARCH AND NOT LLVM_USE_SANITIZER AND'
  local replacement='if (SANITIZER_COMMON_SUPPORTED_ARCH AND (NOT LLVM_USE_SANITIZER OR COMPILER_RT_FORCE_ENABLE_SANITIZER_COMMON) AND'

  if grep -q "$guard_regex" "$config_path"; then
    local tmp_file
    local replaced=0
    local line
    tmp_file="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
      if [ "$replaced" -eq 0 ] && [[ "$line" == *"$guard_regex"* ]]; then
        line="${line/$guard_regex/$replacement}"
        replaced=1
      fi
      printf '%s\n' "$line"
    done <"$config_path" >"$tmp_file"
    mv "$tmp_file" "$config_path"
  fi
}

if [ -f "$STAMP_FILE" ]; then
  echo "Instrumented LLVM toolchain already built for ${USE_INSTRUMENTED_LIBCPP}"
  exit 0
fi

# compiler-rt refuses to compile when sanitizer instrumentation is enabled; scrub
# any inherited -fsanitize toggles from the environment while we build runtimes.
drop_sanitize_flags() {
  local input="$1"
  local output=()
  local token
  for token in $input; do
    case "$token" in
      -fsanitize=*|-fno-sanitize=*|-fno-sanitize-recover=*|-fno-sanitize-trap=*|-fno-sanitize-ignorelist=*)
        # compiler-rt must never be instrumented; drop sanitizer toggles entirely.
        ;;
      *)
        output+=("$token")
        ;;
    esac
  done

  printf '%s' "${output[*]}"
}

ORIG_CFLAGS="${CFLAGS-}"
ORIG_CXXFLAGS="${CXXFLAGS-}"
RESTORE_CFLAGS=0
RESTORE_CXXFLAGS=0

if [ -n "${CFLAGS+set}" ]; then
  RESTORE_CFLAGS=1
  MODIFIED_CFLAGS="$(drop_sanitize_flags "${CFLAGS}")"
  export CFLAGS="$MODIFIED_CFLAGS"
fi

if [ -n "${CXXFLAGS+set}" ]; then
  RESTORE_CXXFLAGS=1
  MODIFIED_CXXFLAGS="$(drop_sanitize_flags "${CXXFLAGS}")"
  if [ "$SANITIZER_CHOICE" = "memory" ]; then
    MODIFIED_CXXFLAGS="${MODIFIED_CXXFLAGS//-stdlib=libc++/}"
  fi
  export CXXFLAGS="$MODIFIED_CXXFLAGS"
fi

if [ -n "$USE_INSTRUMENTED_LIBCPP" ]; then
  LLVM_RUNTIMES="compiler-rt;${LLVM_RUNTIMES}"
fi

rm -rf /llvm-project
if [ ! -f "$STAMP_FILE" ] && [ -d /cxx_build ]; then
  find /cxx_build -mindepth 1 -maxdepth 1 -not -name "ci.build-instrumented-llvm-*" -exec rm -rf {} +
fi

mkdir -p /cxx_build/include/c++/v1 /cxx_build/lib

if [ -n "${CI_RETRY_EXE:-}" ]; then
  ${CI_RETRY_EXE} git clone --depth=1 https://github.com/llvm/llvm-project -b "llvmorg-21.1.3" /llvm-project
else
  git clone --depth=1 https://github.com/llvm/llvm-project -b "llvmorg-21.1.3" /llvm-project
fi

# Upstream compiler-rt skips libFuzzer when LLVM_USE_SANITIZER is set, which leaves ClusterFuzzLite
# without libclang_rt.fuzzer*.a (see job-logs-undefined.txt). Allow overriding this guard locally.
CONFIG_RT_CONFIG=/llvm-project/compiler-rt/cmake/config-ix.cmake
allow_compiler_rt_fuzzer_with_sanitizers "$CONFIG_RT_CONFIG"

cmake_args=(
  -G
  Ninja
  -B
  /cxx_build/
  "-DLLVM_ENABLE_RUNTIMES=${LLVM_RUNTIMES}"
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  -DCMAKE_C_COMPILER=clang
  -DCMAKE_CXX_COMPILER=clang++
  -DLLVM_TARGETS_TO_BUILD=Native
  -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF
  -DCOMPILER_RT_USE_LIBCXX=ON
  -DCOMPILER_RT_LIBCXX_PATH=/cxx_build/include/c++/v1
  -DCOMPILER_RT_LIBCXX_LIBRARY_PATH=/cxx_build/lib
  -DLIBCXXABI_USE_LLVM_UNWINDER=OFF
  "-DLIBCXX_ABI_DEFINES=_LIBCPP_ABI_BOUNDED_ITERATORS;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_STD_ARRAY;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_STRING;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_VECTOR;_LIBCPP_ABI_BOUNDED_UNIQUE_PTR"
  -DLIBCXX_HARDENING_MODE=debug
  -DCOMPILER_RT_BUILD_LIBFUZZER=ON
  -DCOMPILER_RT_INCLUDE_TESTS=OFF
  -DCOMPILER_RT_FORCE_ENABLE_SANITIZER_COMMON=ON
  -DCOMPILER_RT_BUILD_SHARED_SANITIZERS=OFF
  "-DRUNTIMES_compiler-rt_CMAKE_ARGS=-DLLVM_USE_SANITIZER=Off"
  "-DRUNTIMES_libcxx_CMAKE_ARGS=-DLLVM_USE_SANITIZER=${USE_INSTRUMENTED_LIBCPP}"
  "-DRUNTIMES_libcxxabi_CMAKE_ARGS=-DLLVM_USE_SANITIZER=${USE_INSTRUMENTED_LIBCPP}"
  "-DRUNTIMES_libunwind_CMAKE_ARGS=-DLLVM_USE_SANITIZER=${USE_INSTRUMENTED_LIBCPP}"
  -S
  /llvm-project/runtimes
)

cmake "${cmake_args[@]}"

ninja -C /cxx_build/ -t vars COMPILER_RT_BUILD_LIBFUZZER || true
cmake -LA -N /cxx_build | grep -E 'HAS_FUZZER|FUZZER|LIBCXX' || true

ninja -C /cxx_build/ "$MAKEJOBS"

mapfile -t NINJA_TARGET_LINES < <(ninja -C /cxx_build -t targets)

FUZZER_BUILD_TARGETS=()
FUZZER_COMPONENT_TARGET=""
for line in "${NINJA_TARGET_LINES[@]}"; do
  target="${line%%:*}"
  case "$target" in
    clang_rt.fuzzer*)
      FUZZER_BUILD_TARGETS+=("$target")
      ;;
    fuzzer|compiler-rt-fuzzer)
      FUZZER_COMPONENT_TARGET="${FUZZER_COMPONENT_TARGET:-$target}"
      ;;
  esac
done

if [ "${#FUZZER_BUILD_TARGETS[@]}" -gt 0 ]; then
  cmake --build /cxx_build --target "${FUZZER_BUILD_TARGETS[@]}" --parallel
elif [ -n "$FUZZER_COMPONENT_TARGET" ]; then
  echo "No explicit clang_rt.fuzzer* ninja targets; building component target ${FUZZER_COMPONENT_TARGET}"
  cmake --build /cxx_build --target "$FUZZER_COMPONENT_TARGET" --parallel
else
  echo "No explicit clang_rt.fuzzer* targets exported; assuming default runtime build produced the archives"
fi

mapfile -d '' FUZZER_ARCHIVES < <(find /cxx_build -maxdepth 8 -type f -name 'libclang_rt.fuzzer*.a' -print0)

if [ "${#FUZZER_ARCHIVES[@]}" -eq 0 ]; then
  echo "Failed to locate libclang_rt.fuzzer archives in /cxx_build" >&2
  if [ -f /cxx_build/compiler-rt/CMakeFiles/CMakeError.log ]; then
    echo "--- compiler-rt CMakeError.log (libFuzzer excerpt) ---" >&2
    grep -n "fuzzer" /cxx_build/compiler-rt/CMakeFiles/CMakeError.log >&2 || true
  fi
  if [ -n "$FUZZER_COMPONENT_TARGET" ]; then
    echo "Checked ninja component target: $FUZZER_COMPONENT_TARGET" >&2
  fi
  if [ "${#FUZZER_BUILD_TARGETS[@]}" -gt 0 ]; then
    printf 'Checked explicit ninja targets: %s\n' "${FUZZER_BUILD_TARGETS[*]}" >&2
  fi
  exit 1
fi

# Ensure libclang_rt.fuzzer archives are staged where ClusterFuzzLite searches for them.
for runtime_dir in /cxx_build/compiler-rt/lib/linux /cxx_build/lib; do
  install -d "$runtime_dir"
  for archive in "${FUZZER_ARCHIVES[@]}"; do
    dest="$runtime_dir/$(basename "$archive")"
    if [ "$archive" -ef "$dest" ]; then
      continue
    fi
    install -m 0644 "$archive" "$runtime_dir/"
  done
done

rm -rf /llvm-project
mkdir -p "${CFL_TOOLCHAIN_STAMP_DIR}" "$(dirname "$STAMP_FILE")"
echo "${USE_INSTRUMENTED_LIBCPP}" > "$STAMP_FILE"

if [ "$RESTORE_CFLAGS" -eq 1 ]; then
  export CFLAGS="$ORIG_CFLAGS"
else
  unset CFLAGS || true
fi

if [ "$RESTORE_CXXFLAGS" -eq 1 ]; then
  export CXXFLAGS="$ORIG_CXXFLAGS"
else
  unset CXXFLAGS || true
fi
