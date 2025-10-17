#!/usr/bin/env bash

export LC_ALL=C
set -eu

date

cd "$SRC/sv2-tp"

# Reuse a repository-local cache by default so helper runs can share state with
# the workflow containers. Callers may override BASE_ROOT_DIR explicitly.
BASE_ROOT_DIR="${BASE_ROOT_DIR:-${PWD}/.cfl-base}"
mkdir -p "$BASE_ROOT_DIR"
export BASE_ROOT_DIR
export CI_RETRY_EXE="${CI_RETRY_EXE:-bash ./ci/retry/retry --}"
export APT_LLVM_V="${APT_LLVM_V:-21}"
SANITIZER_CHOICE="${SANITIZER:-address}"
CUSTOM_LIBCPP=0
INSTRUMENTED_LIBCPP_MODE=""
SKIP_CFL_SETUP_FLAG="${SKIP_CFL_SETUP:-false}"
EXPECTED_SYMBOLIZER="${LLVM_SYMBOLIZER_PATH:-/usr/local/bin/llvm-symbolizer}"

# shellcheck source=ci/test/cfl-common.sh
source ./ci/test/cfl-common.sh
# shellcheck source=.clusterfuzzlite/symbolizer.sh
source ./.clusterfuzzlite/symbolizer.sh

bootstrap_instrumented_llvm() {
  local mode="$1"
  local sanitizer="$2"

  if [ -z "$mode" ]; then
    return
  fi

  export USE_INSTRUMENTED_LIBCPP="$mode"
  ./ci/test/build-instrumented-llvm.sh "$sanitizer"
}

INSTRUMENTED_LIBCPP_MODE="$(cfl_instrumented_mode "$SANITIZER_CHOICE")"
if [ -n "$INSTRUMENTED_LIBCPP_MODE" ]; then
  CUSTOM_LIBCPP=1
  export USE_INSTRUMENTED_LIBCPP="$INSTRUMENTED_LIBCPP_MODE"
else
  unset USE_INSTRUMENTED_LIBCPP
fi

if [ -z "${PACKAGES:-}" ]; then
  packages_value="$(cfl_packages_for_sanitizer "$SANITIZER_CHOICE")"
  export PACKAGES="$packages_value"
else
  export PACKAGES
fi

if [ "$CUSTOM_LIBCPP" -eq 1 ]; then
  INSTRUMENTED_LIBCPP_MODE="${USE_INSTRUMENTED_LIBCPP:-}"
  TOOLCHAIN_STAMP_DIR="${CFL_TOOLCHAIN_STAMP_DIR:-/cxx_build}"
  TOOLCHAIN_STAMP="${TOOLCHAIN_STAMP_DIR}/ci.build-instrumented-llvm-${INSTRUMENTED_LIBCPP_MODE}"
  TOOLCHAIN_STAMP_BASENAME="$(basename "$TOOLCHAIN_STAMP")"
  # Allow callers to force a specific cache mount; otherwise probe the common
  # host locations used by our helper containers and the GitHub Action.
  HOST_TOOLCHAIN_DIR="${CFL_HOST_TOOLCHAIN_DIR:-}"

  if [ -z "$HOST_TOOLCHAIN_DIR" ]; then
    BASE_PARENT_DIR="$(dirname "${BASE_ROOT_DIR%/}")"
    CANDIDATE_DIRS=()

    if [ -n "$BASE_PARENT_DIR" ]; then
      CANDIDATE_DIRS+=("${BASE_PARENT_DIR%/}/cxx_build")
    fi
    if [ -n "${GITHUB_WORKSPACE:-}" ]; then
      CANDIDATE_DIRS+=("${GITHUB_WORKSPACE%/}/cxx_build")
    fi
    if [ -n "${PROJECT_SRC_PATH:-}" ]; then
      CANDIDATE_DIRS+=("${PROJECT_SRC_PATH%/}/cxx_build")
    fi

    CANDIDATE_DIRS+=(
      "/workspace/cxx_build"
      "/github/workspace/cxx_build"
      "/github/workspace/storage/sv2-tp/cxx_build"
    )

    for candidate in "${CANDIDATE_DIRS[@]}"; do
      [ -n "$candidate" ] || continue
      if [ -d "$candidate" ] || [ -f "${candidate}/${TOOLCHAIN_STAMP_BASENAME}" ]; then
        HOST_TOOLCHAIN_DIR="$candidate"
        break
      fi
    done
  fi

  if [ -n "$HOST_TOOLCHAIN_DIR" ] \
    && [ -d "$HOST_TOOLCHAIN_DIR" ] \
    && [ -f "${HOST_TOOLCHAIN_DIR}/${TOOLCHAIN_STAMP_BASENAME}" ] \
    && [ ! -f "$TOOLCHAIN_STAMP" ]; then
    mkdir -p "$TOOLCHAIN_STAMP_DIR"
    cp -a "${HOST_TOOLCHAIN_DIR}/." "$TOOLCHAIN_STAMP_DIR/"
  fi

  export SKIP_LIBCPP_RUNTIME_BUILD=1
  unset USE_INSTRUMENTED_LIBCPP || true
fi

if [ "$SKIP_CFL_SETUP_FLAG" = "true" ] && [ -f "${BASE_ROOT_DIR}/ci.base-install-done" ]; then
  echo "Skipping base install (already performed upstream)."
else
  ./ci/test/01_base_install.sh
fi

ensure_symbolizer_available

PRE_BUNDLE_DIR="$(mktemp -d)"
if bundle_symbolizer "$PRE_BUNDLE_DIR" "preflight"; then
  rm -rf "$PRE_BUNDLE_DIR"
else
  rm -rf "$PRE_BUNDLE_DIR"
  exit 1
fi

if [ "$CUSTOM_LIBCPP" -eq 1 ]; then
  unset SKIP_LIBCPP_RUNTIME_BUILD || true
  if [ ! -f "$TOOLCHAIN_STAMP" ]; then
    bootstrap_instrumented_llvm "$INSTRUMENTED_LIBCPP_MODE" "$SANITIZER_CHOICE"
    if [ -n "$HOST_TOOLCHAIN_DIR" ]; then
      mkdir -p "$HOST_TOOLCHAIN_DIR"
      cp -a "${TOOLCHAIN_STAMP_DIR}/." "$HOST_TOOLCHAIN_DIR/"
    fi
  else
    if [ "$SKIP_CFL_SETUP_FLAG" = "true" ]; then
      echo "Using prebuilt instrumented toolchain for mode '$INSTRUMENTED_LIBCPP_MODE'."
    fi
    export USE_INSTRUMENTED_LIBCPP="$INSTRUMENTED_LIBCPP_MODE"
  fi
fi

export BUILD_TRIPLET="x86_64-pc-linux-gnu"
export CFLAGS="${CFLAGS:-} -flto=full"
export CXXFLAGS="${CXXFLAGS:-} -flto=full"
export LDFLAGS="-fuse-ld=lld -flto=full ${LDFLAGS:-}"
export CPPFLAGS="${CPPFLAGS:-} -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG"
FUZZ_LIBS_VALUE="$LIB_FUZZING_ENGINE"
CUSTOM_LIBCPP_LIB_PATH=""

if [ "$CUSTOM_LIBCPP" -eq 1 ]; then
  LIBCXX_DIR="${LIBCXX_DIR:-/cxx_build/}"
  LIBCXX_INCLUDE_DIR="${LIBCXX_DIR}include/c++/v1"
  LIBCXX_LIB_DIR="${LIBCXX_DIR}lib"
  LIBCXX_FLAGS="-nostdinc++ -nostdlib++ -isystem ${LIBCXX_INCLUDE_DIR} -L${LIBCXX_LIB_DIR} -Wl,-rpath,${LIBCXX_LIB_DIR} -Wl,-rpath,\$ORIGIN -lc++ -lc++abi -lpthread -Wno-unused-command-line-argument"

  if [ "$SANITIZER_CHOICE" = "memory" ]; then
    MSAN_EXTRA_FLAGS="-fsanitize-memory-track-origins=2 -fno-optimize-sibling-calls"
    export CFLAGS="${CFLAGS} ${MSAN_EXTRA_FLAGS}"
    export CXXFLAGS="${CXXFLAGS} ${MSAN_EXTRA_FLAGS}"
  fi

  export CXXFLAGS="${CXXFLAGS} ${LIBCXX_FLAGS}"
  export LDFLAGS="${LDFLAGS} ${LIBCXX_FLAGS}"
  CUSTOM_LIBCPP_LIB_PATH="$LIBCXX_LIB_DIR"

  CLANG_BIN="clang-${APT_LLVM_V}"
  if ! command -v "$CLANG_BIN" >/dev/null 2>&1; then
    CLANG_BIN="clang"
  fi

  FUZZ_RUNTIME_CANDIDATE=""
  # Compiler-rt leaves sanitized libclang_rt archives in its own tree; probe
  # both the libc++ lib dir and compiler-rt output before falling back.
  RUNTIME_BASE_DIRS=(
    "${LIBCXX_LIB_DIR}/linux"
    "/cxx_build/compiler-rt/lib/linux"
    "/cxx_build/lib/linux"
    "/cxx_build/lib"
  )

  for runtime_base in "${RUNTIME_BASE_DIRS[@]}"; do
    [ -d "$runtime_base" ] || continue

    RUNTIME_CANDIDATES=("${runtime_base}/libclang_rt.fuzzer-x86_64.a")

    case "$SANITIZER_CHOICE" in
      memory)
        RUNTIME_CANDIDATES=(
          "${runtime_base}/libclang_rt.fuzzer-msan-x86_64.a"
          "${RUNTIME_CANDIDATES[@]}"
        )
        ;;
      address)
        RUNTIME_CANDIDATES=(
          "${runtime_base}/libclang_rt.fuzzer-asan-x86_64.a"
          "${RUNTIME_CANDIDATES[@]}"
        )
        ;;
      undefined|integer)
        RUNTIME_CANDIDATES=(
          "${runtime_base}/libclang_rt.fuzzer-ubsan_standalone-x86_64.a"
          "${runtime_base}/libclang_rt.fuzzer-ubsan-x86_64.a"
          "${RUNTIME_CANDIDATES[@]}"
        )
        ;;
    esac

    for candidate in "${RUNTIME_CANDIDATES[@]}"; do
      if [ -f "$candidate" ]; then
        FUZZ_RUNTIME_CANDIDATE="$candidate"
        break 2
      fi
    done
  done

  if [ -z "$FUZZ_RUNTIME_CANDIDATE" ]; then
    # Compiler-rt sometimes shuffles runtime paths between releases; fall back to
    # a broader search before using the system-provided archive.
  mapfile -t FOUND_RUNTIMES < <(find /cxx_build -maxdepth 8 -type f -name 'libclang_rt.fuzzer*.a' 2>/dev/null | sort)
    if [ ${#FOUND_RUNTIMES[@]} -gt 0 ]; then
      case "$SANITIZER_CHOICE" in
        memory)
          PREFERRED_SUFFIXES=(fuzzer-msan fuzzer_msan fuzzer)
          ;;
        address)
          PREFERRED_SUFFIXES=(fuzzer-asan fuzzer)
          ;;
        undefined|integer)
          PREFERRED_SUFFIXES=(fuzzer-ubsan_standalone fuzzer-ubsan fuzzer)
          ;;
        *)
          PREFERRED_SUFFIXES=(fuzzer)
          ;;
      esac

      for suffix in "${PREFERRED_SUFFIXES[@]}"; do
        for candidate in "${FOUND_RUNTIMES[@]}"; do
          case "$candidate" in
            *"${suffix}"*.a)
              FUZZ_RUNTIME_CANDIDATE="$candidate"
              break 2
              ;;
          esac
        done
      done

      if [ -z "$FUZZ_RUNTIME_CANDIDATE" ]; then
        FUZZ_RUNTIME_CANDIDATE="${FOUND_RUNTIMES[0]}"
      fi
    fi
  fi

  if [ -z "$FUZZ_RUNTIME_CANDIDATE" ]; then
    FALLBACK_RUNTIME="$("$CLANG_BIN" -print-file-name=libclang_rt.fuzzer-x86_64.a)"
    if [ -n "$FALLBACK_RUNTIME" ] && [ -f "$FALLBACK_RUNTIME" ]; then
      FUZZ_RUNTIME_CANDIDATE="$FALLBACK_RUNTIME"
    fi
  fi

  if [ -n "$FUZZ_RUNTIME_CANDIDATE" ]; then
    FUZZ_LIBS_VALUE="$FUZZ_RUNTIME_CANDIDATE"
  fi
fi

if [ "$CUSTOM_LIBCPP" -eq 1 ] && [ "$FUZZ_LIBS_VALUE" = "$LIB_FUZZING_ENGINE" ]; then
  FUZZ_LIBS_VALUE="${LIB_FUZZING_ENGINE};-lstdc++"
fi

DEPENDS_PREFIX_DIR="depends/${BUILD_TRIPLET}"
DEPENDS_TOOLCHAIN_PATH="${DEPENDS_PREFIX_DIR}/toolchain.cmake"
DEPENDS_STAMP_PRESENT=0

if [ -d "$DEPENDS_PREFIX_DIR" ] && [ -f "$DEPENDS_TOOLCHAIN_PATH" ]; then
  if find "$DEPENDS_PREFIX_DIR" -maxdepth 1 -type f -name '.stamp_*' -print -quit >/dev/null 2>&1; then
    DEPENDS_STAMP_PRESENT=1
  fi
fi

NEED_DEPENDS_BUILD=1
if [ "${FORCE_DEPENDS_BUILD:-0}" = "1" ]; then
  NEED_DEPENDS_BUILD=1
elif [ "$DEPENDS_STAMP_PRESENT" -eq 1 ]; then
  echo "Using cached depends outputs at ${DEPENDS_PREFIX_DIR}; skipping depends make step."
  NEED_DEPENDS_BUILD=0
fi

export DEPENDS_LOG_VERBOSE=

if [ "$NEED_DEPENDS_BUILD" -eq 1 ]; then
  (
    cd depends
    sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk || true

    # Mirror the MSan depends invocation from ci/test/00_setup_env_native_fuzz_with_msan.sh
    # so that dependencies pick up the sanitizer-friendly toolchain.
    make \
      HOST=$BUILD_TRIPLET \
      DEBUG=1 \
      NO_IPC=1 \
      LOG=1 \
      CC=clang \
      CXX=clang++ \
      CFLAGS="$CFLAGS" \
      CXXFLAGS="$CXXFLAGS" \
      AR=llvm-ar \
      NM=llvm-nm \
      RANLIB=llvm-ranlib \
      STRIP=llvm-strip \
      -j"$(nproc)"
  )
fi

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_CLUSTERFUZZLITE|g" ./src/test/fuzz/CMakeLists.txt || true

EXTRA_CMAKE_ARGS=()
if [ "$SANITIZER_CHOICE" = "memory" ]; then
  EXTRA_CMAKE_ARGS+=("-DAPPEND_CPPFLAGS=-U_FORTIFY_SOURCE")
fi

cmake -B build_fuzz \
  --toolchain "depends/${BUILD_TRIPLET}/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DBUILD_FOR_FUZZING=ON \
  -DBUILD_FUZZ_BINARY=ON \
  -DFUZZ_LIBS="$FUZZ_LIBS_VALUE" \
  -DSANITIZERS="$SANITIZER_CHOICE" \
  "${EXTRA_CMAKE_ARGS[@]}"

cmake --build build_fuzz -j"$(nproc)"

# First execution happens inside the build container so we can enumerate targets before bundling.
# The later "bad build" replay runs in a stripped sandbox with only bundled files, so passing here
# doesn't guarantee libs/symbolizers are packaged correctly—that check happens post-bundle.
WRITE_ALL_FUZZ_TARGETS_AND_ABORT="$WORK/fuzz_targets.txt" ./build_fuzz/bin/fuzz || true
readarray -t FUZZ_TARGETS < "$WORK/fuzz_targets.txt" || FUZZ_TARGETS=()

if [ ${#FUZZ_TARGETS[@]} -eq 0 ]; then
  echo "no fuzz targets discovered" >&2
  exit 1
fi

# Must match FuzzTargetPlaceholder in src/test/fuzz/fuzz.cpp so the python
# patching below can locate the placeholder string.
MAGIC_STR="d6f1a2b39c4e5d7a8b9c0d1e2f30415263748596a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00fedcba9876543210a0b1c2d3"

for fuzz_target in "${FUZZ_TARGETS[@]}"; do
  [ -z "$fuzz_target" ] && continue
  python3 - << PY
c_str_target=b"${fuzz_target}\x00"
c_str_magic=b"$MAGIC_STR"
with open('./build_fuzz/bin/fuzz','rb') as f:
    dat=f.read()
dat=dat.replace(c_str_magic, c_str_target + c_str_magic[len(c_str_target):])
with open("$OUT/${fuzz_target}", 'wb') as g:
    g.write(dat)
PY
  chmod +x "$OUT/${fuzz_target}"

  corpus_dir="assets/fuzz_corpora/${fuzz_target}"
  if [ -d "$corpus_dir" ] && find "$corpus_dir" -type f -print -quit >/dev/null 2>&1; then
    (
      cd "$corpus_dir"
      zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" .
    )
  fi

done

if [ "$CUSTOM_LIBCPP" -eq 1 ] && [ -n "$CUSTOM_LIBCPP_LIB_PATH" ]; then
  # Ensure the custom libc++ runtime is available when bad build checks replay targets.
  for pattern in libc++.so* libc++abi.so* libunwind.so*; do
    for source in "${CUSTOM_LIBCPP_LIB_PATH}"/${pattern}; do
      [ -e "$source" ] || continue
      cp -a "$source" "$OUT/"
    done
  done

  for lib in libc++ libc++abi libunwind; do
    for suffix in .so.1 .so; do
      src="${CUSTOM_LIBCPP_LIB_PATH}/${lib}${suffix}"
      dest="$OUT/${lib}${suffix}"
      if [ -e "$src" ] && [ ! -e "$dest" ]; then
        cp -a "$src" "$OUT/"
      fi
    done
  done
fi

# Bad build checks re-run the packaged binary in that minimal sandbox; ship the symbolizer beside it.
bundle_symbolizer "$OUT"
# Leave a marker so sandboxed bad-build checks can recognise ClusterFuzzLite bundles.
: >"$OUT/.sv2-clusterfuzzlite"

if [ -d assets/fuzz_dicts ]; then
  find assets/fuzz_dicts -maxdepth 1 -type f -name '*.dict' -exec cp {} "$OUT/" \;
fi

if [ -d "$OUT" ]; then
  echo "ClusterFuzzLite bundle tree (find $OUT -maxdepth 2):"
  find "$OUT" -maxdepth 2 -print | sort
fi
