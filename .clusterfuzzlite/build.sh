#!/usr/bin/env bash

export LC_ALL=C
set -eu

date

cd "$SRC/sv2-tp"

SANITIZER_CHOICE="${SANITIZER:-address}"

# Surface ClusterFuzzLite-provided toolchain flags for visibility and auditing.
echo "[cfl] toolchain env:" >&2
echo "  CC=${CC:-}"
echo "  CXX=${CXX:-}"
echo "  CFLAGS=${CFLAGS:-}"
echo "  CXXFLAGS=${CXXFLAGS:-}"
echo "  LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:-}"
echo "  SANITIZER=${SANITIZER:-}"

export BUILD_TRIPLET="x86_64-pc-linux-gnu"
export CFLAGS="${CFLAGS:-} -flto=full"
export CXXFLAGS="${CXXFLAGS:-} -flto=full"
export LDFLAGS="-fuse-ld=lld -flto=full ${LDFLAGS:-}"
export CPPFLAGS="${CPPFLAGS:-} -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG"

FUZZ_LIBS_VALUE="$LIB_FUZZING_ENGINE"

if [ "$SANITIZER_CHOICE" = "coverage" ]; then
  export CFLAGS="${CFLAGS} -fprofile-instr-generate -fcoverage-mapping"
  export CXXFLAGS="${CXXFLAGS} -fprofile-instr-generate -fcoverage-mapping"
  export LDFLAGS="${LDFLAGS} -fprofile-instr-generate"
fi

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

EXTRA_CMAKE_ARGS=()
if [ "$SANITIZER_CHOICE" = "memory" ]; then
  EXTRA_CMAKE_ARGS+=("-DAPPEND_CPPFLAGS=-U_FORTIFY_SOURCE")
fi

cmake -B build_fuzz \
  --toolchain "depends/${BUILD_TRIPLET}/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="${CC:-clang}" \
  -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_C_FLAGS="${CFLAGS:-}" \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS:-}" \
  -DBUILD_FOR_FUZZING=ON \
  -DBUILD_FUZZ_BINARY=ON \
  -DFUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION=ON \
  -DFUZZ_LIBS="${FUZZ_LIBS_VALUE:-${LIB_FUZZING_ENGINE:-}}" \
  -DSANITIZERS="$SANITIZER_CHOICE" \
  -DCMAKE_VERBOSE_MAKEFILE=ON \
  "${EXTRA_CMAKE_ARGS[@]}"

cmake --build build_fuzz -j"$(nproc)"

# First execution happens inside the build container so we can enumerate targets before bundling.
# The later "bad build" replay runs in a stripped sandbox with only bundled files, so passing here
# doesn't guarantee all runtime artefacts are packaged correctly—that check happens post-bundle.
WRITE_ALL_FUZZ_TARGETS_AND_ABORT="$WORK/fuzz_targets.txt" ./build_fuzz/bin/fuzz || true
readarray -t FUZZ_TARGETS < "$WORK/fuzz_targets.txt" || FUZZ_TARGETS=()

if [ ${#FUZZ_TARGETS[@]} -eq 0 ]; then
  echo "no fuzz targets discovered" >&2
  exit 1
fi

# Expose the discovered targets to the run-fuzzers container.
cp "$WORK/fuzz_targets.txt" "$OUT/fuzz_targets.txt"

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

# Leave a marker so sandboxed bad-build checks can recognise ClusterFuzzLite bundles.
: >"$OUT/.sv2-clusterfuzzlite"

if [ -d assets/fuzz_dicts ]; then
  find assets/fuzz_dicts -maxdepth 1 -type f -name '*.dict' -exec cp {} "$OUT/" \;
fi

if [ -d "$OUT" ]; then
  echo "ClusterFuzzLite bundle tree (find $OUT -maxdepth 2):"
  find "$OUT" -maxdepth 2 -print | sort
fi

# Mirror sources under $OUT for llvm-cov HTML generation.
OUT_SRC_ROOT="$OUT/src/sv2-tp"
mkdir -p "$OUT_SRC_ROOT"
rsync -a \
  --delete \
  --exclude '.git/' \
  --exclude '.github/' \
  --exclude '.clusterfuzzlite/' \
  --exclude 'build_fuzz/' \
  --exclude 'depends/' \
  --exclude 'coverage-html/' \
  --exclude 'coverage-out/' \
  --exclude 'coverage-storage/' \
  ./ "$OUT_SRC_ROOT/"
