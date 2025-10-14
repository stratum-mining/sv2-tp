#!/usr/bin/env bash

export LC_ALL=C
set -eu

date

cd "$SRC/sv2-tp"

export BUILD_TRIPLET="x86_64-pc-linux-gnu"
export CFLAGS="${CFLAGS:-} -flto=full"
export CXXFLAGS="${CXXFLAGS:-} -flto=full"
export LDFLAGS="-fuse-ld=lld -flto=full ${LDFLAGS:-}"
export CPPFLAGS="${CPPFLAGS:-} -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG"

(
  cd depends
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk || true

  # Mirror the MSan depends invocation from ci/test/00_setup_env_native_fuzz_with_msan.sh
  # so that dependencies pick up the sanitizer-friendly toolchain.
  make \
    HOST=$BUILD_TRIPLET \
    DEBUG=1 \
    NO_IPC=1 \
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

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_CLUSTERFUZZLITE|g" ./src/test/fuzz/CMakeLists.txt || true

EXTRA_CMAKE_ARGS=()
if [ "${SANITIZER:-address}" = "memory" ]; then
  EXTRA_CMAKE_ARGS+=("-DAPPEND_CPPFLAGS=-U_FORTIFY_SOURCE")
fi

cmake -B build_fuzz \
  --toolchain "depends/${BUILD_TRIPLET}/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DBUILD_FOR_FUZZING=ON \
  -DBUILD_FUZZ_BINARY=ON \
  -DFUZZ_LIBS="$LIB_FUZZING_ENGINE" \
  -DSANITIZERS="${SANITIZER:-address}" \
  "${EXTRA_CMAKE_ARGS[@]}"

cmake --build build_fuzz -j"$(nproc)"

WRITE_ALL_FUZZ_TARGETS_AND_ABORT="$WORK/fuzz_targets.txt" ./build_fuzz/bin/fuzz || true
readarray -t FUZZ_TARGETS < "$WORK/fuzz_targets.txt" || FUZZ_TARGETS=()

if [ ${#FUZZ_TARGETS[@]} -eq 0 ]; then
  echo "no fuzz targets discovered" >&2
  exit 1
fi

MAGIC_STR="d6f1a2b39c4e5d7a8b9c0d1e2f30415263748596a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00fedcba9876543210a0b1c2d3"
sed -i "s|std::getenv(\"FUZZ\")|\"$MAGIC_STR\"|g" ./src/test/fuzz/fuzz.cpp
cmake --build build_fuzz -j"$(nproc)"

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

if [ -d assets/fuzz_dicts ]; then
  find assets/fuzz_dicts -maxdepth 1 -type f -name '*.dict' -exec cp {} "$OUT/" \;
fi
