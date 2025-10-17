#!/bin/sh
export LC_ALL=C

DIR="$(cd "$(dirname "$0")" && pwd)"
SYM="${DIR}/llvm-symbolizer"
if [ -x "$SYM" ]; then
  export LLVM_SYMBOLIZER_PATH="$SYM"
  export ASAN_SYMBOLIZER_PATH="$SYM"
  export MSAN_SYMBOLIZER_PATH="$SYM"
  export UBSAN_SYMBOLIZER_PATH="$SYM"
  if [ -n "${MSAN_OPTIONS:-}" ]; then
    export MSAN_OPTIONS="external_symbolizer_path=$SYM:${MSAN_OPTIONS}"
  else
    export MSAN_OPTIONS="external_symbolizer_path=$SYM"
  fi
fi
REAL_DIR="${DIR}/.fuzz-target-bin"
REAL_BIN="${REAL_DIR}/$(basename "$0")"
if [ ! -x "$REAL_BIN" ]; then
  echo "missing fuzz binary: $REAL_BIN" >&2
  exit 127
fi
exec "$REAL_BIN" "$@"
