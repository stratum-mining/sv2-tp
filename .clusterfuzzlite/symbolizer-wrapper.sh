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
exec "${DIR}/$(basename "$0").bin" "$@"
