#!/usr/bin/env bash
# Shared helpers for ClusterFuzzLite scripts.

export LC_ALL=C

cfl_apt_llvm_version() {
  printf '%s' "${APT_LLVM_V:-21}"
}

cfl_llvm_packages() {
  local ver
  ver="$(cfl_apt_llvm_version)"
  printf 'clang-%s llvm-%s llvm-%s-dev libclang-%s-dev libclang-rt-%s-dev' "$ver" "$ver" "$ver" "$ver" "$ver"
}

cfl_libcxx_packages() {
  local ver
  ver="$(cfl_apt_llvm_version)"
  printf 'libc++-%s-dev libc++1-%s libc++abi-%s-dev libc++abi1-%s libunwind-%s-dev' "$ver" "$ver" "$ver" "$ver" "$ver"
}

cfl_packages_for_sanitizer() {
  local sanitizer="${1:-address}"
  local llvm_pkg libcxx_pkg packages
  llvm_pkg="$(cfl_llvm_packages)"
  libcxx_pkg="$(cfl_libcxx_packages)"
  packages="$llvm_pkg"
  if [ "$sanitizer" != "memory" ]; then
    packages+=" $libcxx_pkg"
  fi
  packages+=" ninja-build make cmake"
  printf '%s' "$packages"
}

cfl_instrumented_mode() {
  local sanitizer="${1:-address}"
  case "$sanitizer" in
    memory)
      printf '%s' "MemoryWithOrigins"
      ;;
    address)
      printf '%s' "Address"
      ;;
    undefined|integer)
      printf '%s' "Undefined"
      ;;
    *)
      printf '%s' ''
      ;;
  esac
}
