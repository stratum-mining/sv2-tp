#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
cd "${REPO_ROOT}"

# Keep native Windows paths and command-line options unchanged under MSYS.
export MSYS_NO_PATHCONV=1

case "${1:-}" in
    build-sv2-tp)
        cmake --preset dev-mode -DCMAKE_BUILD_TYPE=Debug -B build \
            -G "Ninja Multi-Config" -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl \
            -DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache \
            -DCMAKE_POLICY_DEFAULT_CMP0141=NEW -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded \
            "-DCMAKE_TOOLCHAIN_FILE=$(cygpath -m "${VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/vcpkg.cmake")" \
            -DVCPKG_TARGET_TRIPLET=x64-windows -DBUILD_FUZZ_BINARY=OFF
        cmake --build build --config Debug --target sv2-tp -j 4
        ;;
    test-sv2-tp)
        cmake --build build --config Debug --target test_sv2 -j 4
        ./build/bin/Debug/test_sv2.exe -l test_suite
        ;;
    build-bitcoin-core)
        cmake --preset dev-mode -DCMAKE_BUILD_TYPE=Debug \
            -S sri-integration-test/bitcoin-core-source -B sri-integration-test/bitcoin-core-build \
            -G "Ninja Multi-Config" -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl \
            -DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache \
            -DCMAKE_POLICY_DEFAULT_CMP0141=NEW -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded \
            "-DCMAKE_TOOLCHAIN_FILE=$(cygpath -m "${VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/vcpkg.cmake")" \
            -DVCPKG_TARGET_TRIPLET=x64-windows -DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON \
            "-DVCPKG_MANIFEST_FEATURES=ipc;wallet" \
            -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF \
            -DBUILD_SHARED_LIBS=OFF -DBUILD_KERNEL_LIB=OFF -DBUILD_UTIL_CHAINSTATE=OFF \
            -DWITH_ZMQ=OFF -DWITH_QRENCODE=OFF -DWITH_USDT=OFF
        cmake --build sri-integration-test/bitcoin-core-build --config Debug --target bitcoin-node bitcoin-cli -j 4
        cygpath -m "${REPO_ROOT}/sri-integration-test/bitcoin-core-build/vcpkg_installed/x64-windows/tools/capnproto" >> "${GITHUB_PATH}"
        ;;
    build-sv2-apps)
        # Git Bash's link.exe shadows MSVC's linker on PATH.
        CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="$(cygpath -m "${VCToolsInstallDir:?}/bin/Hostx64/x64/link.exe")"
        export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
        cd sri-integration-test/sv2-apps
        cargo build --locked -p pool_sv2 --bin pool_sv2
        cargo build --locked -p integration_tests_sv2 --bin mining_device
        ;;
    validate-manifest)
        # PowerShell expands the SDK variables, not Bash.
        # shellcheck disable=SC2016
        mt_exe=$(powershell.exe -NoProfile -Command '
            $ErrorActionPreference = "Stop"
            $sdk_dir = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots" -Name KitsRoot10).KitsRoot10
            $sdk_latest = (Get-ChildItem "$sdk_dir\bin" -Directory | Where-Object { $_.Name -match "^\d+\.\d+\.\d+\.\d+$" } | Sort-Object Name -Descending | Select-Object -First 1).Name
            Write-Output "${sdk_dir}bin\${sdk_latest}\x64\mt.exe"
        ')
        mt_exe=$(cygpath -u "${mt_exe//$'\r'/}")
        "${mt_exe}" -nologo '-inputresource:bin\sv2-tp.exe' -out:sv2-tp.manifest
        cat sv2-tp.manifest
        "${mt_exe}" -nologo '-inputresource:bin\sv2-tp.exe' -validate_manifest
        ;;
    *)
        echo "Usage: $0 [build-sv2-tp|test-sv2-tp|build-bitcoin-core|build-sv2-apps|validate-manifest]" >&2
        exit 1
        ;;
esac
