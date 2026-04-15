#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C

set -eEuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly BITCOIN_CORE_REPO="${BITCOIN_CORE_REPO:-https://github.com/bitcoin/bitcoin.git}"
readonly BITCOIN_CORE_REF="${BITCOIN_CORE_REF:-}"
readonly SV2_APPS_REPO="${SV2_APPS_REPO:-https://github.com/stratum-mining/sv2-apps.git}"
readonly SV2_APPS_REF="${SV2_APPS_REF:-main}"
readonly SCENARIO_ROOT="${SCENARIO_ROOT:-${REPO_ROOT}/sri-integration-test}"
readonly MODE="${1:-all}"

if [[ -z "${BITCOIN_CORE_REF}" ]]; then
    : "${BITCOIN_CORE_VERSION:?BITCOIN_CORE_VERSION must be set when BITCOIN_CORE_REF is empty}"
    : "${BITCOIN_CORE_PLATFORM:?BITCOIN_CORE_PLATFORM must be set when BITCOIN_CORE_REF is empty}"
    readonly BITCOIN_CORE_VERSION
    readonly BITCOIN_CORE_PLATFORM

    if [[ "${BITCOIN_CORE_VERSION}" == *rc* ]]; then
        bitcoin_core_series="${BITCOIN_CORE_VERSION%%rc*}"
        bitcoin_core_rc="${BITCOIN_CORE_VERSION##*rc}"
        bitcoin_core_url_default="https://bitcoincore.org/bin/bitcoin-core-${bitcoin_core_series}/test.rc${bitcoin_core_rc}"
    else
        bitcoin_core_url_default="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_CORE_VERSION}"
    fi

    readonly BITCOIN_CORE_URL="${BITCOIN_CORE_URL:-${bitcoin_core_url_default}}"
    readonly BITCOIN_CORE_TARBALL="${BITCOIN_CORE_TARBALL:-bitcoin-${BITCOIN_CORE_VERSION}-${BITCOIN_CORE_PLATFORM}.tar.gz}"
    readonly BITCOIN_CORE_DIR="${BITCOIN_CORE_DIR:-bitcoin-${BITCOIN_CORE_VERSION}}"
else
    readonly BITCOIN_CORE_URL="${BITCOIN_CORE_URL:-}"
    readonly BITCOIN_CORE_TARBALL="${BITCOIN_CORE_TARBALL:-}"
    readonly BITCOIN_CORE_DIR="${BITCOIN_CORE_DIR:-}"
fi

readonly DOWNLOADS_DIR="${SCENARIO_ROOT}/downloads"
readonly BITCOIN_CORE_SOURCE_DIR="${SCENARIO_ROOT}/bitcoin-core-source"
readonly BITCOIN_CORE_BUILD_DIR="${SCENARIO_ROOT}/bitcoin-core-build"
readonly SV2_APPS_DIR="${SCENARIO_ROOT}/sv2-apps"
readonly DATADIR="${SCENARIO_ROOT}/datadir"
readonly LOG_DIR="${SCENARIO_ROOT}/logs"
readonly POOL_CONFIG="${SCENARIO_ROOT}/pool-regtest.toml"
readonly BITCOIN_CONFIG_SOURCE="${REPO_ROOT}/ci/test/stratum_v2_bitcoin.conf"
readonly SV2_TP_CONFIG_SOURCE="${REPO_ROOT}/ci/test/stratum_v2_sv2-tp.conf"
readonly POOL_CONFIG_TEMPLATE="${REPO_ROOT}/ci/test/stratum_v2_pool-regtest.toml.in"

if [[ -n "${BITCOIN_CORE_REF}" ]]; then
    readonly BITCOIN_BINDIR="${BITCOIN_CORE_BUILD_DIR}/bin"
else
    readonly BITCOIN_BINDIR="${DOWNLOADS_DIR}/${BITCOIN_CORE_DIR}/bin"
fi
readonly BITCOIN="${BITCOIN_BINDIR}/bitcoin"
readonly BITCOIN_CLI="${BITCOIN_BINDIR}/bitcoin-cli"
readonly SV2_TP="${REPO_ROOT}/build/bin/sv2-tp"
readonly POOL_SV2="${SV2_APPS_DIR}/pool-apps/target/release/pool_sv2"
readonly MINING_DEVICE_MANIFEST="${SV2_APPS_DIR}/integration-tests/Cargo.toml"
readonly MINING_DEVICE="${SV2_APPS_DIR}/integration-tests/target/release/mining_device"
readonly -a BITCOIN_ARGS=("-datadir=${DATADIR}")

SV2_TP_PID=""
POOL_PID=""
MINER_PID=""

stop_pid()
{
    local pid="${1:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

show_logs()
{
    (
        set +e
        for log in \
            "${DATADIR}/regtest/debug.log" \
            "${DATADIR}/regtest/sv2-debug.log" \
            "${LOG_DIR}/sv2-tp.log" \
            "${LOG_DIR}/pool.log" \
            "${LOG_DIR}/mining-device.log"; do
            if [[ -f "${log}" ]]; then
                echo "===== tail -n 200 ${log} ====="
                tail -n 200 "${log}" || true
            fi
        done
    )
}

cleanup()
{
    set +e

    stop_pid "${MINER_PID}"
    stop_pid "${POOL_PID}"
    stop_pid "${SV2_TP_PID}"

    if [[ -x "${BITCOIN_CLI}" ]]; then
        "${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" stop >/dev/null 2>&1 || true
    fi
}

prepare_runtime_state()
{
    rm -rf "${DATADIR}" "${LOG_DIR}"
    rm -f "${POOL_CONFIG}"
    mkdir -p "${DATADIR}" "${LOG_DIR}"
    install -m 0644 "${BITCOIN_CONFIG_SOURCE}" "${DATADIR}/bitcoin.conf"
    install -m 0644 "${SV2_TP_CONFIG_SOURCE}" "${DATADIR}/sv2-tp.conf"
}

download_bitcoin_core()
{
    mkdir -p "${DOWNLOADS_DIR}"
    if [[ ! -f "${DOWNLOADS_DIR}/${BITCOIN_CORE_TARBALL}" ]]; then
        tmp_tarball="${DOWNLOADS_DIR}/${BITCOIN_CORE_TARBALL}.tmp"
        rm -f "${tmp_tarball}"
        echo "Downloading ${BITCOIN_CORE_URL}/${BITCOIN_CORE_TARBALL}"
        curl -fsSLo "${tmp_tarball}" \
            "${BITCOIN_CORE_URL}/${BITCOIN_CORE_TARBALL}"
        mv "${tmp_tarball}" "${DOWNLOADS_DIR}/${BITCOIN_CORE_TARBALL}"
    fi
    if [[ ! -x "${BITCOIN}" ]]; then
        echo "Extracting ${BITCOIN_CORE_TARBALL}"
        tar -C "${DOWNLOADS_DIR}" -xzf "${DOWNLOADS_DIR}/${BITCOIN_CORE_TARBALL}"
    fi
}

update_bitcoin_core_source()
{
    if [[ ! -d "${BITCOIN_CORE_SOURCE_DIR}/.git" ]]; then
        rm -rf "${BITCOIN_CORE_SOURCE_DIR}"
        echo "Cloning Bitcoin Core (${BITCOIN_CORE_REPO})"
        git init "${BITCOIN_CORE_SOURCE_DIR}"
        git -C "${BITCOIN_CORE_SOURCE_DIR}" remote add origin "${BITCOIN_CORE_REPO}"
    fi

    echo "Updating Bitcoin Core to ${BITCOIN_CORE_REF}"
    git -C "${BITCOIN_CORE_SOURCE_DIR}" fetch --depth=1 --filter=blob:none origin "${BITCOIN_CORE_REF}"
    git -C "${BITCOIN_CORE_SOURCE_DIR}" checkout --force FETCH_HEAD
}

build_bitcoin_core_from_source()
{
    echo "Building Bitcoin Core from ${BITCOIN_CORE_REF}"
    update_bitcoin_core_source
    cmake -B "${BITCOIN_CORE_BUILD_DIR}" -G Ninja \
        -DBUILD_BENCH=OFF \
        -DBUILD_FUZZ_BINARY=OFF \
        -DBUILD_GUI=OFF \
        -DBUILD_TESTS=OFF \
        "${BITCOIN_CORE_SOURCE_DIR}"
    cmake --build "${BITCOIN_CORE_BUILD_DIR}" --target bitcoin bitcoin-node bitcoin-cli -j"$(nproc)"
}

prepare_bitcoin_core()
{
    if [[ -n "${BITCOIN_CORE_REF}" ]]; then
        build_bitcoin_core_from_source
    else
        download_bitcoin_core
    fi
}

update_sv2_apps()
{
    if [[ ! -d "${SV2_APPS_DIR}/.git" ]]; then
        rm -rf "${SV2_APPS_DIR}"
        echo "Cloning sv2-apps (${SV2_APPS_REF})"
        git clone --depth=1 --branch "${SV2_APPS_REF}" "${SV2_APPS_REPO}" "${SV2_APPS_DIR}"
    else
        echo "Updating sv2-apps to ${SV2_APPS_REF}"
        git -C "${SV2_APPS_DIR}" fetch --depth=1 origin "${SV2_APPS_REF}"
        git -C "${SV2_APPS_DIR}" checkout --force FETCH_HEAD
    fi
}

build_mining_device()
{
    echo "Building mining_device"
    cargo build --release --manifest-path="${MINING_DEVICE_MANIFEST}" --bin mining_device
}

build_phase()
{
    echo "Preparing SRI integration test build artifacts"
    prepare_bitcoin_core
    update_sv2_apps

    echo "Building sv2-tp"
    cmake -B "${REPO_ROOT}/build" -G Ninja -DBUILD_TESTS=OFF "${REPO_ROOT}"
    cmake --build "${REPO_ROOT}/build" --target sv2-tp -j"$(nproc)"

    echo "Building pool_sv2"
    cargo build --release --manifest-path="${SV2_APPS_DIR}/pool-apps/pool/Cargo.toml"

    build_mining_device
}

build_bitcoin_core_phase()
{
    echo "Preparing Bitcoin Core artifacts"
    prepare_bitcoin_core
}

build_sv2_tp_phase()
{
    echo "Building sv2-tp"
    cmake -B "${REPO_ROOT}/build" -G Ninja -DBUILD_TESTS=OFF "${REPO_ROOT}"
    cmake --build "${REPO_ROOT}/build" --target sv2-tp -j"$(nproc)"
}

build_sv2_apps_phase()
{
    update_sv2_apps

    echo "Building pool_sv2"
    cargo build --release --manifest-path="${SV2_APPS_DIR}/pool-apps/pool/Cargo.toml"

    build_mining_device
}

assert_run_prereqs()
{
    local missing=0
    for path in "${BITCOIN}" "${BITCOIN_CLI}" "${SV2_TP}" "${POOL_SV2}" "${MINING_DEVICE}"; do
        if [[ ! -x "${path}" ]]; then
            echo "Missing executable for run mode: ${path}" >&2
            missing=1
        fi
    done
    if (( missing != 0 )); then
        echo "Run mode requires a prior build step" >&2
        exit 1
    fi
}

run_phase()
{
    echo "Preparing SRI integration test runtime state"
    prepare_runtime_state
    assert_run_prereqs

    echo "Starting Bitcoin Core"
    "${BITCOIN}" -m node "${BITCOIN_ARGS[@]}" -daemonwait
    "${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" -rpcwait getblockcount >/dev/null

    echo "Preparing regtest wallet"
    "${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" createwallet miner >/dev/null
    count="$("${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" getblockcount)"
    if (( count < 17 )); then
        echo "Mining regtest blocks up to height 17"
        addr="$("${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" -rpcwallet=miner getnewaddress)"
        "${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" -rpcwallet=miner generatetoaddress \
            "$((17 - count))" "${addr}" >/dev/null
    fi

    reward_addr="$("${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" -rpcwallet=miner getnewaddress)"
    sed "s/REPLACE_WITH_REGTEST_ADDRESS/${reward_addr}/" "${POOL_CONFIG_TEMPLATE}" > "${POOL_CONFIG}"

    echo "Starting sv2-tp"
    "${SV2_TP}" -datadir="${DATADIR}" > "${LOG_DIR}/sv2-tp.log" 2>&1 &
    SV2_TP_PID="$!"

    for ((i = 0; i < 60; ++i)); do
        if grep -q "Connected to bitcoin-node via IPC" "${LOG_DIR}/sv2-tp.log" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    echo "Starting pool_sv2"
    RUST_LOG=debug "${POOL_SV2}" -c "${POOL_CONFIG}" > "${LOG_DIR}/pool.log" 2>&1 &
    POOL_PID="$!"

    sleep 5

    echo "Starting mining_device"
    RUST_LOG=debug "${MINING_DEVICE}" --address-pool 127.0.0.1:33333 \
        --nominal-hashrate-multiplier 0.01 --cores 1 \
        > "${LOG_DIR}/mining-device.log" 2>&1 &
    MINER_PID="$!"

    echo "Waiting for a mined block"
    for ((i = 0; i < 180; ++i)); do
        count="$("${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" getblockcount)"
        if (( count > 17 )); then
            break
        fi
        sleep 1
    done

    count="$("${BITCOIN_CLI}" "${BITCOIN_ARGS[@]}" getblockcount)"
    if (( count <= 17 )); then
        echo "SRI integration test did not mine a block; regtest height stayed at ${count}" >&2
        exit 1
    fi

    grep -q "Connected to bitcoin-node via IPC" "${LOG_DIR}/sv2-tp.log"

    echo "SRI integration test completed successfully at regtest height ${count}"
}

trap cleanup EXIT
trap show_logs ERR

case "${MODE}" in
    all)
        build_bitcoin_core_phase
        build_sv2_tp_phase
        build_sv2_apps_phase
        run_phase
        ;;
    build)
        build_phase
        ;;
    build-bitcoin-core)
        build_bitcoin_core_phase
        ;;
    build-sv2-tp)
        build_sv2_tp_phase
        ;;
    build-sv2-apps)
        build_sv2_apps_phase
        ;;
    run)
        run_phase
        ;;
    *)
        echo "Usage: $0 [all|build|build-bitcoin-core|build-sv2-tp|build-sv2-apps|run]" >&2
        exit 1
        ;;
esac
