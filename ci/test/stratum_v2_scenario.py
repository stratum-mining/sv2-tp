#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Run the SRI mining and backend-disconnect scenarios on Linux and Windows."""

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path


class Scenario:
    def __init__(self, args):
        self.args = args
        self.root = args.runtime_root.resolve()
        self.data = self.root / "datadir"
        self.logs = self.root / "logs"
        self.processes = []
        self.outputs = []
        self.backend = None

    def start(self, name, executable, *args):
        output = (self.logs / f"{name}.log").open("w", encoding="utf-8")
        self.outputs.append(output)
        process = subprocess.Popen(
            [str(executable), *map(str, args)], cwd=self.root,
            stdout=output, stderr=subprocess.STDOUT,
            env=dict(os.environ, RUST_LOG="debug"),
        )
        self.processes.append(process)
        print(f"Started {name}: PID {process.pid}", flush=True)
        return process

    def rpc(self, *args):
        result = subprocess.run(
            [str(self.args.bitcoin_cli), f"-datadir={self.data}", *map(str, args)],
            capture_output=True, text=True, timeout=15, check=True,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return result.stdout.strip()

    @staticmethod
    def wait_until(predicate, processes, description, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f"Process {process.pid} exited ({process.returncode}) while waiting for {description}")
            if predicate():
                return
            time.sleep(1)
        raise TimeoutError(f"Timed out waiting for {description}")

    def rpc_ready(self):
        try:
            self.rpc("getblockcount")
            return True
        except subprocess.CalledProcessError:
            return False

    def log_contains(self, text):
        return text in (self.logs / "sv2-tp.log").read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def run(self):
        # Reset only runtime data, preserving any source/build directories nearby.
        for directory in [self.data, self.logs]:
            if directory.exists():
                shutil.rmtree(directory)
        self.data.mkdir(parents=True)
        self.logs.mkdir()
        fixtures = Path(__file__).resolve().parent
        shutil.copyfile(fixtures / "stratum_v2_bitcoin.conf", self.data / "bitcoin.conf")
        shutil.copyfile(fixtures / "stratum_v2_sv2-tp.conf", self.data / "sv2-tp.conf")
        try:
            # Foreground processes work on Windows too, without daemonwait or PID files.
            self.backend = self.start("bitcoin-node", self.args.bitcoin_node, f"-datadir={self.data}", "-listen=0")
            self.wait_until(self.rpc_ready, [self.backend], "Bitcoin Core RPC")
            provider = self.start("sv2-tp", self.args.sv2_tp, f"-datadir={self.data}")
            self.wait_until(lambda: self.log_contains("Connected to bitcoin-node via IPC"),
                            [self.backend, provider], "sv2-tp IPC connection")
            if self.args.scenario == "mining":
                self.mine(provider, fixtures)
                if self.args.expect_memory_load:
                    log = (self.logs / "sv2-tp.log").read_text(encoding="utf-8", errors="replace")
                    assert re.search(r"Template memory footprint [0-9.]+ MiB", log), "Missing getMemoryLoad() memory footprint log"
                if self.args.expect_legacy_interface:
                    assert self.log_contains("The IPC error above is expected when connecting to Bitcoin Core v31"), "Legacy mining interface was not selected"
                print("PASS: mining", flush=True)
                return

            # Exercise backend disconnect detection without an SV2 client.
            self.rpc("stop")
            assert self.backend.wait(timeout=60) == 0, "Bitcoin Core failed to stop cleanly"
            assert provider.wait(timeout=30) == 0, "sv2-tp failed to stop cleanly"
            assert self.log_contains("Mining backend IPC connection lost"), "Missing backend disconnect log"
            print(f"PASS: {self.args.scenario}; backend and sv2-tp exited cleanly", flush=True)
        except Exception:
            for log in [*self.logs.glob("*.log"), *self.data.glob("regtest/*.log")]:
                print(f"===== {log} =====", flush=True)
                print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]), flush=True)
            raise
        finally:
            for process in reversed(self.processes):
                if process is not self.backend:
                    self.stop(process)
            # Stop clients before the backend, as in the original shell runner.
            if self.backend is not None and self.backend.poll() is None:
                try:
                    self.rpc("stop")
                    self.backend.wait(timeout=30)
                except (subprocess.SubprocessError, OSError):
                    pass
                self.stop(self.backend)
            for output in self.outputs:
                output.close()

    def mine(self, provider, fixtures):
        self.rpc("createwallet", "miner")
        address = self.rpc("-rpcwallet=miner", "getnewaddress")
        self.rpc("generatetoaddress", 17, address)
        config = self.root / "pool-regtest.toml"
        config.write_text(
            (fixtures / "stratum_v2_pool-regtest.toml.in").read_text(encoding="utf-8")
            .replace("REPLACE_WITH_REGTEST_ADDRESS", address), encoding="utf-8",
        )
        pool = self.start("pool", self.args.pool, "-c", config)
        time.sleep(5)
        miner = self.start("mining-device", self.args.miner, "--address-pool", "127.0.0.1:33333",
                           "--nominal-hashrate-multiplier", "0.01", "--cores", "1")
        self.wait_until(lambda: self.rpc("getblockcount") > 17,
                        [self.backend, provider, pool, miner], "an SRI-mined block", timeout=180)
        self.stop(miner)
        time.sleep(2)
        count = self.rpc("getblockcount")
        for height in range(18, count + 1):
            block = self.rpc("getblock", self.rpc("getblockhash", height), 2)
            coinbase = block["tx"][0]
            assert coinbase["locktime"] == height - 1, f"Block {height}: wrong BIP54 nLockTime"
            assert coinbase["vin"][0]["sequence"] != 0xffffffff, f"Block {height}: final nSequence"
            assert b"Stratum V2 SRI Pool" in bytes.fromhex(coinbase["vin"][0]["coinbase"]), "Missing pool signature"
            print(f"SRI block {height}: {block['hash']}, BIP54 coinbase OK", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["mining", "backend-disconnect"])
    parser.add_argument("--runtime-root", type=Path, required=True, help="Working directory (datadir and logs are reset)")
    parser.add_argument("--expect-legacy-interface", action="store_true", help="Check v31 legacy IPC detection")
    parser.add_argument("--expect-memory-load", action="store_true", help="Require getMemoryLoad() reporting when mining")
    for binary in ["bitcoin-node", "bitcoin-cli", "sv2-tp", "pool", "miner"]:
        parser.add_argument(f"--{binary}", type=lambda value: Path(value).resolve(), required=binary not in ["pool", "miner"])
    args = parser.parse_args()
    if args.scenario == "mining" and (args.pool is None or args.miner is None):
        parser.error("mining requires --pool and --miner")
    Scenario(args).run()


if __name__ == "__main__":
    main()
