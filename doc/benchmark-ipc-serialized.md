# Serialized IPC payload benchmark

Build an optimized `test_sv2` with IPC enabled, then run:

```sh
IPC_SERIALIZED_BENCH=1 build/bin/test_sv2 --run_test=ipc_serialized_tests
```

This compares `mp::ReadField<CBlock>` with
`mp::ReadField<ipc::Serialized<CBlock>>` on the same Cap'n Proto Data field.
The latter makes an owned copy without constructing transactions or computing
transaction hashes. It uses the existing libmultiprocess customization hooks;
no libmultiprocess changes or wire changes are needed.

The fixtures are a 142-byte control and a synthetic 3,713,460-byte block with
1,021 independent transactions and large witness items. They exercise decoding,
not consensus validation. Each case has five warmups and 101 measurements,
alternating which conversion runs first. The reported medians include destroying
the decoded block or owned byte buffer. Encoding, socket transport and disk writes
are outside the timing. SHA256 acceleration is selected as in production startup.
These are repeated, hot-cache conversions; they do not predict total RPC latency.

On this machine (GCC 15.2, RelWithDebInfo `-O2`, x86 SHA-NI), the large case took
1.829 ms as `CBlock` and 0.053 ms as `ipc::Serialized<CBlock>`.

The normal test run also checks empty payloads and proves that arbitrary bytes
survive independently of the source message, without requiring a valid block.
