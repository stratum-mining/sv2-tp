# Historical release notes

Previous releases, newest first. See the [current release notes](release-notes.md).
Notes before v1.1.2 were imported from the linked GitHub releases.

# sv2-tp v1.1.3

## Upgrade instructions: existing key files

**If you already run sv2-tp, restrict access to your existing private-key
files.** Run this command as the user running sv2-tp, in its network-specific
data directory (the directory containing these files):

```sh
chmod 600 sv2_static_key sv2_authority_key
```

Earlier versions could create these keys with permissions that allowed
other local users to read them. This release creates new private keys,
`sv2-debug.log`, the PID file, and saved `.dat` blocks with owner-only
permissions (`0600`). Existing files keep their permissions, so upgrading
alone does not fix existing key files.
([#161](https://github.com/stratum-mining/sv2-tp/pull/161) by @xyephy)

## Bitcoin Core compatibility

This release supports Bitcoin Core v31 and v32. When upgrading to Bitcoin
Core v32, upgrade sv2-tp to v1.1.2 or later first. Earlier sv2-tp releases
do not support v32's changed IPC block-submission interface.

sv2-tp automatically selects the appropriate mining interface for the
connected node. The integration test matrix covers Bitcoin Core v31.1
and v32.1, as well as Core's development branch. sv2-tp v1.0.6 remains
the last release compatible with Bitcoin Core v30.2.

## Notable changes

- Keep Noise handshake secrets out of normal trace logs. Logging those
  secrets now requires the explicit `-loglevel=sv2:trace-unsafe` setting.
  Continue using `-loglevel=sv2:trace` for normal diagnostics.
  ([#152](https://github.com/stratum-mining/sv2-tp/pull/152) by @xyephy)
- Require a numeric IP address for `-sv2bind` and report invalid values
  before connecting to Bitcoin Core. Previously, a hostname such as
  `localhost` or a typo could bind to every IPv6 interface on a random
  port. Use `127.0.0.1` for IPv4 loopback, or explicit wildcard addresses
  `0.0.0.0` and `[::]` when intended.
  ([#160](https://github.com/stratum-mining/sv2-tp/pull/160) by @xyephy)
- Limit simultaneous SV2 connections to 16 by default, including incomplete
  handshakes. Set `-sv2maxconnections=<n>` to change the limit, or
  `-sv2maxconnections=0` to allow unlimited connections.
  ([#146](https://github.com/stratum-mining/sv2-tp/pull/146) by @enirox001)
- Reduce idle CPU usage by waiting for socket send readiness only when
  there is data to send.
  ([#143](https://github.com/stratum-mining/sv2-tp/pull/143) by @xyephy)
- Clean up disconnected clients and join their handler threads. Disconnect
  clients when their template handler exits or a socket send fails, even
  when messages remain queued.
  ([#139](https://github.com/stratum-mining/sv2-tp/pull/139),
  [#147](https://github.com/stratum-mining/sv2-tp/pull/147), and
  [#148](https://github.com/stratum-mining/sv2-tp/pull/148) by @xyephy and @Sjors)
- Validate coinbase output constraints before accepting them, accounting
  for reserved block weight, and disconnect clients whose template
  creation fails. Snapshot each client's constraints before template
  creation so concurrent updates do not change an in-flight request.
  ([#132](https://github.com/stratum-mining/sv2-tp/pull/132) and
  [#133](https://github.com/stratum-mining/sv2-tp/pull/133) by @xyephy and @Sjors)
- Leave `RequestTransactionData.Success`'s `excess_data` empty, matching
  the updated specification and SRI behavior. The coinbase witness is no
  longer copied into that field.
  ([#141](https://github.com/stratum-mining/sv2-tp/pull/141) by @Sjors)
- Reject unsupported setup protocols and feature flags. Retain SV2
  protocol version 2 while preparing explicit version-range negotiation.
  ([#157](https://github.com/stratum-mining/sv2-tp/pull/157) by @Sjors)
- Handle unknown message types consistently when `-debug=sv2` is enabled,
  without disconnecting the client as a side effect of logging.
  ([#150](https://github.com/stratum-mining/sv2-tp/pull/150) by @xyephy)
- Improve networking portability and socket readiness handling.
  ([#136](https://github.com/stratum-mining/sv2-tp/pull/136) and
  [#145](https://github.com/stratum-mining/sv2-tp/pull/145) by @Sjors)
- Update the bundled libmultiprocess library to v14.0 and secp256k1 to
  v0.8.0, update the depends build of Cap'n Proto to v1.5.0 and Boost to
  v1.92.0, and refresh the build system and Guix release tooling.
  ([#134](https://github.com/stratum-mining/sv2-tp/pull/134),
  [#140](https://github.com/stratum-mining/sv2-tp/pull/140),
  [#149](https://github.com/stratum-mining/sv2-tp/pull/149),
  [#135](https://github.com/stratum-mining/sv2-tp/pull/135),
  [#162](https://github.com/stratum-mining/sv2-tp/pull/162), and
  [#163](https://github.com/stratum-mining/sv2-tp/pull/163) by @Sjors;
  Cap'n Proto update by @xyephy)

## Build requirements

Building from source now requires GCC 12.1 or later, Clang 19 or later,
or Xcode Command Line Tools 26.3 or later. The depends build uses Boost
1.92.0. Guix macOS builds use the LLVM toolchain and the extracted SDK
from Xcode 26.1.1 (build 17B100); the minimum macOS version remains 14.0.

## Getting started

See the [README](https://github.com/stratum-mining/sv2-tp#usage) for full
instructions. TL;DR:

- Install or compile Bitcoin Core v31 or v32.
- Start the node with `bitcoin -m node -ipcbind=unix`.
- Start the Template Provider with
  `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`.
- Tail `sv2-debug.log` for runtime diagnostics.

## Contributors

Excluding backports

- Enoch Azariah
- Sjors Provoost
- Толли (@xyephy)

[Previous release notes](https://github.com/stratum-mining/sv2-tp/blob/v1.1.3/doc/release-notes-history.md)

[Full changelog](https://github.com/stratum-mining/sv2-tp/compare/v1.1.2...v1.1.3)

Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.1.2

## Bitcoin Core compatibility

This release supports Bitcoin Core v31 and v32. When upgrading to Bitcoin
Core v32, upgrade sv2-tp to v1.1.2 first. Earlier sv2-tp releases do not
support v32's changed IPC block-submission interface.

sv2-tp automatically selects the appropriate mining interface for the
connected node. Bitcoin Core v31 users can also upgrade to this release.
sv2-tp v1.0.6 remains the last release compatible with Bitcoin Core v30.2.

## Notable changes

- Support Bitcoin Core v32's block-submission interface and log the
  rejection reason and debug details returned by the node.
- Exit safely when the Bitcoin Core IPC connection is lost, including
  when no SV2 clients are connected. Backend loss removes the PID file
  and returns a failure exit status so a supervisor can restart a fresh
  process. Avoid an IPC cleanup race that could crash sv2-tp while clients
  were connected. Requested shutdown through SIGINT or SIGTERM continues
  to return success. The bundled systemd service retries after five seconds.
- Forward `SubmitSolution` even before a client completes
  `SetupConnection` and `CoinbaseOutputConstraints`. A reconnecting
  client can submit a solution for a previously cached template.
- Reply to premature `RequestTransactionData` messages with a
  `setup-incomplete` error instead of disconnecting the client, allowing
  a following solution to be submitted.
- Preserve each client's template ID when sending concurrent updates,
  keeping it paired with the correct cached template.
- Fix locking around client disconnect flags and template identifiers.
- Improve Noise handshake diagnostics and document authority keys,
  static keys, and certificates.
- Update the bundled libmultiprocess library and Guix release tooling.

## Contributors

- Enoch Azariah
- Sjors Provoost

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.1.2)

---

# sv2-tp v1.1.1

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.1.1)

## What's Changed

* **Send `SetNewPrevHash` to every connected client when the chain tip changes** by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/112
* **Immediately resend `NewTemplate` and `SetNewPrevHash` when a client updates its `CoinbaseOutputConstraints`**, preventing JDC fallback from stalling by @enirox001 in https://github.com/stratum-mining/sv2-tp/pull/106
* **Retry the initial Bitcoin Core IPC connection with interruptible exponential backoff**, allowing quick recovery when Bitcoin Core is temporarily unavailable without delaying shutdown by @enirox001 in https://github.com/stratum-mining/sv2-tp/commit/076a7f58a03bd39e316376ad793e1fe5b89e4df4
* Update the libmultiprocess subtree by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/109
* Add integration coverage confirming that Bitcoin Core v31, sv2-tp, and SRI produce BIP54-compliant blocks by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/96
* Extract a reusable SV2 connection tester by @enirox001 in https://github.com/stratum-mining/sv2-tp/pull/105
* Wake mock template waits during shutdown by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/107

**Full Changelog**: https://github.com/stratum-mining/sv2-tp/compare/v1.1.0...v1.1.1

See [README](https://github.com/stratum-mining/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL;DR:

  - install or compile Bitcoin Core v31.0 or later
  - `bitcoin -m node -ipcbind=unix`
  - `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`
  - tail `sv2-debug.log` for runtime diagnostics

  Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.1.0

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.1.0)

## What's Changed

* **config `-sv2interval` was renamed to `-templateinterval`**  by @xyephy in https://github.com/stratum-mining/sv2-tp/pull/90
* Match Bitcoin Core v31 breaking changes, add SRI integration test by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/65
* ci: fix sv2-apps mining device path by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/89
* ci: allow Bitcoin Core ref in SRI test by @Sjors in https://github.com/stratum-mining/sv2-tp/pull/91
* test: add fee timer blocking test coverage by @xyephy in https://github.com/stratum-mining/sv2-tp/pull/70
* fuzz: add raw deserialization targets for SV2 messages by @xyephy in https://github.com/stratum-mining/sv2-tp/pull/81


**Full Changelog**: https://github.com/stratum-mining/sv2-tp/compare/v1.0.6...v1.1.0

See [README](https://github.com/stratum-mining/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL;DR:

  - install or compile Bitcoin Core v31.0
  - `bitcoin -m -ipcbind=unix`
  - `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`
  - tail `sv2-debug.log` for runtime diagnostics

  Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.0.6

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.6)

Notable changes in this release:

  - **Fix SV2 reserved weight handling** by honoring Bitcoin Core’s minimum reserved weight and fixing a floor/cap regression so values below 2000 are treated correctly. (#79 and #82 by @Sjors)
  - **Use `CoinbaseTemplate` when available** to avoid reconstructing coinbase fields from dummy transactions, with fallback behavior for older interfaces. (#59 by @Sjors)
  - **Change default ports to `x8442`** for the Stratum V2 endpoints. (#72 by @Sjors)
  - **Refresh key dependencies**: depends now pins Boost 1.90.0 and native Cap’n Proto 1.3.0, and CMake/docs now require Boost 1.74.0 minimum. (#87 by @Sjors)
  - **Update bundled subtrees** for `libmultiprocess` (v8 line) and `secp256k1` (includes 0.7.1 prep and upstream fixes). (by @Sjors)
  - **Update docs to reflect minimum supported Bitcoin Core version v30.2**. (#80 by @xyephy)

  See [README](https://github.com/stratum-mining/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL;DR:

  - install or compile Bitcoin Core v30.2
  - `bitcoin -m -ipcbind=unix`
  - `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`
  - tail `sv2-debug.log` for runtime diagnostics

  Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.0.5

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.5)

Notable changes in this release:

- **Fix the regression in v1.0.4** that accidentally disabled `PruneBlockTemplateCache` when `-sv2interval` ≤ 10s. The pruning timer now advances only when the best tip really changes. (#66 by @Sjors)
- Emit (trace) logs when pruning stale templates so operators can correlate template lifecycle events. (#64 by @Sjors)
- Restore PID management: `-pid` works again, sv2-tp now creates/removes its PID file, update `sv2-tp.service` systemd unit. (#68 by @Sjors)
- Switch the default `-debuglogfile` to `sv2-debug.log` to prevent writing into the same `debug.log` as Bitcoin Core. (#69 and follow-ups by @Sjors)
- Update documentation to reflect the move to the `stratum-mining` GitHub organization. (by @Sjors)

See [README](https://github.com/stratum-mining/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL;DR:

- install or compile Bitcoin Core v30
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`
- tail `sv2-debug.log` for runtime diagnostics

Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.0.4

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.4)

Notable changes in this release:

- improved logging during startup (#52 by @xyephy)
- reduce delay in sending `NewTemplate` (#56 by @sjors)
- speed up ctrl + c (with future Bitcoin Core versions, #57 by @sjors)
- show `-logtimemicros` in default help
- support multiple coinbase outputs (#55 by @xyephy)
- reduce `getBlockHeader()` IPC call (#58 by @sjors)
- allow `RequestTransactionData` for stale templates for 10s (#61 by @sjors)

See [README](https://github.com/stratum-mining/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL&DR:

- install or compile Bitcoin Core v30
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`

Guix signatures: https://github.com/stratum-mining/sv2-tp-guix.sigs

---

# sv2-tp v1.0.3

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.3)

New in this release:

- ignore `bitcoin.conf` and check for `sv2-tp.conf` instead
- retry connecting to bitcoin core if not available: #27 (by @jbesraa)
- add missing rand init #35 (by @theuni)
- reduce logging CPU overhead #34 (by @theuni)
- log fee total after sending the template downstream
- removed lots of unused code  - @sjors and Chat GBT 5 :-)

See [README](https://github.com/Sjors/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL&DR:

- install or compile Bitcoin Core v30
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`

Guix signatures: https://github.com/Sjors/sv2-tp-guix.sigs

---

# sv2-tp v1.0.2

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.2)

New in this release:

- store blocks after submitting them (for debugging invalid blocks)
- improved ctrl + c shutdown behaviour
- using latest libmultiprocess version (might fix some crashes)

See [README](https://github.com/Sjors/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL&DR:

- install or compile Bitcoin Core v30rc1 or newer
  - download: https://bitcoincore.org/bin/bitcoin-core-30.0/
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`

Guix signatures: https://github.com/Sjors/sv2-tp-guix.sigs

---

# sv2-tp v1.0.1

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0.1)

New in this release:
- macOS binaries are now code-signed and notarised, so you no longer have to manually code-sign them

See [README](https://github.com/Sjors/sv2-tp?tab=readme-ov-file#stratum-v2-template-provider-c) for instructions. TL&DR:

- install or compile Bitcoin Core v30 or newer (not released yet)
  - download (release candidate) https://bitcoincore.org/bin/bitcoin-core-30.0/test.rc1/
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`

Guix build hashes: https://github.com/Sjors/sv2-tp-guix.sigs/tree/main/1.0.1

---

# sv2-tp v1.0

[GitHub release](https://github.com/stratum-mining/sv2-tp/releases/tag/v1.0)

The Template Provider is now a standalone program. It should behave the same as the last IPC release https://github.com/Sjors/bitcoin/releases/tag/sv2-tp-0.1.19-ipc, but no longer contains a `bitcoin-node` binary.

The `bitcoin-mine` command has been renamed to `sv2-tp`.

You need to self-sign the macOS binaries:

```
codesign -s - bin/*
```

See [README](https://github.com/Sjors/sv2-tp) for instructions. TL&DR:

- install or compile Bitcoin Core v30 or newer (not released yet)
  - download unofficial preview: https://github.com/Sjors/bitcoin/releases/tag/v30.0-alpha-1
- `bitcoin -m -ipcbind=unix`
- `bin/sv2-tp -debug=sv2 -loglevel=sv2:trace`

Guix build hashes: https://github.com/Sjors/sv2-tp-guix.sigs/tree/main/1.0
