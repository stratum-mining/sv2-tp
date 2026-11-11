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
