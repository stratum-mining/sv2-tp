# Stratum v2

## Requirements

### Bitcoin Core Version

sv2-tp requires **Bitcoin Core v31.0 or later** compiled with IPC support
(`bitcoin-node` binary, not `bitcoind`).

**Compatibility note**
- `sv2-tp` v1.0.6 is the last release that works with Bitcoin Core v30.2
- Current `sv2-tp` depends on the Bitcoin Core v31.0 IPC mining interface
- Bitcoin Core master changed `submitSolution()` after v31.0. Both variants are
  supported: which one to use is determined when the IPC connection is made,
  so that submitting a solution is not delayed.

To check your Bitcoin Core version:
```sh
bitcoin-node --version
```

## Design

The Stratum v2 protocol specification can be found here: https://stratumprotocol.org/specification

Bitcoin Core together together with this application perform the
Template Provider role (Template Distribution
Protocol). When launched we connect to running Bitcoin Core node via IPC and then listen for connections from either a
Job Declarator client (JDC) or a Pool (pool default template or for solo mining).

A JDC probably runs on the same machine. A different possible use case is where
a miner relies on a node run by someone else to provide the templates. This is
currently not safe for the node operator, see the section on DoS.

The Template Provider send the JDC (or Pool) a new block template whenever our
tip is updated, or when mempool fees have increased sufficiently. If the pool
finds a block, we attempt to broadcast it based on a cached template.

Communication with other roles uses the Noise Protocol, which has been implemented
to the extent necessary.

### Advantage over getblocktemplate RPC

Although under the hood the Template Provider uses `CreateNewBlock()` just like
the `getblocktemplate` RPC, there's a number of advantages in running a
server with a stateful connection, and avoiding JSON RPC in general.

1. Stateful, so we can have back-and-forth, e.g. requesting transaction data,
   processing a block solution.
2. Less (de)serializing and data sent over the wire, compared to plain text JSON
3. Encrypted, safer (for now: less unsafe) to expose on the public internet
4. Push based: new template is sent immediately when a new block is found rather
   than at the next poll interval. Combined with Cluster Mempool this can
   hopefully be done for higher fee templates too.
5. Low friction deployment with other Stratum v2 software / devices

### Message flow(s)

See the [Message Types](https://stratumprotocol.org/specification/08-Message-Types/)
and [Protocol Overview](https://stratumprotocol.org/specification/03-Protocol-Overview/)
section of the spec for all messages and their details.

When a Job Declarator client connects to us, it first sends a  `SetupConnection`
message. We reply with `SetupConnection.Success` unless something went wrong,
e.g. version mismatch, in which case we reply with `SetupConnection.Error`.

Next the client sends us their `CoinbaseOutputConstraints`. If this is invalid,
or Bitcoin Core rejects the resulting block options (e.g. a reserved weight
above its `-blockmaxweight`), we disconnect. Otherwise we start the cycle below
that repeats with every block.

We send a `NewTemplate` message with `future_template` set `true`, immedidately
followed by `SetNewPrevHash`. We _don't_ send any transaction information
at this point. The Job Declarator client uses this to announce upstream that
it wants to declare a new template.

In the simplest setup with SRI the Job Declarator client doubles as a proxy and
sends these two messages to all connected mining devices. They will keep
working on their previous job until the `SetNewPrevHash` message arrives.
Future implementations could provide an empty or speculative template before
a new block is found.

Meanwhile the pool will request, via the Job Declarator client, the transaction
lists belonging to the template: `RequestTransactionData`. In case of a problem
we reply with `RequestTransactionData.Error`. Otherwise we reply with the full[0]
transaction data in `RequestTransactionData.Success`.

When we find a template with higher fees, we send a `NewTemplate` message
with `future_template` set to `false`. This is _not_ followed by `SetNewPrevHash`.

Finally, if we find an actual block, the client sends us `SubmitSolution`.
We then lookup the template (may not be the most recent one), reconstruct
the block and broadcast it. The pool will do the same.

A Job Declarator server can instead connect with the `REQUIRES_JOB_VALIDATION`
flag set in `SetupConnection`, which we only accept when the node is Bitcoin
Core v32 or later. Such a client may skip `CoinbaseOutputConstraints`, in
which case it receives no templates, and sends `ProposeTemplate` with the
custom job a miner declared to it: the coinbase prefix and suffix and the
wtxid of every other transaction.

If the node lacks some of those transactions we reply `ProvideMissingTransactions`
with their positions and keep the request pending, for up to 30 seconds and
at most 8 per client. The client answers `ProvideMissingTransactions.Success`
with exactly those transactions, after which validation resumes. Reusing a
pending `request_id` in a new `ProposeTemplate` is answered with
`duplicate-request-id`, and transactions for a request we do not (or no
longer) hold with `unknown-request-id`.

Otherwise we reply `ProposeTemplate.Error` with the node's rejection reason or
one of our own (`bad-cb-decode`, `duplicate-wtxid`, `bad-missing-tx`,
`job-validation-unavailable`), or `ProposeTemplate.Success` with a
`template_id` that a later `SubmitSolution` can refer to, the tip the block was
validated on, and the block's fee total. Only the validating node can compute
the fee total, but Bitcoin Core's mining interface does not expose it for a
checked block yet, so we send 0 (unknown) until it does. While the node is in
initial block download every proposal gets `job-validation-unavailable`.

The node calls that validation takes run on a separate thread, one proposal at
a time, so that they don't hold up `SubmitSolution` and other messages. Each
client may have 4 proposals waiting for or undergoing validation; further
ones get `job-validation-unavailable`. A validated template is kept next to
our own templates and pruned with them after the next block. The spec does
not cap the number of templates a client may have validated yet.

See https://github.com/stratum-mining/sv2-spec/discussions/239 and
https://github.com/bitcoin/bitcoin/pull/35671.

`[0]`: When the Job Declarator client communicates with the Job Declarator
server there is an intermediate message which sends short transaction ids
first, followed by a `ProvideMissingTransactions` message. The spec could be
modified to introduce a similar message here. This is especially useful when
the Template Provider runs on a different machine than the Job Declarator
client. Erlay might be useful here too, in a later stage.

### Noise Protocol

As detailed in the [Protocol Security](https://stratumprotocol.org/specification/04-Protocol-Security/)
section of the spec, Stratum v2 roles use the Noise Protocol to communicate.

We only implement the parts needed for inbound connections, although not much
code would be needed to support outbound connections as well if this is required later.

The spec was written before BIP 324 peer-to-peer encryption was introduced. It
has much in common with Noise, but for the purposes of Stratum v2 it currently
lacks authentication. Perhaps a future version of Stratum will use this. Since
we only communicate with the Job Declarator role, a transition to BIP 324 would
not require waiting for the entire mining ecosystem to adopt it.

An alternative to implementing the Noise Protocol in Bitcoin Core is to use a
unix socket instead and rely on the user to install a separate tool to convert
to this protocol. This approach is implemented in https://github.com/Sjors/bitcoin/pull/48,
but could also be provided as part of SRI.

#### Keys and certificates

For the protocol definitions, see the spec sections on
[server authentication](https://stratumprotocol.org/specification/04-protocol-security/#453-server-authentication)
and [key management and rotation](https://stratumprotocol.org/specification/04-protocol-security/#48-key-management-and-rotation).

At startup, `sv2-tp` loads two private keys from its network-specific data
directory: the Noise static key from `sv2_static_key`, and the authority key
from `sv2_authority_key`. If a key is missing, cannot be read, or is invalid,
it generates a new random key and attempts to save it in the corresponding
file. Successfully saved keys are reused on subsequent starts.

Each startup creates a certificate for the static public key, signed by the
authority private key. The certificate is kept in memory and used for every
incoming Noise handshake during that run. Its validity starts one hour before
startup to allow for clock differences and ends at Unix timestamp 4294967295
(in 2106). A fresh ephemeral key is generated for each handshake.

Configure downstream clients with the Base58Check-encoded
[authority public key](https://stratumprotocol.org/specification/04-protocol-security/#47-url-scheme-and-authority-key)
printed in the `Template Provider authority key: ...` startup log message.
The separate `Static key: ...` message contains the public key authenticated
by the certificate; clients receive that key during the handshake. Neither
private-key file is needed by clients.

If `sv2_authority_key` is lost or unreadable, startup generates a replacement
and clients must be configured with the new authority public key. Replacing
only `sv2_static_key` does not require client reconfiguration, because the new
static key's certificate is signed by the same authority key.

The current implementation has these limitations:

- Externally signed certificates cannot be loaded. The `-sv2cert` option
  mentioned in a source comment is not implemented, so the authority private
  key must be available on the Template Provider when it starts.
- Certificate validity is hardcoded; there is no configurable lifetime or
  renewal while running.

### Mempool monitoring

The current design uses `waitNext()` to monitor for fee increases and new tips.
Fee-based template updates are rate-limited to at most once every
`-templateinterval` seconds (default: 5). New blocks always propagate
immediately. A pool may have additional rate limiting in place.

This is better than the Stratum v1 model of a polling call to the `getblocktemplate` RPC.
It avoids (de)serializing JSON, uses an encrypted connection and only sends data
over the wire if fees increased.

But it's still a poll based model, as opposed to the push based approach
whenever a new block arrives. It would be better if a new template is generated
as soon as a potentially revenue-increasing transaction is added to the mempool.
The Cluster Mempool project might enable that.

### DoS and privacy

The current Template Provider should not be run on the public internet with
unlimited access. It is not hardened against DoS attacks, nor against mempool probing.

There's currently no limit to the number of Job Declarator clients that can connect,
which could exhaust memory. There's also no limit to the amount of raw transaction
data that can be requested.

Templates reveal what is in the mempool without any delay or randomization.

Future improvements should aim to reduce or eliminate the above concerns such
that any node can run a Template Provider as a public service.

## Usage

Using this in a production environment is not yet recommended, but see the testing guide below.

### Parameters

See also `sv2-tp --help`.

Start Bitcoin Core with `bitcoin -m node -ipcbind=unix` and then run `sv2-tp` to start a Template Provider server with default settings.
The listening port can be changed with `-sv2port`.

By default it only accepts connections from localhost. This can be changed
using `-sv2bind`. See DoS and Privacy above.

Use `-debug=sv2` to see Stratum v2 related log messages. Set `-loglevel=sv2:trace`
to see which messages are exchanged with the Job Declarator client.

Fee-based template updates are rate-limited by `-templateinterval` (default: 5
seconds). New blocks always propagate immediately. Templates are only sent to
connected clients if they are for a new block, or if fees have increased by at
least `-sv2feedelta`.

## Testing Guide

Unfortunately testing still requires quite a few moving parts, and each setup has
its own merits and issues.

To get help with the stratum side of things, this Discord may be useful: https://discord.gg/fsEW23wFYs

The Stratum Reference Implementation (SRI) provides example implementations of
the various (other) Stratum v2 roles: https://github.com/stratum-mining/sv2-apps

You can set up an entire pool on your own machine. You can also connect to an
existing pool and only run a limited set of roles on your machine, e.g. the
Job Declarator client and Translator (v1 to v2).

The native Sv2 CPU miner in SRI works for local regtest testing, so a
Translator is not required there.

### Regtest

Regtest is the easiest way to exercise Stratum v2 mining end to end with only
local processes.

In one terminal, start Bitcoin Core with IPC enabled:

```sh
bitcoin -m node -regtest -ipcbind=unix
```

In another terminal, ensure at least 17 blocks have been mined:

For now, those first 17 blocks are still mined over RPC because of the low
height coinbase `bad-cb-length` issue described in Bitcoin Core PR
[#34860](https://github.com/bitcoin/bitcoin/pull/34860).

```sh
COUNT=$(bitcoin-cli -regtest getblockcount)
if [ "$COUNT" -lt 17 ]; then
  bitcoin-cli -regtest -rpcwait createwallet miner
  ADDR=$(bitcoin-cli -regtest -rpcwallet=miner getnewaddress)
  bitcoin-cli -regtest -rpcwallet=miner generatetoaddress $((17 - COUNT)) "$ADDR"
fi
bitcoin-cli -regtest getblockcount
```

Now start `sv2-tp`:

```sh
sv2-tp -regtest -conf=0 -ipcconnect=unix -debug=sv2
```

The SRI Pool role can connect directly to that local Template Provider. Save a
minimal config such as:

```toml
authority_public_key = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
authority_secret_key = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
cert_validity_sec = 3600
listen_address = "127.0.0.1:33333"
coinbase_reward_script = "addr(REPLACE_WITH_REGTEST_ADDRESS)"
server_id = 1
pool_signature = "Stratum V2 SRI Pool"
shares_per_minute = 6.0
share_batch_size = 10

[template_provider_type.Sv2Tp]
address = "127.0.0.1:18447"
```

Start the pool role:

```sh
pool_sv2 -c /path/to/pool-regtest.toml
```

Finally start the native Sv2 CPU miner and point it at the pool:

```sh
mining_device --address-pool 127.0.0.1:33333 --nominal-hashrate-multiplier 0.01 --cores 1
```

At this point the pool log should show `SetupConnection`,
`OpenStandardMiningChannel`, and then `SubmitSharesStandard` / `SubmitSolution`
for newly found blocks. Check `bitcoin-cli -regtest getblockcount` again; it
should advance past 17, and in a typical run the pool and miner will find
multiple blocks quickly.

This setup is also a good target for future functional test coverage.

For testnet, signet, mainnet, translator, Job Declarator client, and ASIC-based
setups, refer to the official SRI documentation:
https://github.com/stratum-mining/sv2-apps
