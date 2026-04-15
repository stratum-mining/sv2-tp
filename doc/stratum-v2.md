# Stratum v2

## Requirements

### Bitcoin Core Version

sv2-tp requires **Bitcoin Core v31.0 or later** compiled with IPC support
(`bitcoin-node` binary, not `bitcoind`).

**Compatibility note**
- `sv2-tp` v1.0.6 is the last release that works with Bitcoin Core v30.2
- Current `sv2-tp` depends on the Bitcoin Core v31.0 IPC mining interface

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

Next the client sends us their `CoinbaseOutputConstraints`. If this is invalid
we disconnect. Otherwise we start the cycle below that repeats with every block.

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
