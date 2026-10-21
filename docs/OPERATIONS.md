# Operating impulse-watch and the impulse CLI

For the operator who runs the watcher and the CLI on their own machine. The behaviour described here is defined in `spec/WATCH.md` and `spec/CLI.md`; where this guide and a spec differ, the spec is right and this guide is wrong. Nothing here is a measured figure unless it says so: timeouts and intervals are policy choices.

Rules that hold throughout:

- Neither binary holds a key for anyone else. The CLI reads only the key file you name with `--key-file`, inside its signing module, and never prints, logs or transmits it. The watcher holds no key and signs nothing.
- Nothing acts on mainnet unless you pass `--network mainnet`. The watcher has no default network at all; the CLI defaults to testnet.
- A mainnet transaction is signed and sent by its key holder only, from their own machine.

## 1. Install

Build from the repository at a tagged commit. The toolchain is pinned (`rust-toolchain.toml`, Rust 1.94.0); `--locked` refuses any dependency that is not in `Cargo.lock`.

```
git clone <repository> impulse && cd impulse
git checkout <tag>
cargo build --locked --release -p impulse-watch -p impulse-cli
install -m 0755 target/release/impulse-watch target/release/impulse /usr/local/bin/
impulse-watch --version && impulse --version
```

Verify a published release against its signature and SHA-256 sums before installing it (`SHA256SUMS` and its detached signature, published with each release).

Key files: the CLI has no key generator. An operator who signs (an authority, or a party running `impulse ipst sign`) brings a key file of 64 hex digits, mode 0600, as described in `docs/USER-GUIDE.md`, "Getting a key file". The watcher needs none.

Run the watcher as an unprivileged user that owns one directory for its state, for example `/var/lib/impulse-watch`, mode 0700. The watcher writes its state file mode 0600 (it holds signed transactions, not keys).

## 2. The node

Each watcher reads one node that you name with `--node`. There is no default endpoint and no resolver.

- Run your own kaspad, synced, on the network you watch. The CLI's builders also need `--utxoindex`.
- Trust the node. At the pinned rusty-kaspa client, a hostile or compromised node can abort or panic a process that reads from it (an unchecked length prefix in the Borsh reader, and an address length assertion). Nothing is signed or submitted when that happens and no key material is involved, but the process stops. Use only a node you operate or trust, over a private link, and run the watcher under a supervisor (section 3). A fix needs a client patch or a pin bump, which is a later increment (decision D71).
- On mainnet the link must be private: `wss://`, or `ws://` to `127.0.0.1`, `[::1]` or `localhost`. Plaintext to another host is refused (`WATCH_NODE_INSECURE`, `CLI_NODE_INSECURE`). Reach a remote node through an SSH tunnel to a loopback port.
- Before the first run against a node, and after every kaspad upgrade, check it with read-only calls:

```
impulse-watch probe --network testnet --node ws://127.0.0.1:17210 --expect-version <kaspad version>
scripts/check-vcc-v2.sh --network testnet --node ws://127.0.0.1:17210 --expect-version <kaspad version>
```

A node URL can carry a credential in its user information, path or query. Both binaries print it as scheme, host and port only. Keep it out of shell history and process listings anyway: prefer an SSH tunnel to a loopback port over a URL with a credential.

### Node failover

The open-source watcher follows a single node by design (owner decision D19: multi-node tracking is outside its scope). It does not switch nodes by itself. What it does do:

- **Timeouts.** Connecting has a 10 second timeout. Every call after it has 30 seconds. A call with no answer in time fails that poll (`WATCH_SOURCE_FAILED`) and drops the link, so a link that went silent without closing is not called on for minutes.
- **Reconnects.** A lost link is made again before the next call, and the node is checked again (right network, synced) before anything is read from it. A node that restarts costs failed polls, not the watcher.
- **Giving up.** With `--max-failed-polls K` the K-th failed poll in a row ends the run with exit 1, so your supervisor can restart it, alert, or switch it to another node. Without it the watcher reports each failed poll and keeps trying for ever.

To move a watcher to another node by hand: stop it, then start it with the same command line and a different `--node`. The state file names no node. The new node must be on the same network, synced, and must know the cursor block in the state file. A node that does not yet know it (still syncing) fails polls until it does. A node that has pruned past it (the watcher was stopped for longer than the node keeps) fails every poll: see "Incidents".

## 3. Configure and run the watcher

Everything that matters is a required flag; nothing is chosen for you.

| Flag | Choose |
| --- | --- |
| `--network` | `mainnet` or `testnet`; the node, the state file and every terms file must be on it |
| `--node` | your node's wRPC Borsh URL |
| `--finality-depth N` | DAA scores deep before an acceptance is reported `final`. A security choice with no default (decision D18) |
| `--state FILE` | the local state file. `--init` once to create it; never again on the same path |
| `--trade TERMS_FILE` | each trade to watch (repeat). Every trade in the state needs its terms file on every start |
| `--keep-signed TX_FILE` | each signed settle or refund to rebroadcast after a reorg (the file `impulse submit --signed-tx-out` writes) |
| `--retire TERMS_HASH` | stop watching a trade |
| `--retention-daa R` | evict final acceptances R DAA scores deep (R above N). Without it the state only grows |
| `--max-failed-polls K` | end the run after K failed polls in a row |
| `--log-format json` | one JSON object per stderr line |
| `--poll-interval-ms` | default 1000 |

Start the watcher, with the trade's terms file, before the trade is funded. The first poll starts one chain block behind the node's sink, and a trade added to a state that has already polled is watched from the cursor only: nothing accepted before is reported.

First start (testnet shown; on mainnet the key holder types `--network mainnet` and a mainnet node):

```
impulse-watch run --network testnet --node ws://127.0.0.1:17210 \
  --finality-depth <N> --state /var/lib/impulse-watch/state.json --init \
  --trade /var/lib/impulse-watch/trade-1.json --max-polls 1
```

Every later start is the same command line without `--init`. Adding a trade, a kept transaction or a retirement means a restart with the changed flags; a kept transaction already in the state is skipped, so repeating the command line is safe.

### Under a supervisor (systemd example)

```
[Unit]
Description=impulse-watch
After=network-online.target

[Service]
User=impulse
ExecStart=/usr/local/bin/impulse-watch run --network testnet \
  --node ws://127.0.0.1:17210 --finality-depth <N> \
  --state /var/lib/impulse-watch/state.json \
  --trade /var/lib/impulse-watch/trade-1.json \
  --retention-daa <R> --max-failed-polls 60 --log-format json
StandardOutput=append:/var/lib/impulse-watch/events.jsonl
StandardError=journal
Restart=on-failure
RestartSec=30
# Exit 2 is a usage error: restarting does not fix it.
RestartPreventExitStatus=2

[Install]
WantedBy=multi-user.target
```

Stopping it (SIGTERM, or SIGKILL) at any moment is safe: the state file is only ever replaced whole, by a rename, after the round's events were written. A stop can leave a `.<state>.tmp.*` file, which the next start removes and says so.

### Output

- **stdout**: events, one JSON object per line (`spec/WATCH.md`, "JSON form of events"). Delivery is at least once: a crash between printing a round and saving it repeats that round after the restart. De-duplicate on the event key of `spec/WATCH.md` ("Rounds"), and add the state file's identity if you keep keys across a new `--init`.
- **stderr**: notes, failed polls and the refusal that ends a run. Text form `impulse-watch: CODE: detail`, or with `--log-format json` the keys `ts_ms`, `level` (`info`, `warn`, `error`), `code` (null for a note) and `message`. Match on `code`, never on the text. No line carries key material or a signed transaction; node URLs are redacted, and text from a node is escaped.

### Exit codes

| Binary | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `impulse-watch run` | a bounded run (`--max-polls`) with no failed poll | a refusal (start-up check, state, output, `--max-failed-polls` reached), or a bounded run in which a poll failed | usage error; nothing read, contacted or written |
| `impulse-watch probe` | every check passed | a check failed or the node was refused | usage error |
| `impulse` | success | a refusal, `impulse: CODE: detail` on stderr | usage error |

An unbounded run never exits 0 by itself.

## 4. Monitor

- **Liveness.** The state file is replaced after every round that changed the state, and the cursor moves with every new chain block, so on a live network the file's modification time advances with every successful poll. A modification time older than a few poll intervals means no poll has succeeded since. The `round` key counts rounds that reported events, not polls.
- **Failed polls.** Count `WATCH_SOURCE_FAILED` lines at level `warn`. A run that ends with one at level `error` hit `--max-failed-polls`.
- **Events that need a person.** Any event carrying a code: `WATCH_FUNDING_NOT_EXACT`, `WATCH_STRAY_DEPOSIT`, `WATCH_SPEND_UNCLASSIFIED`, `WATCH_REBROADCAST_FAILED`, `WATCH_REBROADCAST_ABANDONED`, `WATCH_REBROADCAST_PAST_EXPIRY`, `WATCH_FINAL_REORGED`. Their meaning is in `spec/WATCH.md`.
- **Growth.** Without `--retention-daa` the state file grows with every funding, deposit and spend of a watched vault. Watch its size, or set a retention window.
- Alerting is not part of Impulse. Wire the above into your own.

## 5. Back up and upgrade

- **Backup.** Copying the state file while the watcher runs is safe: the file is replaced by a rename, so a copy is always one whole state. Keep the terms files and the signed-transaction files with it; the state needs the terms files on every start.
- **Upgrade.** Read the release notes for a change to the state file `version` or to the codes. Then: stop the watcher, back up the state file, install the new binaries, start with the same command line. A state the new binary cannot read is refused (`WATCH_STATE_INVALID`) and left untouched; go back to the old binary and the backup. Run `impulse-watch probe` against the node after a kaspad upgrade.
- **Downgrade** is not supported across a change of the state file `version`.

## 6. Incidents

| Symptom | Meaning | What to do |
| --- | --- | --- |
| `WATCH_NODE_UNREACHABLE`, `WATCH_NODE_NOT_SYNCED`, `WATCH_NODE_NETWORK_MISMATCH` at start | The node is down, syncing, or on another network | Fix the node, or start against another node of the same network |
| `WATCH_SOURCE_FAILED` lines, then recovery | The node or link dropped and came back | Nothing; the state is the last good round's |
| `WATCH_SOURCE_FAILED` on every poll, the node healthy | The node does not know the cursor block: still syncing, or pruned past it after a long stop | If syncing, wait. If pruned, there is no historical scan (nothing is lost silently: every poll fails loudly and the state file is untouched, and a watcher holds no key, so no settle or refund depends on it): retire the trades, or start a new state with `--init` on a new path, accepting that nothing in between is reported. Check each trade's vaults on chain with `impulse status` and `impulse decode` |
| `WATCH_SOURCE_FAILED` naming `above the node's virtual DAA score`, or `added chain blocks, above the 5000 a walk may carry` | The node sent a walk the watcher refuses whole (spec/WATCH.md, "The node"): a chain block above its own virtual DAA score, or more added chain blocks than any honest node of the pinned release sends | A single line after a reorg is a race and clears on the next poll. Repeating lines mean a faulty or hostile node: stop, and run `impulse-watch probe` against it or switch to a node you operate |
| `WATCH_STATE_LOCKED` | Another watcher holds this state (the lock is released when its process exits, however it exits) | Find and stop the other process. Two watchers on one state is the refusal working |
| `WATCH_STATE_INVALID` | The state file is damaged or from an incompatible version | Do not edit it. Restore the latest backup, or go back to the binary that wrote it |
| `WATCH_TRADE_NOT_RESUMED` | A trade of the state has no `--trade` file on this start | Restore the terms file, or `--retire` the trade on purpose |
| `WATCH_STATE_WRITE_FAILED` | Disk full, permissions, or a read-only file system | Free space or fix permissions and restart; the round's events were printed and repeat after the restart |
| `WATCH_OUTPUT_FAILED` | stdout closed or unwritable | Fix the consumer and restart; the round was not saved and repeats |
| `WATCH_FINAL_REORGED` event | A reorg went deeper than your finality depth | Treat as a serious incident: review N, check the trade on chain, and expect the rebroadcast of any kept transaction |
| `WATCH_REBROADCAST_ABANDONED` or `WATCH_REBROADCAST_PAST_EXPIRY` | A kept settle or refund could not be put back, or a settle is past its expiry and is not submitted | A person decides: resubmit with `impulse submit`, or let the refund path run |
| CLI `CLI_NODE_RPC` with `no answer in 30000 ms` on `submit` | The node may have taken the transaction | The refusal names the transaction ID and the `--from-block` to give `impulse status` (with your `--node` and `--terms`); run it before submitting again. Submitting the same signed transaction twice cannot apply it twice: the node refuses the second copy |

## 7. Signing as an authority

A signed settle is a bearer instrument. The authority's signature covers the transaction's inputs (outpoints) and outputs, and the contract checks only a lower time bound (`[S3]`): there is no upper bound, and nothing revokes a signature once it exists. Whoever holds the signed transaction can broadcast it at any time the vault inputs are still unspent, including after `expiry_daa`, when the seller's refund also opens. Example, external cash: the authority signs a settle after it sees the off-chain payment, and the buyer keeps the signed transaction. The payment is then reversed (card or bank). The authority cannot revoke the signature; it can only race its own refund, which the buyer beats by broadcasting first. Late settle is accepted in the design; a held-back signature that outlives the authority's own decision is the same property, and no contract change closes it (the template hash is fixed).

Guidance for an authority, whether one key or a FROST group:

- Sign only when the signing party will broadcast at once. Do not hand a signed settle to a party that may hold it.
- Keep the fee input under the authority's own control. The signature binds the fee outpoints, so a signed settle can only be broadcast with the fee UTXO the authority chose; spend that UTXO elsewhere to withdraw a held signature.
- Sign nothing before the off-chain payment is final.

To withdraw a signature you have already released, spend the fee UTXO it binds (and, if the trade is to be abandoned, run the refund path before the party broadcasts). Nothing else revokes it.
