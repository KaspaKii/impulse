# Impulse watcher: events, attribution and codes

The reference watcher `impulse-watch`, increment I8. Companion to `IMPULSE-SPEC.md` ("Off-chain components", "Red team"), `TEMPLATE.md` (the vaults it watches) and `ENCODING.md` (the terms it reads). This file defines what the watcher reports, what each report does and does not prove, the JSON form of its events, its rebroadcast policy, and the `WATCH_*` codes. Reference implementation: `crates/impulse-watch/`. The codes and the event schema below are frozen by `watch_codes_are_frozen` and by tests that assert every event kind field for field; `spec/ERRORS.md` (I10) is to absorb the codes.

Status: phase 1 of I8 is the library driven by a fake source. Phase 2 adds the wRPC node adapter, the `impulse-watch` binary, the local state file, retiring a trade and evicting final acceptances; its tests drive the binary as a process against a fake wRPC node on a loopback port. The live run on mainnet, and the check of the node's answers against mainnet kaspad 2.1.0 (`scripts/check-vcc-v2.sh`), are the key holder's and have not been run. Review round 4 of I8 tightened the rebroadcast guard, the link handling, retiring, the state file's writing and the start-up checks; review round 5 gave every event a round number, so that its de-duplication key is unique across episodes, and made a node call that times out drop the link; this file says what each now does.

## What the watcher follows

- The node's virtual selected parent chain, through `get_virtual_chain_from_block_v2` from a cursor: the chain blocks removed (tip first) and added (oldest first), each added block's DAA score, the transactions it accepted, and for each input the UTXO entry it spent. A mempool miss is never read as anything.
- The first poll starts one chain block behind the node's sink. Nothing accepted before that is reported.
- A trade added once polls have run is watched from the walk after the current cursor only: nothing accepted at or before that chain block is reported for it, unless a reorg brings it into a later walk. `add_trade` returns that cursor (`Watching::from`; none for a trade added before the first poll), and a trade added again from a resumed state keeps the cursor it was first added at.
- Depth is in DAA scores below the last chain block of the poll's walk (the node's sink once the walk has caught up). It never mixes two views of the chain and can only understate the depth below the virtual.
- Finality depth N is the operator's choice. There is no default, and 0 is refused (`WATCH_FINALITY_DEPTH_ZERO`). No value of N is published as safe here.
- A walk is applied whole or not at all. A failed node call (`WATCH_SOURCE_FAILED`) or a poll dropped before the node answers changes nothing, except that the first poll's bootstrap cursor is kept.
- Acceptance is idempotent. A walk delivered twice is reported once. A transaction seen accepted at another block without a removal of the first is a move: a reorg of the old acceptance, then an acceptance at the new block. This holds within one walk too: a transaction that two chain blocks of one walk accept (a valid chain never shows this) is reported accepted at the first, reorg, then accepted at the second, in walk order, each acceptance with its own effects.

## Attribution: per leg, never per trade

Every event about a vault names one trade (its terms hash) and one leg. There is no trade-level settled or refunded event: one settle transaction can spend the asset vault of one trade and the cash vault of another (cross-trade mixing, accepted in the spec red team), and each spent vault is reported as its own (trade, leg). The "Off-chain components" row of `IMPULSE-SPEC.md` says "per trade"; see "Owner edits proposed" below.

A spend is attributed by the UTXO the input spent, never by its signature script alone. Standardness is a mempool rule, not a consensus rule, so a block producer can include an input that spends some other, non-standard UTXO (for example one whose script drops the pushes and leaves true) with exactly the signature script of a vault's settle. Only when the spent UTXO's scriptPubKey is the vault's P2SH has consensus run the vault script. Such a forged input is not reported at all.

## Events

| Event | When | What it shows | What it does not show |
| --- | --- | --- | --- |
| `funded` | An output pays the vault of a KAS leg | A UTXO of `value` sompi at the vault; `exact` is whether it is the leg amount. Only an exact UTXO can settle ([S2]); any other is flagged `WATCH_FUNDING_NOT_EXACT` and can only be refunded | That the depositor is the party named in the terms |
| `authorizer_seen` | An output pays the vault of a KCC-20 leg | A KAS output at the vault (the authorizer). `escrow` is always `not_verified`. `covenant_output` is whether the same transaction has an output bound to the leg's covenant ID | That the escrowed token exists. The token is a separate KCC-20 output whose scriptPubKey is the P2SH of the token template and its state; the terms carry only the template's hash and lengths, so the watcher cannot rebuild it. Anyone can pay a vault address, 1 sompi included. A vault without its escrowed token can never settle ([E1] to [E5]) |
| `settled` | An input spends a vault UTXO through `settle` at the leg's index ([S1]) | The vault script ran and passed; `spent_txid`, `spent_index` and `spent_value` name the vault UTXO | Anything about the other vault of the trade |
| `refunded` | An input spends a vault UTXO through `refund` at input 0 ([R4]) | As for `settled` | |
| `unclassified_spend` | An input spends a vault UTXO, but not as a settle or refund the watcher can read: another entry, an entry at an index it never runs at, a signature script that does not reveal the vault's script, or a KAS leg settled from an inexact UTXO | Flagged `WATCH_SPEND_UNCLASSIFIED`. Seen only if the template is not the one the watcher assumes | Never reported as a settle or refund |
| `stray_deposit` | An output pays the cash-vault script of external-cash terms, which Impulse never instantiates (decision D14) | Flagged `WATCH_STRAY_DEPOSIT`. The deposit belongs to no leg and has no recovery builder; no address is shown for the script | |
| `foreign_token` | Retired in I26: never raised. It was a transaction that spends a watched vault and, at another input, a token of a covenant that spend does not check; every template now refuses such a spend (`TRANSACTIONS.md`, "A token of another covenant at a vault"), so the watcher no longer looks for one | None. A `foreign_token` effect in a state file written by an earlier build still reads back, with its `input` and `covenant_id` | |
| `final` | An acceptance reaches depth N | Once per acceptance; `of` names the effect | Irreversibility: N makes a deeper reorg unlikely, not impossible |
| `reorg` | A reorg removed the accepting block | The effect is undone until accepted again; `was_final` is whether that acceptance had been reported final, and if so the event carries `WATCH_FINAL_REORGED` in place of the effect's own code | |
| `rebroadcast` | A kept transaction a reorg removed was submitted, or was not | See "Rebroadcast": `submitted` is the node holding it in its mempool | That a block will include it, or that the mempool keeps it |

`funded` is for KAS legs only. In v1 the asset leg is always a KCC-20 token (decision D13), so the asset leg is never reported `funded`: its vault output is always `authorizer_seen`. Only a KAS cash leg can be `funded`. `IMPULSE-SPEC.md` and the I8 requirement name `funded` without this split; see "Owner edits proposed" below.

`covenant_output` rests on the consensus covenant rules (rusty-kaspa `CovenantsContext::from_tx`): an output bound to a covenant ID is valid only if its authorizing input's UTXO carries that ID, or the ID is the genesis hash of that input's outpoint and the bound outputs. An existing token's covenant ID can therefore only be continued by spending a UTXO that carries it. `covenant_output: true` shows that the transaction moved some token of the leg's covenant. It does not show the token's owner (the vault), its amount, that the bound output is the escrow, or that it is still unspent.

## Rebroadcast

- The operator marks a signed transaction with `keep_signed`. Refused: an input with no signature script (`WATCH_TX_UNSIGNED`), a transaction whose signature scripts settle or refund no watched vault (`WATCH_TX_NOT_TRACKED`), a txid already kept (`WATCH_TX_DUPLICATE`). Only the txid is kept.
- What is submitted is always the copy the node accepted. A txid does not cover signature scripts, so a copy with the same txid and a bogus signature must never stand in for it.
- When a reorg removes a kept transaction and the same walk does not accept it again, it becomes pending. `rebroadcast_next` submits one pending transaction and changes nothing until the node answers, so a dropped call is repeated by the next one. One attempt per poll, until the node takes it, the chain accepts it again, or 10 refusals (`REBROADCAST_ATTEMPTS`). A settle whose funding left in the same reorg is refused until the funding returns.
- What `submitted` means: the node answered that the transaction is in its mempool, either by taking it or by saying `transaction <id> is already in the mempool` (a submission made and not saved before a crash is made again after the restart, and that is the answer). It does not mean a block will include it: the later walks show whether the chain accepts it, and a transaction the node drops from its mempool before it is accepted is not noticed.
- A node that answers `transaction <id> was already accepted by the consensus` is not saying that. The pinned rusty-kaspa keeps a record of every transaction of every block it processes, on or off the selected chain, for a while (120 seconds by default), and a reorg does not remove it, so after a reorg the answer is true of a transaction the chain no longer holds and the node's mempool does not either. It is a wait, not a refusal of the transaction: it is reported as a `rebroadcast` with outcome `refused` and `WATCH_REBROADCAST_FAILED`, with `attempt` unchanged (no attempt is used, so 0 on a first wait), the transaction stays pending, and it is tried again after the next poll, until a walk accepts it again, the node takes it, the expiry guard holds it back or the operator retires the trade. Waits are bounded by the node's own record, not by a count.
- A settle is not submitted once the tip is at or past the `expiry_daa` of a trade it settles: the depositor's refund may be open, and the decision is the operator's (`WATCH_REBROADCAST_PAST_EXPIRY`). This keeps the watcher in line with the red-team row "Settle after expiry cannot be forbidden in script", where authorities and the SDK refuse past expiry. Refunds are submitted whatever the tip, and the node's clock is not read for them.
- The tip for that guard is the larger of the last walk's tip and the node's own current virtual DAA score (`get_block_dag_info`), read when the settle is about to be submitted. The last walk's tip alone understates the chain whenever the walk stopped short of the sink (the node's added-block batch limit) or the watcher has been down, which is exactly when a rebroadcast is due. If the node's score cannot be read, the settle is not submitted and the attempt is counted as a refusal with the reason.
- A transaction dropped before it was ever accepted is not submitted, and a funding transaction cannot be kept.
- The red-team row "A reorg removes a settle transaction" is rated "MEDIUM, resolved" and reads "The signed transaction stays valid; `impulse-watch` rebroadcasts it"; see "Owner edits proposed" below.

## Restart

`WatchState` holds everything a restart needs except the trades' terms, which the caller adds again: every trade watched with it (its terms hash) and the cursor it was first added at, the cursor, the acceptance index (also by block), each accepted watched transaction with its effects, the copy the node accepted (for spends), the earliest expiry of the trades it settles and whether it was reported final, the kept txids, the pending rebroadcasts and the round count. The binary writes this one object to the local state file after each round ("State file").

A poll is refused (`WATCH_TRADE_NOT_RESUMED`, naming each missing trade) while any trade of a resumed state has not been added again. A missing or renamed terms file therefore stops the watcher before any node call, instead of dropping that trade's fundings, settles, refunds and stray deposits without a sign. Another trade does not stand in for it.

Retiring a trade (`Watcher::retire_trade`, `--retire <terms hash>`) is the explicit way to stop watching one, with or without its terms file. The trade leaves the state, so a resumed state no longer requires it. Its effects are dropped from the accepted transactions; a transaction left with no effect is no longer tracked (not in the acceptance index, not kept, not pending), and a transaction that settled vaults of two trades stays tracked for the other trade. What a tracked transaction keeps is what its remaining effects need and no more: its accepted copy, and its place among the kept, only while one of them is a settle or a refund (a transaction that settled one trade and merely paid another's vault keeps neither, and the state file stays readable), and its settle expiry recomputed from the settles that are left. A settle of a trade not added again keeps the earlier expiry it had, which can only be earlier than the true one: it holds a settle back, never lets one through. A pending rebroadcast that no longer settles or refunds a vault of an added trade is dropped, and the others have their expiry recomputed. The binary adds the trades of the run before it retires, so the trades that stay are known. Nothing is reported. A trade that is not in the state is `WATCH_TRADE_UNKNOWN`, and a trade both retired and given a terms file in one run is `WATCH_RETIRE_WATCHED`. A kept transaction that was never accepted stays in the kept list (the state holds only its txid).

The state grows with every funding, deposit and spend of a watched vault seen, third-party deposits included. `--retention-daa R` (`Retention`) bounds it: the poll that finds an acceptance final and at least R DAA scores deep drops it from the state and the acceptance index. R must be above the finality depth (`WATCH_RETENTION_TOO_SHORT`), so an acceptance has been reported final before it can be evicted. The price is stated: a reorg deeper than R of an evicted acceptance is not reported, and nothing about it is rebroadcast. A kept transaction is never evicted, so its reorg is always followed. Without the option nothing is evicted and the state grows.

## JSON form of events

One JSON object per event. As in the JSON form of terms (`ENCODING.md`), u64 values are decimal strings and u32 values are numbers; hashes and txids are lowercase hex; a trade is its terms hash in lowercase hex.

| Field | Type | In |
| --- | --- | --- |
| `round` | u64 string: the number of the round that reported the event (see "The binary", Rounds) | every event |
| `event` | string: `funded`, `authorizer_seen`, `settled`, `refunded`, `unclassified_spend`, `stray_deposit`, `foreign_token`, `final`, `reorg`, `rebroadcast` | every event |
| `of` | string, the effect's event name | `final`, `reorg` |
| `trade` | hex | every event but `rebroadcast` |
| `leg` | `asset` or `cash` | every vault event (not `stray_deposit`, not `rebroadcast`) |
| `output` | u32 | `funded`, `authorizer_seen`, `stray_deposit` |
| `value` | u64 string, sompi | `funded`, `authorizer_seen`, `stray_deposit` |
| `exact` | bool | `funded` |
| `escrow` | `not_verified` | `authorizer_seen` |
| `covenant_output` | bool | `authorizer_seen` |
| `input` | u32 | `settled`, `refunded`, `unclassified_spend`, `foreign_token` |
| `covenant_id` | hex | `foreign_token` |
| `spent_txid`, `spent_index`, `spent_value` | hex, u32, u64 string | `settled`, `refunded`, `unclassified_spend` |
| `txid` | hex | every event |
| `accepting_block` | hex | every event but `rebroadcast` |
| `accepting_daa` | u64 string | every event but `rebroadcast` |
| `depth` | u64 string | an accepted effect, `final` |
| `was_final` | bool | `reorg` |
| `outcome` | `submitted`, `refused`, `abandoned`, `skipped_past_expiry` | `rebroadcast` |
| `attempt` | u32: the attempts that count so far (a node that only remembers the transaction as accepted is a wait and does not add one) | `rebroadcast` submitted, refused, abandoned |
| `reason` | string, the node's refusal | `rebroadcast` refused, abandoned |
| `expiry_daa`, `tip_daa` | u64 strings | `rebroadcast` skipped_past_expiry |
| `code` | string, an event code below | a flagged event only |

`final`, `reorg` and an accepted effect carry the effect's own fields (`trade`, `leg`, `output` or `input`, and so on).

## The node

The binary reads one node, named by the user (`--node`, a `ws://` or `wss://` wRPC Borsh URL; there is no default endpoint and no resolver). On mainnet the node is the watcher's only input, so the link must be private: `wss://`, or `ws://` to `127.0.0.1`, `[::1]` or `localhost` with an optional port; anything else is `WATCH_NODE_INSECURE`, checked before a file is read or the node is contacted (a remote node is reached through an SSH tunnel to a loopback port; there is no override). A URL that is not `ws://` or `wss://` is `WATCH_NODE_URL_INVALID`; a failed connection is `WATCH_NODE_UNREACHABLE`. After connecting, the server info is read and a node on another network than `--network` is `WATCH_NODE_NETWORK_MISMATCH` (devnet and simnet never match), and a node that is not synced is `WATCH_NODE_NOT_SYNCED`. A start-up call that fails is `WATCH_NODE_RPC`. Every call has a 30 second timeout (a policy figure, not a measured one; a field of the adapter, set at connect, which tests shorten); a poll whose call fails or times out is `WATCH_SOURCE_FAILED` and changes nothing. The URL is echoed as scheme, host and port only, never its user information, path or query, which can carry a credential or a key; text from the other end of a failed connection is echoed escaped.

**The link.** The wRPC client reconnects once when a link drops and then gives up for good (the `Fallback` strategy that makes an unreachable node at start-up an error and not a hang), so a node that restarts would otherwise leave every later call failing. The adapter therefore makes the link again before a call that finds it down, once per call; a poll that cannot is a failed poll, reported, and the next poll tries again. A link that was lost, whether the client re-made it by itself or the adapter did, is checked as at start-up (the right network, synced) before anything is read from it, and closed again if it fails (`the link to the node was lost and could not be made again`). The client's disconnect signal can reach the adapter a moment after the drop, so one poll may read from the new link before it is checked; a node of another chain does not know the cursor's block hash, which fails such a walk. A call that gets no answer within the timeout also drops the link, so that the next call makes it again and checks the node as at start-up. The wRPC client has no keepalive, so a link that went silent without closing (a half-open socket: a firewall that forgot the connection, a peer that vanished without a reset) is never reported as lost, and would otherwise be called on, and time out, until the operating system gives up on the socket, which takes minutes. Making the link again has the same timeout: a node that takes the connection and never answers the check is a failed call (`the link to the node was lost and could not be made again`), and the next call tries again. Sync is checked at start-up and after a lost link, not on every poll.

The walk is `get_virtual_chain_from_block_v2` at Full verbosity with no confirmation count; the bootstrap reads `get_block_dag_info` (the sink) and `get_block` without transactions (the sink's selected parent). It is converted block by block, and a walk is refused whole (`WATCH_SOURCE_FAILED`) unless:

- the added chain blocks and the accepted-transaction batches match one for one, in order, by hash (the node truncates the added list to the batches it returns), every header carries its hash and DAA score, and the DAA scores rise strictly from one added chain block to the next;
- every transaction carries all of: version, each input's outpoint, signature script, sequence, sigop count (version 0) or compute budget (later versions) and spent UTXO entry, each output's value and script, lock time, subnetwork ID, gas, payload and storage mass, and its transaction ID;
- - a walk carries at most 5,000 added chain blocks (`MAX_ADDED_CHAIN_BLOCKS`, a policy figure, I14 O1): the pinned rusty-kaspa sets the node's batch to ten times its mergeset size limit and states 2480 at 10 bps and 1800 on mainnet in a comment in `rpc/service/src/service.rs`, so the cap is twice the largest figure. The check runs before any block is converted, and the probe applies it to its walks, so a node whose real batch is above it is found by the probe and not by a stalled watcher;
- the last added chain block's DAA score is at or below the node's own virtual DAA score (`get_block_dag_info`, read after the walk and only when the walk added a block), with no slack: a chain block is never above the virtual that selected it, and the virtual is read second. A reorg that lowers the virtual below the walk's last block between the two calls fails that one poll, and the next poll reads a consistent pair;
- the transaction rebuilt from those fields has the ID the node reports. That catches a field the ID covers (outpoints, sequences, outputs, lock time, subnetwork, gas, the payload and, for version 1, the covenant bindings of the outputs) that is missing or wrong. It cannot catch one the ID leaves out: the signature scripts, the sigop counts or compute budgets and the storage mass. Those must be present, because spends are classified by the signature script and the rebroadcast of the accepted copy needs the rest, and they are taken from the node, which on mainnet is the trust anchor (hence the private link). `probe` is how the key holder checks a node sends them.

What is not checked, so that nobody reads more into the checks than they are: the number of removed chain blocks (the node's batch does not bound them either), the number of transactions, effects and bytes in a walk, and the state file's growth between evictions. The wRPC client has already decoded the node's whole answer when these checks run, so they bound the watcher's conversion and its state, not the allocation of the decoder (finding F2 of the I14 review). A node that sends a score that is inflated but still at or below its own virtual DAA score is not detected: the node is the watcher's trust anchor, the private link and a node the operator runs themselves are the defence, and `--retention-daa` bounds the state file. The cap is a policy figure from the node's source; `scripts/check-vcc-v2.sh` reads a node's batch and fails if it is above the cap.

A walk that adds nothing is a walk. The node may stop short of its sink (its added-block batch limit); the next poll continues from the cursor. The cursor is always a block the node reported, so a node that has pruned past a cursor (a watcher left stopped for longer than the node keeps) fails every poll with `WATCH_SOURCE_FAILED` and the watcher has no historical scan (a decision, not an omission: the blocks between the cursor and the node's pruning point are gone from that node, so a scan could only cover what the node still holds, and the report of everything else is `impulse status --from-block` per transaction; see the operations guide, "Incidents"): retire the trades and start a new state, accepting that nothing between is reported.

`impulse-watch probe --network <network> --node <url> [--expect-version <v>]` and `scripts/check-vcc-v2.sh` check, with read-only calls and no submission, what the above rests on: the server version (against `--expect-version`; the script expects `2.1.0` unless told otherwise, the version mainnet runs (release gate A3), `WATCH_PROBE_FAILED` otherwise), a short walk from ten chain blocks behind the sink, and a long walk from the pruning point whose size is the node's added-block batch limit. Every transaction goes through the conversion above. The key holder runs the script against their own node and keeps its output; it has not been run against any real node here.

## The binary

```
impulse-watch run   --network mainnet|testnet --node <url> --finality-depth <N> --state <file>
                    [--init] [--trade <terms file>]... [--keep-signed <tx file>]... [--retire <terms hash>]...
                    [--retention-daa <R>] [--poll-interval-ms <ms>] [--max-polls <K>]
                    [--max-failed-polls <K>] [--log-format text|json]
impulse-watch probe --network mainnet|testnet --node <url> [--expect-version <version>]
                    [--log-format text|json]
```

Nothing is chosen for the user: the network, the node, the finality depth (at least 1) and the state file are required, and a missing one is a usage error (exit 2) before anything is read, contacted or written. Mainnet is never implied. The watcher submits only the transactions the user names with `--keep-signed`, after a reorg removed them, and only the copy the node had accepted; it holds no key and signs nothing. The poll interval defaults to 1000 ms (a mechanical default). Without `--max-polls` it runs until killed; with it, it stops after K polls and exits 1 if any poll failed. With `--max-failed-polls K` (I14, operations) the K-th failed poll in a row ends the run with `WATCH_SOURCE_FAILED` (`K polls in a row failed (--max-failed-polls), the last: ...`) and exit 1, so that a supervisor restarts the watcher or raises an alarm instead of a watcher that has lost its node reporting failures for ever; a poll that goes through resets the count. Without it a failed poll is reported and the run goes on. The state file is the last good round's either way.

**Terms files** (`--trade`) are as `impulse terms new` writes them: a JSON object with exactly `terms`, `canonical` and `terms_hash`, no key twice. The watcher watches what `canonical` says: it decodes the canonical bytes with impulse-core, runs the structure checks, and refuses the file unless `terms_hash` is their hash (`WATCH_TERMS_FILE_INCONSISTENT`); anything that is not such a file is `WATCH_TERMS_FILE_INVALID`, an unreadable file `WATCH_FILE_READ`. It does not read the JSON view under `terms`, which the `impulse` CLI checks against `canonical`.

**Signed transactions** (`--keep-signed`) are the raw form of VERIFY.md (rusty-kaspa a41a333's borsh encoding, carrying the transaction ID last) as lowercase hex with at most one final line feed, whose carried ID is the ID of its contents (`WATCH_SIGNED_TX_INVALID`), and which `keep_signed` accepts (`WATCH_TX_UNSIGNED`, `WATCH_TX_NOT_TRACKED`). A transaction already kept in the state is skipped, so the same command line restarts the watcher. The file format at the CLI boundary (what `impulse submit` hands over) is I7 phase 2's; the watcher takes this one.

**Start-up** refuses, in this order, before the node is contacted: the finality depth, the retention window, the node URL and transport, any terms file or signed transaction, a trade both retired and watched, a state file that is missing without `--init` (`WATCH_STATE_MISSING`, a missing directory included) or present with it (`WATCH_STATE_EXISTS`; it is never overwritten, so neither a mistyped path nor a stale one starts a silent new state, and nothing, not even a lock file, is created next to a path that is not a state), a new state file in a directory that does not exist (`WATCH_STATE_WRITE_FAILED`, naming the directory), the state file held by another watcher (`WATCH_STATE_LOCKED`, an advisory lock on `<state>.lock` that the operating system releases when the process exits however it exits), then the state file's contents, adding trades, retiring, keeping transactions and finally a trade of the state with no terms file (`WATCH_TRADE_NOT_RESUMED`). With the lock held, the temporary files a crashed write left next to the state file (`.<state file name>.tmp.*`, each a full copy of an earlier state with its signed transactions) are removed, and said on stderr. A lock file that the run itself made is removed again if the run ends without a state file existing; one that was there before, or sits beside a state file, stays. A trade added to a state that has already polled is watched from the cursor only, and the binary says so on stderr.

**Output.** Events are one JSON object per line on stdout (the schema above). Refusals, failed polls and notes are lines on stderr, `impulse-watch: CODE: detail`, with every control character written as its escape sequence, so text from a node or a file cannot write control sequences or extra lines to the terminal. Exit 0: a bounded run polled without a failure. Exit 1: a refusal, or a bounded run in which a poll failed. Exit 2: a usage error.

**Log format.** `--log-format text` (the default) writes the stderr lines above. `--log-format json` (I14, operations) writes each of them as one JSON object per line with exactly the keys `ts_ms` (Unix time in milliseconds), `level` (`info` for a note, `warn` for a failed poll, `error` for the refusal that ends the run), `code` (the stable code, or `null` for a note) and `message` (the text after the code, unescaped; JSON escapes control characters itself). Neither form carries key material, which the watcher never has, nor a signed transaction; a node URL is shown redacted. Events on stdout are unchanged.

**Rounds.** Each round is one poll and then every due rebroadcast. The events of the round are written to stdout and flushed, and then the state file is replaced if the state changed. A failed poll (`WATCH_SOURCE_FAILED`) is reported on stderr and the next round is tried after the interval; a state file that cannot be written (`WATCH_STATE_WRITE_FAILED`) or an output that cannot be written (`WATCH_OUTPUT_FAILED`) ends the run. Events are therefore at least once: a crash after a round's events were printed and before its state was saved repeats that round's events after the restart, and nothing is lost. A consumer de-duplicates on the key of the event: `round`, `event`, `of`, `trade`, `leg`, `output` or `input`, `txid` and `accepting_block`, and for a `rebroadcast` its `round`, `event`, `txid`, `outcome` and `attempt`; not on `depth`, `reason` or `tip_daa`, which measure the moment and differ between a round and its replay. The two legs of one settle share a transaction and a block and differ in `leg` and `input`, so they are two events and not one; the same holds for a `final` and a `reorg` (which add `of`) and for two outputs of one funding. A replayed round carries the same keys as the first, and no two events of one round share a key. A round whose submission was made and not saved submits again after the restart; a node that already has the transaction in its mempool (`transaction <id> is already in the mempool`) is taken as having done what a rebroadcast is for; its other duplicate answer, only a record of an acceptance, is a wait (see "Rebroadcast"). Killing the process at any moment (SIGKILL included) leaves a whole state file, the previous round's or this one's, because the new file is only ever renamed over the old one once it is complete; a kill can leave a temporary file, which the next start removes. The tests kill a watcher that rewrites its state on every poll at moments that differ each time and restart from what is left; that shows the protocol, not what a power failure does to a disk.

`round` is what keeps the key unique across episodes. It counts the rounds that reported at least one event, from 1; a round that reports nothing is not counted. The count is part of the state file, saved after the round's events are printed: a crash between the two reloads the previous count, so the replayed round carries the same number and the same keys, while a later episode of the same event is a later round and has a key of its own. Without it, a transaction accepted at a block, reorged out and accepted at the same block again would repeat the key of its first acceptance (and of its `final`, and a transaction rebroadcast after each of two reorgs would repeat the key `rebroadcast`, `txid`, `submitted`, 1), and a consumer that de-duplicated on the key would drop the second episode and end on `reorg` for a transaction the chain holds. A new state file (`--init`) starts again at round 1, so a consumer that keeps keys across state files adds the state file's identity to the key. A replay that finds a changed chain reports what it now finds, under the same number.

## State file

One JSON document, `format` `impulse-watch-state`, `version` 1, written whole and replaced atomically: a new file in the same directory, created exclusively (a name that is already taken, by a symlink planted there included, is never opened and the next name is tried), flushed to disk, renamed over the old one, with mode 0600 on Unix (it holds signed transactions). `crates/impulse-watch/tests/golden/state-v1.json` is a state file pinned byte for byte by a test: a renamed key or a changed spelling fails there and not at the next start of a watcher that already wrote a state. No database. Keys are sorted, lists are sorted by txid or trade, so equal states give equal text; u64 values are decimal strings with no leading zero, hashes are lowercase hex.

| Key | Content |
| --- | --- |
| `network` | `mainnet` or `testnet`; a state of another network than `--network` is `WATCH_STATE_MISMATCH` |
| `trades` | `[{trade, from}]`: every trade watched with the state, and the cursor it was first added at (`null` before the first poll, else `{block, daa}`) |
| `cursor` | `null` before the first poll, else `{block, daa}` (`daa` is `null` for the bootstrap cursor) |
| `accepted` | `[{txid, block, daa, finalized, settle_expiry, tx, effects}]`: each accepted watched transaction, its accepting block and DAA score, whether it was reported final, the earliest expiry of the trades it settles (`null` if none), its accepted copy in the raw form (`null` unless an effect is a settle or a refund) and its effects |
| `kept` | the txids marked for rebroadcast |
| `pending` | `[{txid, tx, settle_expiry, attempts, due}]`: each kept transaction a reorg removed, with the copy to submit, the attempts made and whether the next poll's turn has come |
| `round` | u64 string: the rounds that have reported at least one event (the next such round is this plus one) |

An effect is `{kind, trade, leg, ...}` with `kind` one of `funded`, `authorizer_seen`, `settled`, `refunded`, `unclassified_spend`, `stray_deposit`, `foreign_token` and the fields of the event of that name (`index`, `value`, `exact`, `covenant_output`; `input`, `spent_txid`, `spent_index`, `spent_value`; `input`, `covenant_id`). The acceptance index is not stored: it is rebuilt from `accepted`, so the two cannot disagree. The watcher finality depth, the retention window and the node are not stored; they are given on every start, and a changed depth takes effect at the next poll (an acceptance already reported final is not reported again).

The reader is strict and fails closed (`WATCH_STATE_INVALID`): exact key sets at every level, no key twice, lowercase hex, canonical decimals, and a state consistent with itself: every effect names a trade of the state and each accepted transaction at least one effect; a transaction carries its accepted copy exactly when an effect is a settle or a refund and its settle expiry exactly when an effect is a settle, and every stored transaction is one whole raw transaction whose carried ID is the ID of its contents and, where it has one, its `txid`; a pending rebroadcast is a kept transaction that is not accepted; no txid, trade or kept entry is listed twice; accepted transactions need a cursor. A file that cannot be read is `WATCH_FILE_READ`.

## Codes

Refusals, returned by a call (`WATCH_ERROR_CODES`, in this order). Instantiation refusals met while adding a trade keep their own `TEMPLATE_*` and `TERMS_*` codes.

| Code | Refused |
| --- | --- |
| `WATCH_NETWORK_MISMATCH` | Terms of another network than the watcher's |
| `WATCH_TRADE_DUPLICATE` | Terms already watched |
| `WATCH_FINALITY_DEPTH_ZERO` | A finality depth of 0 |
| `WATCH_STRAY_SCRIPT_UNDERIVABLE` | The cash-vault script of external-cash terms could not be derived and checked against impulse-core's decode |
| `WATCH_TX_UNSIGNED` | `keep_signed`: an input with no signature script |
| `WATCH_TX_NOT_TRACKED` | `keep_signed`: settles or refunds no watched vault |
| `WATCH_TX_DUPLICATE` | `keep_signed`: the txid is already kept |
| `WATCH_SOURCE_FAILED` | A node call failed, or the node's data was malformed (spent entries that do not match the inputs one for one); nothing was applied |
| `WATCH_TRADE_NOT_RESUMED` | A poll while a trade of a resumed state has not been added again; nothing was walked |
| `WATCH_TRADE_UNKNOWN` | Retiring a trade the state does not hold |
| `WATCH_RETENTION_TOO_SHORT` | A retention window that is not above the finality depth |
| `WATCH_NODE_URL_INVALID` | The node URL is not `ws://` or `wss://` |
| `WATCH_NODE_INSECURE` | On mainnet, the node URL is neither `wss://` nor `ws://` to a loopback host |
| `WATCH_NODE_UNREACHABLE` | The connection to the node failed |
| `WATCH_NODE_NETWORK_MISMATCH` | The node is on another network than `--network` |
| `WATCH_NODE_NOT_SYNCED` | The node is not synced |
| `WATCH_NODE_RPC` | A call made while starting, or by `probe`, failed or returned something malformed |
| `WATCH_FILE_READ` | A terms file, a signed-transaction file or the state file cannot be read |
| `WATCH_TERMS_FILE_INVALID` | A terms file is not a terms file |
| `WATCH_TERMS_FILE_INCONSISTENT` | A terms file's canonical bytes and terms hash disagree |
| `WATCH_SIGNED_TX_INVALID` | A signed-transaction file is not the raw form of one transaction with the right carried ID |
| `WATCH_STATE_INVALID` | A state file is not in the accepted form, or is not consistent with itself |
| `WATCH_STATE_MISMATCH` | A state file belongs to another network |
| `WATCH_STATE_WRITE_FAILED` | The state file (or its lock file) could not be written, or a new one has no directory to go in; a state file already there is untouched |
| `WATCH_STATE_LOCKED` | Another watcher holds the state file |
| `WATCH_RETIRE_WATCHED` | A trade is both retired and given a terms file in one run |
| `WATCH_PROBE_FAILED` | A check of `probe` failed |
| `WATCH_STATE_MISSING` | The state file does not exist (its directory included) and `--init` was not given |
| `WATCH_STATE_EXISTS` | `--init` was given and the state file exists |
| `WATCH_OUTPUT_FAILED` | The events of a round could not be written to stdout; the round's state was not saved |

Event flags, carried in `code` (`WATCH_EVENT_CODES`, in this order). A flagged event is something the operator must look at.

| Code | Event |
| --- | --- |
| `WATCH_STRAY_DEPOSIT` | `stray_deposit` |
| `WATCH_FUNDING_NOT_EXACT` | `funded` with `exact: false` |
| `WATCH_SPEND_UNCLASSIFIED` | `unclassified_spend` |
| `WATCH_REBROADCAST_FAILED` | `rebroadcast` refused; tried again after the next poll |
| `WATCH_REBROADCAST_ABANDONED` | `rebroadcast` refused for the last allowed time; not tried again |
| `WATCH_REBROADCAST_PAST_EXPIRY` | `rebroadcast` of a settle skipped at or past its trade's expiry |
| `WATCH_FINAL_REORGED` | `reorg` of an acceptance already reported final |
| `WATCH_LINK_RETURN_EARLY` | `linked` with a return vault funded while the opening is not settled |
| `WATCH_FOREIGN_TOKEN` | `foreign_token`, retired in I26 and never raised: every template refuses a spend of a vault that also moves a token of a covenant that spend does not check. Reserved: the name is never reused |

Both lists are frozen once merged and may only grow at the end.

## Linked trades

`impulse-watch run --linked <sheet file>` (repeatable; I22, `V2.md` section 17.9) reads a sheet file of `impulse linked new` as a terms file is read (a JSON object with exactly the keys `sheet`, `canonical` and `linked_hash`; the canonical bytes are decoded with impulse-core, the sheet checks run, and the file is refused unless `linked_hash` is their hash: `WATCH_TERMS_FILE_INVALID`, `WATCH_TERMS_FILE_INCONSISTENT`). Both trades the sheet derives are watched as ordinary trades, so every event of this file is reported for them unchanged, and a trade already given with `--trade` is not added twice. The same sheet twice is `WATCH_TRADE_DUPLICATE`.

The watcher then follows the pair. After each poll it reads the pair's phase from the acceptances it holds and reports one `linked` event for each change:

```
{"event":"linked","linked":"<sheet hash>","opening":"<terms hash>","return":"<terms hash>","phase":"opening_settled","txid":"<txid>","round":"<n>"}
```

`phase` is one of `opening_open`, `opening_settled` (both opening vaults settled), `opening_refunded` (an opening vault refunded and the opening not settled), `return_settled` and `return_refunded`; the return's phases take precedence over the opening's. A return vault funded for exactly its leg amount (or a KCC-20 authorizer seen) while the opening is not settled adds `"code":"WATCH_LINK_RETURN_EARLY"`; the flag clears, in a later `linked` event, when the opening settles. The event is reported in the poll that caused the change, after that poll's events, and its `txid` is that of the last event of the poll that touched either trade. Its de-duplication key is `round`, `event`, `linked`, `phase` and `txid`.

What it does not do. The phase is read from acceptances, so a reorg that removes the opening's settle moves it back (`opening_open`), reported with the reorg events of the same poll. An acceptance that reached the finality depth is remembered by the link even after `--retention-daa` evicts it, so eviction never moves the phase back; a reorg of an acceptance already reported final does not move it either (that reorg is the `WATCH_FINAL_REORGED` event). The state file does not hold the link: after a restart the phase is read from the acceptances the file holds, without a report, and an event is reported only for a change after that. The event is a report of what the chain shows, not a check that the return was agreed or complete.

## Owner edits proposed

`IMPULSE-SPEC.md` is the owner's to change. Where it and this file differ, these are the proposed edits; none is made here.

| `IMPULSE-SPEC.md` | Now | Proposed | Why |
| --- | --- | --- | --- |
| "Off-chain components", `impulse-watch` row | "reports funded, settled and refunded per trade as JSON events" | "reports funded (KAS legs), authorizer_seen (KCC-20 legs), settled and refunded per leg, naming the trade, as JSON events" | Attribution is per leg (one settle can spend vaults of two trades). A KCC-20 leg's vault output shows only the authorizer, never the escrowed token, so it is `authorizer_seen`, not `funded`; with the v1 asset leg always KCC-20 (D13), `funded` is reported for a KAS cash leg only. The I8 requirement ("funded(leg)") drifts the same way |
| Red team, "A reorg removes a settle transaction" | "The signed transaction stays valid; `impulse-watch` rebroadcasts it" | "The signed transaction stays valid; `impulse-watch` rebroadcasts it up to 10 times, once per poll, and reports refusals, abandonment and settles past expiry to the operator" | The watcher retries a refused rebroadcast, gives up after `REBROADCAST_ATTEMPTS`, and does not submit a settle at or past its trade's expiry (see "Rebroadcast") |
| "Scope and open-core boundary", Monitoring row | Impulse (open source): "Reference funding and settlement watcher (single node)". WarpCore (commercial): "Virtual-chain finality tracker, reorg policy, alerting" | Either Impulse: "Reference funding and settlement watcher (single node): virtual-chain acceptance tracking, `final` at depth N, rebroadcast after a reorg with its retry and expiry policy" and WarpCore: "Multi-node tracking, leader election, a database store, alerting"; or the owner holds `final` and the rebroadcast policy back from the open-source watcher | The I8 watcher ships a single-node virtual-chain tracker (`tracker.rs`), `final` events at depth N, and a reorg policy: rebroadcast up to 10 times, once per poll, no settle submitted at or past expiry, `was_final` and `WATCH_FINAL_REORGED`. The I8 requirement and the `impulse-watch` row of "Off-chain components" ask for this ("tracks acceptance through the virtual chain", "rebroadcasts a settle transaction that a reorg removed", "configurable finality depth N"), while the Monitoring row gives the finality tracker and the reorg policy to WarpCore commercial. The spec contradicts itself, and merging I8 moves the boundary it draws. The local JSON state file of phase 2 is persistent, so the commercial column names a database store, not persistence. No code change until the owner rules |
