// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The two wallets of the page. A wallet is the SDK's `Wallet`: its key is drawn by the module
// from the browser's own source of randomness, held in the module's memory and never handed to this
// code, which sees a public key and signatures. This code never stores, shows, sends or logs a key
// (no cookie, no local or session storage, no IndexedDB, no file, no request), and there is no
// button that exports one. The browser and the engine may keep copies of the bytes they handed over
// or moved, which this page cannot clear. The key lives until the wallet is wiped, until the page
// is hidden or unloaded (`pagehide`), or until the tab closes; a wallet that is lost is lost with
// whatever KAS it holds.
//
// A wallet is a signing key and a source of fee inputs, not a place to keep KAS: the page has no
// button that sends from a wallet. So three things guard the funds:
//   - Wipe asks first when the last balance read from the node was above zero, or when the wallet
//     funded a cash vault and this page has not seen that trade settled or refunded since, for one
//     wallet or both (`requestWipe`). The second is value too: the wallet's key is the buyer's own
//     way to take the deposit back, and a wipe destroys it. A wallet can have funded several
//     trades, and each deposit is remembered on its own.
//   - The page asks the browser to confirm before it navigates away while a wallet holds a key
//     (`beforeunload`). Only `pagehide`, when the page really goes, wipes: a navigation that is
//     cancelled or fails leaves the keys where they are.
//   - The SDK refuses, on mainnet, to pay a destination or change to a key of these wallets
//     (`SDK_DESTINATION_IN_WALLET`); `heldKeys()` is how it is told which keys those are.
import { describe } from "./dom.js";

const NAMES = ["a", "b"];

/**
 * Wires the two wallet cards of the page. `ctx` offers `network()` ("mainnet" or "testnet"),
 * `node` (a NodeClient), `useKey(field, hex)` to put a public key into the form, `changed()` when
 * the set of wallets or their state changed, and `walletsChanged()` when a key was made.
 */
export function mountWallets(doc, win, sdk, ctx) {
  const wallets = { a: null, b: null };
  /** The balance last read from the node for each wallet, in sompi as a BigInt; null when not read. */
  const balances = { a: null, b: null };
  /**
   * The deposits each wallet made into a cash vault that this page has not seen settled or
   * refunded: a list of `{ termsHash, amount (sompi, text), txid, note }`, one entry for each
   * funding transaction, so that funding a second trade from the same wallet adds to the first and
   * never replaces it. The page records an entry when the funding is written to the node (the node
   * may take it from then on, and an unknown outcome counts), drops it when the node itself refuses
   * the transaction, and clears one entry when the page submits the settle or a refund of the cash
   * leg of that trade (one settle spends one deposit), when the wallet is wiped and when its key is
   * made again. A trade settled by someone else is not seen, so the page may ask when it need not;
   * it never fails to ask when it should.
   */
  const escrows = { a: [], b: [] };
  const card = (name) => doc.getElementById(`wallet-${name}`);
  const part = (name, selector) => card(name).querySelector(selector);
  const live = (name) => wallets[name] !== null && !wallets[name].isWiped();

  /**
   * Shows the wallet's card. `refresh` tells the page that the set of wallets, or their state,
   * changed (the sign buttons of a document under review follow it); a change of the escrow alone
   * does not, and must not: it happens right after a submission, and the page would offer the
   * submit button again for a transaction the node has just taken.
   */
  const show = (name, refresh = true) => {
    const w = wallets[name];
    const state = part(name, ".wallet-state");
    const wiped = w !== null && w.isWiped();
    state.dataset.state = w === null ? "none" : wiped ? "wiped" : "ready";
    state.textContent =
      w === null
        ? "No key yet."
        : wiped
          ? "Wiped: the key is gone from this page and cannot be signed with. The public key is shown for reference."
          : "Key held in this page's memory only.";
    const held = escrows[name];
    const escrow = part(name, ".wallet-escrow");
    escrow.hidden = held.length === 0;
    escrow.textContent =
      held.length === 0
        ? ""
        : `${held
            .map(
              (e, i) =>
                `${i === 0 ? "This wallet funded" : "It also funded"} ${sdk.kasFromSompi(e.amount)} KAS into the cash vault of the trade ${e.termsHash} (transaction ${e.txid}), and this page has not seen it settled or refunded.`,
            )
            .join(" ")} This key is your way to refund ${held.length === 1 ? "it" : "them"}: wiping the wallet or closing the page destroys it.`;
    part(name, ".wallet-key").textContent = w === null ? "" : w.publicKey();
    part(name, ".wallet-address").textContent = w === null ? "" : w.address(ctx.network());
    part(name, ".wallet-generate").disabled = w !== null && !wiped ? true : false;
    for (const sel of [".wallet-wipe", ".wallet-refresh"]) part(name, sel).disabled = w === null || wiped;
    for (const sel of [".wallet-use-me", ".wallet-use-seller", ".wallet-use-buyer"]) part(name, sel).disabled = w === null;
    if (w === null || wiped) {
      part(name, ".wallet-balance").textContent = "";
      balances[name] = null;
    }
    if (refresh) ctx.changed();
  };

  const generate = (name) => {
    const old = wallets[name];
    try {
      wallets[name] = sdk.Wallet.generate();
      old?.free();
    } catch (e) {
      part(name, ".wallet-state").dataset.state = "error";
      part(name, ".wallet-state").textContent = `No key was made: ${describe(e).message}`;
      return;
    }
    balances[name] = null;
    escrows[name] = [];
    show(name);
    ctx.walletsChanged?.();
  };

  /** Wipes now, without asking: the key is gone, the public key stays for reference. */
  const wipe = (name) => {
    wallets[name]?.wipe();
    // The key that was the way to refund a deposit is gone; nothing is left to protect.
    escrows[name] = [];
    show(name);
  };

  const confirm = doc.getElementById("wipe-confirm");
  const hideConfirm = () => {
    confirm.hidden = true;
    confirm.dataset.names = "";
  };

  /**
   * The wipe a person asks for. A wallet is not wiped until the person says so again when its last
   * balance read was above zero, or when it funded a cash vault that this page has not seen settled
   * or refunded: what it holds, and the way to refund that deposit, are gone with its key.
   */
  const requestWipe = (names) => {
    const targets = names.filter(live);
    const holding = targets.filter((n) => (balances[n] !== null && balances[n] > 0n) || escrows[n].length > 0);
    if (holding.length === 0) {
      hideConfirm();
      targets.forEach(wipe);
      return;
    }
    const reasons = holding
      .flatMap((n) => {
        const N = n.toUpperCase();
        const out = [];
        if (balances[n] !== null && balances[n] > 0n) {
          out.push(`wallet ${N} held ${sdk.kasFromSompi(balances[n].toString())} KAS when you last read its balance`);
        }
        for (const e of escrows[n]) {
          out.push(
            `wallet ${N} funded ${sdk.kasFromSompi(e.amount)} KAS into the cash vault of the trade ${e.termsHash} (transaction ${e.txid}), and this page has not seen it settled or refunded`,
          );
        }
        return out;
      })
      .join("; ");
    const notes = [...new Set(holding.flatMap((n) => escrows[n].map((e) => e.note)).filter((note) => typeof note === "string"))];
    doc.getElementById("wipe-confirm-text").textContent =
      `${reasons[0].toUpperCase()}${reasons.slice(1)}. ${notes.length === 0 ? "" : `${notes.join(" ")} `}A wiped wallet's key is gone, and so is whatever it holds: nothing here can send it anywhere. Wipe ${targets.length === 1 ? "it" : "them"} anyway?`;
    confirm.dataset.names = targets.join(",");
    confirm.hidden = false;
  };

  const refresh = async (name) => {
    const w = wallets[name];
    const out = part(name, ".wallet-balance");
    if (w === null || w.isWiped()) return;
    try {
      const { reply } = await ctx.node.call("getUtxosByAddresses", [w.address(ctx.network())]);
      out.dataset.state = "ok";
      out.textContent = `${reply.total_kas} KAS in ${reply.utxos.length} UTXO${reply.utxos.length === 1 ? "" : "s"}, as the node reports`;
      // The wallet may have been wiped while the node was answering: then it holds nothing to read.
      balances[name] = live(name) ? BigInt(reply.total) : null;
    } catch (e) {
      out.dataset.state = "error";
      out.textContent = `Not read: ${describe(e).message}`;
    }
  };

  for (const name of NAMES) {
    part(name, ".wallet-generate").addEventListener("click", () => generate(name));
    part(name, ".wallet-wipe").addEventListener("click", () => requestWipe([name]));
    part(name, ".wallet-refresh").addEventListener("click", () => refresh(name));
    part(name, ".wallet-use-me").addEventListener("click", () => ctx.useKey("my-key", wallets[name].publicKey()));
    part(name, ".wallet-use-seller").addEventListener("click", () => ctx.useKey("seller_key", wallets[name].publicKey()));
    part(name, ".wallet-use-buyer").addEventListener("click", () => ctx.useKey("buyer_key", wallets[name].publicKey()));
    show(name);
  }

  /** Wipes every wallet that holds a key, without asking: the page is going away. */
  const wipeAll = () => {
    for (const name of NAMES) {
      if (live(name)) wipe(name);
    }
  };
  doc.getElementById("wipe-all").addEventListener("click", () => requestWipe(NAMES));
  doc.getElementById("wipe-confirm-yes").addEventListener("click", () => {
    const names = confirm.dataset.names.split(",").filter((n) => NAMES.includes(n));
    hideConfirm();
    names.forEach((n) => live(n) && wipe(n));
  });
  doc.getElementById("wipe-confirm-no").addEventListener("click", hideConfirm);

  // The keys do not survive the page: when it goes, they are wiped. `pagehide` only: a
  // `beforeunload` fires for a navigation that is then cancelled or fails, and the page stays up
  // with its keys gone. The browser is asked to confirm a navigation while a key is held.
  win.addEventListener("pagehide", wipeAll);
  win.addEventListener("beforeunload", (event) => {
    if (!NAMES.some(live)) return;
    event.preventDefault();
    event.returnValue = "";
  });

  return {
    /** The wallet named "a" or "b", or null. */
    get: (name) => wallets[name],
    names: NAMES,
    /** The wallet whose public key is `hex`, or null. */
    byKey: (hex) => NAMES.map((n) => wallets[n]).find((w) => w !== null && w.publicKey() === hex) ?? null,
    nameOf: (wallet) => NAMES.find((n) => wallets[n] === wallet),
    /**
     * The public key of every wallet made in this page, wiped or not: keys that live only here, which
     * the SDK refuses as a mainnet destination or change.
     */
    heldKeys: () => NAMES.map((n) => wallets[n]).filter((w) => w !== null).map((w) => w.publicKey()),
    /**
     * The funding wallet `name` made into a cash vault, as it is written to the node: from now on
     * the wallet is asked about before it is wiped, and its card says so. One entry for each funding
     * transaction: a deposit for another trade is added beside the ones already held, and the same
     * transaction again (a resubmission) adds nothing. Returns true when the entry is new.
     */
    holdEscrow(name, info) {
      if (escrows[name].some((e) => e.txid === info.txid)) return false;
      escrows[name].push({ termsHash: info.termsHash, amount: info.amount, txid: info.txid, note: info.note });
      show(name, false);
      return true;
    },
    /**
     * The node itself refused the funding transaction `txid` of wallet `name`: it was not taken, and
     * the entry made when it was written goes. Nothing else is dropped.
     */
    dropEscrow(name, txid) {
      escrows[name] = escrows[name].filter((e) => e.txid !== txid);
      show(name, false);
    },
    /**
     * The trade settled or its cash was refunded by this page: one deposit for it is spent, so one
     * entry goes. A second deposit for the same trade (two fundings the node took) stays, because it
     * is still in the cash vault and its wallet's key is still the way to take it back.
     */
    releaseEscrow(termsHash) {
      for (const name of NAMES) {
        const at = escrows[name].findIndex((e) => e.termsHash === termsHash);
        if (at >= 0) {
          escrows[name].splice(at, 1);
          show(name, false);
          return;
        }
      }
    },
    /** The deposits wallet `name` has in cash vaults that this page has not seen settled or refunded. */
    escrowsOf: (name) => escrows[name].map((e) => ({ ...e })),
    wipeAll,
    refreshAddresses: () => NAMES.forEach((name) => show(name)),
  };
}
