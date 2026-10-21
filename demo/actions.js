// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Fund the buyer's KAS cash leg, settle, refund and Direct, from the node's UTXOs to a submitted
// transaction. Every step is the SDK's: it names the addresses to ask the node about, chooses the
// UTXOs of the node's answer by its rules and calls the builder (`fundCashFromReply`,
// `settleFromReply`, `refundFromReply`, `directFromReply`), writes the review a signer reads
// (`Ipst.review`), signs (`Wallet.sign`, which checks the document, the value cap, the role, the
// fee, the change and what the signer commits before it signs), adds the signatures of a document
// signed elsewhere (`Ipst.combine`, which refuses any document that is not this one) and writes
// the node's request (`rpcSubmitRequest`) and reads its reply. This file reads the form, calls
// those, and shows what they return as text.
//
// Nothing is signed before the review is on the screen, and the review is of the document that is
// signed. The only thing sent to the node besides questions is the signed transaction, on a click
// of the submit button, after the node's current DAA score has been read again.
import { describe, el } from "./dom.js";

/** The text of a scriptPublicKey where there is no address. */
function scriptText(spk) {
  return `script version ${spk.version}: ${spk.script}`;
}

function amountText(entry) {
  return `${entry.amount_kas} KAS (${entry.amount} sompi)`;
}

const ROLE_TEXT = {
  seller: "the seller",
  buyer: "the buyer",
  authority: "the authority",
  other: "no party of the terms",
};

const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function mountActions(doc, win, sdk, ctx) {
  const $ = (id) => doc.getElementById(id);
  /** The document being built and signed, and what it was built against. */
  let session = null;
  /**
   * Bumped whenever the terms, the role or the node change under a document (`dropSession`, and
   * the page recomputing through `available`). A build reads it when it starts and discards its
   * result if it moved while the node was being read.
   */
  let generation = 0;

  const setAction = (state, text, code = "") => {
    const out = $("action-status");
    out.dataset.state = state;
    out.dataset.code = code;
    out.textContent = text;
  };
  const refuse = (e) => {
    const { code, message } = describe(e);
    setAction("refused", code === "" ? `Not done: ${message}` : `Refused: ${message}`, code);
  };

  const setSubmitStatus = (state, text, code = "") => {
    const out = $("submit-status");
    out.dataset.state = state;
    out.dataset.code = code;
    out.textContent = text;
  };
  const setImportStatus = (state, text, code = "") => {
    const out = $("import-status");
    out.dataset.state = state;
    out.dataset.code = code;
    out.textContent = text;
  };
  const setCopyStatus = (state, text) => {
    const out = $("ipst-copy-status");
    out.dataset.state = state;
    out.textContent = text;
  };

  const dropSession = () => {
    generation += 1;
    session?.ipst.free();
    session = null;
    $("review-panel").hidden = true;
    $("sign-buttons").replaceChildren();
    $("review-inputs-body").replaceChildren();
    $("review-outputs-body").replaceChildren();
    $("review-facts").replaceChildren();
    $("review-notes").replaceChildren();
    $("ipst-text").textContent = "";
    $("ipst-export").open = false;
    setCopyStatus("idle", "");
    $("import-text").value = "";
    setImportStatus("idle", "");
    $("submit").disabled = true;
    setSubmitStatus("idle", "");
  };

  const artifacts = () => {
    const cash = $("cash-artifact").value;
    return { asset: $("asset-artifact").value, cash: cash === "" ? null : cash };
  };

  /** Where the fee wallet's change goes, as the user typed it; null for back to the wallet's own key. */
  const changeAddress = () => (($("change-address").value.trim() === "") ? null : $("change-address").value.trim());

  /** The review of `ipst` at `daa`, with the keys that live only in this page marked. */
  const reviewOf = (ipst, arts, daa, value) => ipst.review(arts, daa, value, ctx.wallets.heldKeys());

  const render = () => {
    if (session === null) return;
    const { ipst, review } = session;
    $("review-panel").hidden = false;
    $("review-title").textContent = review.title;
    const facts = $("review-facts");
    facts.replaceChildren();
    const row = (label, text, field) => {
      const dd = el(doc, "dd", { text });
      dd.dataset.field = field;
      facts.append(el(doc, "dt", { text: label }), dd);
    };
    row("Network", review.network, "network");
    row("Terms hash", review.terms_hash, "terms-hash");
    row("Nonce", review.nonce, "nonce");
    row("Fee", `${review.fee_kas} KAS (${review.fee} sompi); the minimum relay fee is ${review.min_relay_fee} sompi`, "fee");
    row("You pay beyond the fee", review.payer_cost_text, "payer-cost");
    row(
      "Lock time",
      review.lock_time === "0"
        ? "none: a node admits it at once"
        : `DAA score ${review.lock_time}: final in a block from DAA score ${review.final_from_daa}`,
      "lock-time",
    );
    row("The node's DAA score", review.current_daa, "daa");
    row(
      "Can be submitted",
      review.submit_ready ? "yes" : `not yet: ${review.wait} to go, at the nominal 10 DAA scores a second`,
      "submit-ready",
    );
    row(
      "Masses (grams)",
      `compute ${review.masses.compute}, transient ${review.masses.transient}, storage ${review.masses.storage}`,
      "masses",
    );
    const notes = $("review-notes");
    notes.replaceChildren(...review.notes.map((text) => el(doc, "li", { class: "review-note", text })));
    const entries = (tbody, items, withSigner) => {
      tbody.replaceChildren();
      for (const item of items) {
        const tr = el(doc, "tr", { "data-index": String(item.index) });
        const held = item.held_key === true;
        tr.append(
          el(doc, "td", { class: "index", text: String(item.index) }),
          el(doc, "td", { class: "amount", text: amountText(item) }),
          el(doc, "td", { class: "address", text: item.address ?? scriptText(item.script_public_key) }),
          el(doc, "td", {
            class: "what",
            text: held ? `${item.what} [pays a key that lives only in this page]` : item.what,
          }),
          el(doc, "td", { class: "covenant", text: item.covenant_id ?? "" }),
        );
        if (held) tr.dataset.held = "true";
        if (withSigner) {
          tr.append(
            el(doc, "td", {
              class: "signer",
              text:
                item.signer === null
                  ? "no signature"
                  : `${item.signed ? "signed by" : "needs"} ${item.signer} (${ROLE_TEXT[item.signer_role] ?? item.signer_role})`,
            }),
          );
          tr.dataset.signed = String(item.signed);
        }
        tbody.append(tr);
      }
    };
    entries($("review-inputs-body"), review.inputs, true);
    entries($("review-outputs-body"), review.outputs, false);
    $("ipst-text").textContent = ipst.toJson();

    // The signatures: a button for each wallet of the page that holds a key some input needs.
    const buttons = $("sign-buttons");
    buttons.replaceChildren();
    const slots = ipst.slots();
    const pending = slots.filter((s) => s.signer !== null && s.signature === null);
    const held = new Set();
    for (const name of ctx.wallets.names) {
      const w = ctx.wallets.get(name);
      if (w === null || w.isWiped()) continue;
      const mine = pending.filter((s) => s.signer === w.publicKey());
      if (mine.length === 0) continue;
      held.add(w.publicKey());
      const button = el(doc, "button", {
        type: "button",
        class: "sign-with",
        "data-wallet": name,
        text: `Sign with wallet ${name.toUpperCase()} (input${mine.length === 1 ? "" : "s"} ${mine.map((s) => s.input).join(", ")})`,
      });
      button.addEventListener("click", () => sign(name));
      buttons.append(button);
    }
    const foreign = pending.filter((s) => !held.has(s.signer));
    const status = $("review-pending");
    if (pending.length === 0) {
      status.textContent = "Every input has its signature. The transaction can be submitted.";
    } else if (foreign.length > 0) {
      status.textContent = `Inputs still unsigned: ${pending.map((s) => s.input).join(", ")}. ${foreign.length} of them need${foreign.length === 1 ? "s" : ""} a key this page does not hold (${[...new Set(foreign.map((s) => s.signer))].join(", ")}): hand the partially signed transaction to its holder (the copy button below puts it on your clipboard, impulse ipst sign signs it, and the signatures are added back under this review).`;
    } else {
      status.textContent = `Inputs still unsigned: ${pending.map((s) => s.input).join(", ")}.`;
    }
    $("submit").disabled = !ipst.isComplete() || session.unknown !== undefined;
  };

  /**
   * Replaces the document under review by `ipst`, with what `patch` says about it. The review is
   * made first, at the score the session holds: a document that no longer passes the terms check
   * (an expiry that has passed) throws before anything is replaced, and the session stays as it was.
   */
  const adopt = (ipst, patch) => {
    const previous = session;
    const next = { ...(previous ?? {}), ...patch, ipst };
    next.review = reviewOf(ipst, next.artifacts, next.daa, next.value);
    session = next;
    if (previous !== null && previous.ipst !== ipst) previous.ipst.free();
    render();
  };

  /**
   * What the user typed about the keys they hold, given to a wallet that signs as a party: the
   * user's pins to the wallet that is the user, the other party's pins to the wallet that is the
   * other party, and nothing to any other wallet.
   */
  const pinsFor = (wallet) => {
    const key = wallet.publicKey();
    const pins = (prefix) => {
      const pin = (id) => ($(id).value === "" ? null : $(id).value);
      return { receive: pin(`${prefix}-receive`), refund: pin(`${prefix}-refund`) };
    };
    if ($("my-key").value === key) return pins("pin");
    const field = (path) => doc.querySelector(`[data-path="${path}"]`).value;
    const role = $("role").value;
    const otherKey = role === "buyer" ? field("seller_key") : role === "seller" ? field("buyer_key") : null;
    if (otherKey === key) {
      const other = pins("pin-other");
      if (other.receive !== null || other.refund !== null) return other;
    }
    return undefined;
  };

  function sign(name) {
    const w = ctx.wallets.get(name);
    try {
      const options = {
        artifacts: session.artifacts,
        current_daa: session.daa,
        value: session.value,
        mainnet: ctx.mainnet(),
        held: ctx.wallets.heldKeys(),
      };
      const change = changeAddress();
      if (change !== null) options.change = change;
      for (const [id, key] of [["max-fee", "max_fee"], ["max-topup", "max_topup"]]) {
        const limit = $(id).value.trim();
        if (limit !== "") options[key] = limit;
      }
      const pins = pinsFor(w);
      if (pins !== undefined) options.pins = pins;
      const out = w.sign(session.ipst, options);
      adopt(out.ipst, {});
      setAction("ok", `Wallet ${name.toUpperCase()} signed input${out.signed_inputs.length === 1 ? "" : "s"} ${out.signed_inputs.join(", ")}.`);
    } catch (e) {
      refuse(e);
      render();
    }
  }

  /** Reads the node and the form, and builds one of the three transactions. */
  async function build(kind) {
    setAction("working", "Reading the node.");
    const started = generation;
    // The terms, the role or the node changed while the node was being read: what was built is
    // not for the form as it now stands, and is thrown away.
    const stale = () => started !== generation || $("actions").hidden;
    const discard = () =>
      setAction("stale", "The terms, the role or the node changed while the node was being read. Nothing was built from the old ones; press build again.");
    let terms;
    let built = null;
    try {
      terms = ctx.currentTerms();
      if (!ctx.node.connected) throw new Error("Connect to a node first: the page builds from the UTXOs and the DAA score it reports.");
      const info = await ctx.node.serverInfo();
      if (stale()) return discard();
      const daa = info.virtual_daa_score;
      const payerName = $("fee-payer").value;
      const payer = ctx.wallets.get(payerName);
      if (payer === null || payer.isWiped()) throw new Error("Choose a wallet that holds a key to pay the fee.");
      const key = payer.publicKey();
      const funding = { payer: key, fee: $("fee").value.trim() };
      const change = changeAddress();
      if (change !== null) funding.change = change;
      const arts = artifacts();
      const value = ctx.valueDeclaration();
      let addresses;
      let leg = null;
      if (kind === "fund") {
        // The addresses are the cash vault, the asset vault with its escrowed token and the payer's
        // own: the SDK refuses to build while the seller's asset leg is not on the node, and when
        // the cash vault already holds the deposit, and never for a token that is no pinned build.
        addresses = terms.fundCashAddresses(arts, key);
        const { text } = await ctx.node.call("getUtxosByAddresses", addresses);
        if (stale()) return discard();
        built = terms.fundCashFromReply(arts, text, funding, daa, value);
      } else if (kind === "refund") {
        leg = Number($("refund-leg").value);
        addresses = terms.refundAddresses(leg, arts, key);
        const { text } = await ctx.node.call("getUtxosByAddresses", addresses);
        if (stale()) return discard();
        built = terms.refundFromReply(leg, $("refund-signer").value, $("refund-token").checked, arts, text, funding, value);
      } else {
        const direct = kind === "direct";
        addresses = direct ? terms.directAddresses(arts, key) : terms.settleAddresses(arts, key);
        const { text } = await ctx.node.call("getUtxosByAddresses", addresses);
        if (stale()) return discard();
        built = direct
          ? terms.directFromReply(arts, text, funding, daa, value)
          : terms.settleFromReply(arts, text, funding, daa, value);
      }
      if (stale()) return discard();
      const ipst = built;
      built = null;
      // A new document is a new submission: what was unknown about the last one is not carried over.
      adopt(ipst, { artifacts: arts, daa, value, kind, payerName, refundLeg: leg, unknown: undefined });
      setSubmitStatus("idle", "");
      setAction("ok", "Built. Read every input, output, the fee and the lock time below before you sign anything.");
    } catch (e) {
      if (stale()) return discard();
      dropSession();
      refuse(e);
    } finally {
      built?.free();
      terms?.free();
    }
  }

  /** The decoder, opened in another tab: this page, and the keys it holds, stay where they are. */
  const decoderLink = (txid, from) =>
    el(doc, "a", {
      href: `decoder.html#txid=${txid}&from=${from}`,
      target: "_blank",
      rel: "noopener",
      text: "Decode it",
    });

  /**
   * The status of a submission whose outcome is not known, with the way to look (the decoder, in
   * another tab) and the question to the node. `lead` says what happened last.
   */
  function renderUnknown(lead) {
    const { txid, before } = session.unknown;
    const status = $("submit-status");
    status.dataset.state = "unknown";
    status.dataset.code = "";
    const check = el(doc, "button", { type: "button", id: "submit-check", text: "Ask the node whether it has it" });
    check.addEventListener("click", () => checkSubmitted());
    status.replaceChildren(
      `${lead} Its ID is ${txid}. Do not submit again before you have checked: `,
      decoderLink(txid, before),
      " (opens in another tab), or ",
      check,
      ".",
    );
    $("submit").disabled = true;
  }

  /** The submission whose outcome is not known: the node may or may not have taken it. */
  function showUnknown(txid, before, why) {
    session.unknown = { txid, before };
    renderUnknown(`Outcome unknown: ${why} The transaction may have been accepted.`);
  }

  /**
   * The status of a submission whose outcome is not known, when the document it was made from is
   * gone (the terms, the role or the node changed while it was in flight): the same warning, the
   * way to look, and no button, because there is no document left to keep submit off for.
   */
  function showDetachedUnknown(txid, before, why) {
    const status = $("submit-status");
    status.dataset.state = "unknown";
    status.dataset.code = "";
    status.replaceChildren(
      `Outcome unknown: ${why} The transaction may have been accepted. Its ID is ${txid}. The terms, the role or the node changed while it was being sent, so this page no longer holds the document. Look with the decoder (`,
      decoderLink(txid, before),
      ", opens in another tab) before you build or submit anything for this trade again.",
    );
  }

  /** Asks the node's mempool for the transaction whose submission is unknown. */
  async function checkSubmitted() {
    if (session === null || session.unknown === undefined) return;
    const { txid, before } = session.unknown;
    const status = $("submit-status");
    try {
      const { id, text } = await ctx.node.exchange((i) => sdk.rpcRequest(i, "getMempoolEntry", txid));
      sdk.rpcTransactionReply(text, id, "getMempoolEntry", txid);
      status.dataset.state = "ok";
      status.replaceChildren(
        `The node has the transaction ${txid} in its mempool: it was accepted. Do not submit it again. `,
        decoderLink(txid, before),
        " (opens in another tab).",
      );
    } catch (e) {
      const { code, message } = describe(e);
      if (code === "SDK_RPC_NOT_FOUND" && session !== null) {
        // Not in the mempool: it may be in a block already, which only the decoder, with the block
        // to look from, can tell. The person is told, and may submit again.
        delete session.unknown;
        status.dataset.state = "wait";
        status.replaceChildren(
          `The node's mempool does not have ${txid}. It may already be in a block: look with the decoder (`,
          decoderLink(txid, before),
          ", opens in another tab) before you submit again. Submit is enabled; the node refuses a transaction it already took.",
        );
        render();
      } else if (session !== null && session.unknown !== undefined) {
        renderUnknown(`The node could not be asked: ${message}`);
      }
    }
  }

  async function submit() {
    if (session === null || session.unknown !== undefined) return;
    let signed;
    let taken = false;
    let txid = null;
    let before = null;
    // `sentRequest`: the request has been written to the socket; from then on the node may take the
    // transaction, whatever this page hears afterwards. `answered`: a reply arrived, which may not
    // be one this page can use.
    let sentRequest = false;
    let answered = false;
    // The deposit entry was made by this very submission (a resubmission of a transaction that was
    // already remembered adds none, and a refusal must not take the earlier entry away).
    let remembered = false;
    // What this submission means for the funding wallet's escrow, read now: the terms may be edited
    // while the node answers, and the session with them. A funding puts the buyer's deposit into the
    // cash vault, and the key that signed it is then the buyer's own way to take it back; a settle,
    // or a refund of the cash leg, ends that.
    const trade = session.review.terms_hash;
    const deposit =
      session.kind === "fund"
        ? { wallet: session.payerName, termsHash: trade, amount: session.review.payer_cost, note: session.review.exit_note }
        : null;
    const closes = session.kind === "settle" || session.kind === "direct" || (session.kind === "refund" && session.refundLeg === 1);
    // One submission at a time: the button is off until the node has answered.
    $("submit").disabled = true;
    setSubmitStatus("working", "Reading the node's DAA score before anything is sent.");
    try {
      // The score is read again: a lock time that has not passed, or an expiry that has, stops the
      // submission here, with nothing sent.
      const info = await ctx.node.serverInfo();
      const review = reviewOf(session.ipst, session.artifacts, info.virtual_daa_score, session.value);
      if (!review.submit_ready) {
        setSubmitStatus(
          "wait",
          `Not final yet: the lock time is DAA score ${review.lock_time} and the node is at ${review.current_daa}; ${review.wait} to go, at the nominal 10 DAA scores a second. Nothing was sent.`,
        );
        session.daa = info.virtual_daa_score;
        session.review = review;
        render();
        return;
      }
      signed = session.ipst.finalize();
      txid = hexOf(signed.txid());
      before = (await ctx.node.call("getBlockDagInfo")).reply.sink;
      const { id, text } = await ctx.node.exchange((i) => {
        const request = sdk.rpcSubmitRequest(i, signed);
        // The request is written to the socket right after this returns. The deposit counts from
        // here, whatever the page is doing when the node answers: the terms may be edited, the
        // session dropped, the answer lost, late, or not the one to this request.
        sentRequest = true;
        if (deposit !== null) remembered = ctx.wallets.holdEscrow(deposit.wallet, { ...deposit, txid });
        return request;
      });
      answered = true;
      const reply = sdk.rpcSubmitReply(text, id, signed);
      taken = true;
      if (closes) ctx.wallets.releaseEscrow(trade);
      const status = $("submit-status");
      status.dataset.state = "ok";
      status.dataset.code = "";
      status.replaceChildren(
        `Submitted. The node accepted the transaction ${reply} into its mempool. The node's chain block before the submission was ${before}: give it to the decoder as the block to look from. `,
        decoderLink(reply, before),
        " (opens in another tab)",
        ...(deposit !== null
          ? [
              `. This is the funding of the cash leg. Wait until the node lists the deposit at the cash vault before you build the settle (the page expects the node to list the UTXOs of accepted blocks; that has not been observed against a real node): a settle built before then is refused (SDK_UTXO_NOT_FOUND). Until the trade settles, the way you can take the deposit back yourself is a refund signed with wallet ${deposit.wallet.toUpperCase()}'s key, and closing this page or wiping that wallet destroys it.`,
            ]
          : []),
      );
    } catch (e) {
      const { code, message } = describe(e);
      // The request left this page when the exchange failed after it was sent (a timeout, a closed
      // connection, a frame that is not text) or when an answer came back. The one answer that
      // says what became of it is the node's own error to this very request (`nodeError`, set by
      // the SDK): the node did not take it. An answer that is for another request, cannot be
      // read, or names another transaction says nothing: the node may have taken the transaction,
      // and this page treats it so.
      const left = sentRequest && (answered || (e && e.afterSend === true));
      if (left && !(e && e.nodeError === true)) {
        taken = true;
        // The deposit stays remembered, with or without the document it was made from.
        if (session !== null) showUnknown(txid, before, message);
        else showDetachedUnknown(txid, before, message);
      } else {
        // Refused by the node, or never sent: no deposit was made by this submission.
        if (remembered) ctx.wallets.dropEscrow(deposit.wallet, txid);
        setSubmitStatus("refused", code === "" ? `Not submitted: ${message}` : `Refused: ${message}`, code);
      }
    } finally {
      signed?.free();
      // Not taken by the node: the signed document is still there to send again.
      if (!taken) $("submit").disabled = session === null || !session.ipst.isComplete();
    }
  }

  /** The signatures of a pasted IPST that the document under review lacks. */
  const signedInputs = (ipst) => ipst.slots().filter((slot) => slot.signature !== null).length;

  /**
   * Adds the signatures of an IPST signed elsewhere (`impulse ipst sign`) to the document under
   * review. The SDK's `combine` takes them only from a document that is this one, byte for byte
   * but for the signatures (same terms, inputs, outputs and slots: `IPST_CONFLICT`), and checks each
   * against its slot's signer and sighash (`TX_SIGNATURE`). The result is reviewed again, as any
   * adopted document is, at the node's score as it is now: hours may have passed since the build,
   * and a review at the score of the build would say "can be submitted" of a document whose lock
   * time has since passed or whose expiry has. If the score cannot be read, the review keeps the
   * score of the build and the status says so. The page never takes the pasted document in place
   * of its own.
   */
  async function importSignatures() {
    let combined = null;
    try {
      if (session === null) {
        throw new Error("There is no document under review. Build one first: signatures are added to the document you reviewed, never in place of it.");
      }
      const pasted = $("import-text").value;
      if (pasted.trim() === "") throw new Error("Paste the IPST text first.");
      const started = generation;
      const target = session;
      const before = signedInputs(session.ipst);
      combined = session.ipst.combine(pasted);
      const added = signedInputs(combined) - before;
      if (added === 0) {
        throw new Error("The pasted transaction is this one but adds no signature the document under review lacks. Nothing changed.");
      }
      let daa = session.daa;
      let stale = "";
      try {
        daa = (await ctx.node.serverInfo()).virtual_daa_score;
      } catch {
        stale = ` The node's DAA score could not be read, so the review still shows the score from the build (${daa}).`;
      }
      if (session !== target || started !== generation) {
        throw new Error("The terms, the role or the node changed while the node was being read. Nothing was added; paste the signed text again.");
      }
      adopt(combined, { daa });
      combined = null;
      $("import-text").value = "";
      setImportStatus("ok", `Added ${added} signature${added === 1 ? "" : "s"}. The review above is of the result, at the node's DAA score ${daa}.${stale}`);
    } catch (e) {
      const { code, message } = describe(e);
      setImportStatus("refused", code === "" ? `Not added: ${message}` : `Refused: ${message}`, code);
    } finally {
      combined?.free();
    }
  }

  /** Copies the document as text to the clipboard; it goes nowhere else. */
  async function copyIpst() {
    const text = $("ipst-text").textContent;
    try {
      await win.navigator.clipboard.writeText(text);
      setCopyStatus("ok", "Copied.");
    } catch {
      // The text sits in a block that is closed until a person opens it: the way to it is opened
      // here, so that the message points at text that can be seen and selected.
      $("ipst-export").open = true;
      setCopyStatus("error", "The browser did not allow the copy. The text is open below: select it and copy it yourself.");
    }
  }

  $("ipst-copy").addEventListener("click", copyIpst);
  $("import-apply").addEventListener("click", importSignatures);
  $("build-fund").addEventListener("click", () => build("fund"));
  $("build-settle").addEventListener("click", () => build(ctx.termsMode() === "direct" ? "direct" : "settle"));
  $("build-refund").addEventListener("click", () => build("refund"));
  $("submit").addEventListener("click", submit);

  return {
    /** The terms or the node changed under a document: it is dropped, and with it any signatures. */
    reset: dropSession,
    /** Shows the panel for terms that passed the role check. */
    available(ok) {
      generation += 1;
      $("actions").hidden = !ok;
      if (!ok) dropSession();
    },
    refresh: render,
    /**
     * The wording of the build button follows the terms, and the funding is offered only to the
     * buyer of a Vault trade with a KAS cash leg: the one leg the SDK builds the funding of. The
     * SDK refuses every other asker (`SDK_FUND_NOT_YOUR_LEG`, `TEMPLATE_NO_VAULT`,
     * `TX_WRONG_MODE`); this only keeps the button from inviting it.
     */
    setMode(mode, role = null, cashKind = null) {
      $("build-settle").textContent = mode === "direct" ? "Build the Direct trade" : "Build the settle";
      $("refund-options").hidden = mode === "direct";
      $("fund-options").hidden = !(mode === "vault" && role === "buyer" && cashKind === "kas");
    },
  };
}
