// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The decoder page: fetch a transaction by its ID from the node the user typed and show the trade
// it settled or refunded. The SDK does the work: it writes the requests, reads the replies as
// text, checks that what the node returned hashes to the ID asked for, finds the vault inputs and
// reads their terms back from the scripts they reveal (`decodeFetched`). The page looks in the
// node's mempool first and then, if the user gave a chain block to start from, along the chain: a
// node keeps no index of transactions by ID.
//
// A transaction fetched from the mempool, or from a node that leaves out the scripts its inputs
// spend, is decoded without being bound to them, and the page says so.
import init, * as sdk from "./sdk/index.js";
import { describe, el, shortCode, shorten } from "./dom.js";
import { NodeClient } from "./node.js";

const MAX_BATCHES = 200;

function destinationText(d) {
  if (d.kind === "kas") return `KAS scriptPublicKey (version ${d.version}) ${d.script}`;
  if (d.kind === "kcc20") return `KCC-20 owner ${d.identifier_type} ${d.identifier}`;
  return "off chain";
}

function renderTrade(doc, decoded) {
  const out = doc.getElementById("out-trade");
  out.replaceChildren();
  if (decoded.legs.length === 0) out.append(el(doc, "p", { class: "error", text: "No leg of an Impulse trade was found in this transaction." }));
  for (const leg of decoded.legs) {
    const card = el(doc, "section", { class: "leg", "data-leg": String(leg.leg), "data-input": String(leg.input_index) });
    const entry =
      leg.entry.kind === "settle"
        ? "settle"
        : `refund${leg.entry.party ? ` signed by the ${leg.entry.party}` : ""}${leg.entry.signer ? ` (key ${leg.entry.signer})` : ""}`;
    card.append(
      el(doc, "h3", { text: `Input ${leg.input_index} spends the vault of the ${leg.leg === 0 ? "asset" : "cash"} leg: ${entry}` }),
      el(doc, "p", {
        class: "outcome",
        text:
          leg.outcome.kind === "delivered"
            ? `Delivered ${leg.outcome.amount} to ${destinationText(leg.outcome.to)}`
            : `Refunded to ${destinationText(leg.outcome.to)}`,
      }),
      el(doc, "p", { class: "label", text: "Terms hash" }),
      shortCode(doc, "terms-hash", leg.terms_hash),
      el(doc, "p", { class: "label", text: "Vault script hash" }),
      shortCode(doc, "script-hash", leg.script_hash),
      el(doc, "p", { class: "label", text: "Spent outpoint" }),
      shortCode(doc, "outpoint", `${leg.outpoint.transaction_id}:${leg.outpoint.index}`, `${shorten(leg.outpoint.transaction_id)}:${leg.outpoint.index}`),
    );
    const details = el(doc, "details");
    details.append(el(doc, "summary", { text: "Terms read back from the script" }), el(doc, "pre", { text: JSON.stringify(leg.terms, null, 2) }));
    card.append(details);
    out.append(card);
  }
  for (const r of decoded.refused) {
    out.append(
      el(doc, "p", {
        class: "error refused-input",
        text: `Input ${r.input_index ?? "?"} looked like a vault spend and was refused: ${r.code}: ${r.message}`,
      }),
    );
  }
}

function renderTemplate(doc, decoded, template) {
  const out = doc.getElementById("out-template");
  out.replaceChildren(
    el(doc, "p", { class: "label", text: "Template hash this page's SDK pins (the ImpulseVault contract, compiled)" }),
    shortCode(doc, "template-hash", hexOf(template.hash())),
    el(doc, "p", {
      class: "binding",
      "data-bound": String(decoded.bound),
      text: decoded.bound
        ? "Bound: the node gave the scriptPublicKey each input spends, and every vault input spends the pay-to-script-hash of the script it reveals, which has this template. The trade above is read from scripts that are consistent with what this one node reports the inputs spend."
        : "Not bound: the node did not give the scriptPublicKey of every spent output (a transaction in the mempool never has them), so the scripts read from the inputs are not tied to what they spend. The trade above is only as trustworthy as the node's copy of the transaction.",
    }),
  );
}

function hexOf(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function renderReceipt(doc, view) {
  const out = doc.getElementById("out-receipt");
  out.replaceChildren();
  if (view.source === "mempool") {
    out.append(
      el(doc, "p", { class: "receipt", text: "Not accepted into a block yet: the transaction is in the node's mempool." }),
    );
  } else {
    const block = view.accepting;
    out.append(
      el(doc, "p", {
        class: "receipt",
        text: block
          ? `Accepted by chain block ${block.hash ?? "(not stated)"} at DAA score ${block.daa_score ?? "(not stated)"}; the node is at DAA score ${view.daa}${block.daa_score ? `, ${Number(view.daa) - Number(block.daa_score)} DAA scores after that block` : ""}.`
          : `Accepted on the chain; the node is at DAA score ${view.daa}.`,
      }),
    );
  }
  out.append(
    el(doc, "p", {
      class: "hint",
      text: "This is what the node says now. It is not a signed receipt: a signed receipt is made with the command line (impulse receipt) by the holder of a key, over the same facts. The difference of two DAA scores is a distance the node reports, not a count of confirmations.",
    }),
  );
}

async function mount(doc, win) {
  const $ = (id) => doc.getElementById(id);
  const template = sdk.templateCheck();
  const status = (state, text, code = "") => {
    const out = $("decoder-status");
    out.dataset.state = state;
    out.dataset.code = code;
    out.textContent = text;
  };
  // A link from the trade page names the transaction and the block to look from.
  for (const part of win.location.hash.replace(/^#/, "").split("&")) {
    const [key, value] = part.split("=");
    if (/^[0-9a-f]{64}$/.test(value ?? "")) {
      if (key === "txid") $("txid").value = value;
      if (key === "from") $("from-block").value = value;
    }
  }

  async function decode() {
    const network = $("decoder-network").value;
    const txid = $("txid").value.trim();
    const from = $("from-block").value.trim();
    for (const id of ["out-trade", "out-template", "out-receipt"]) {
      $(id).replaceChildren(el(doc, "p", { class: "pending", text: "Nothing decoded yet." }));
    }
    status("working", "Connecting.");
    const node = new NodeClient(sdk, win.WebSocket);
    try {
      await node.connect($("node-url").value.trim(), network);
      let found = null;
      let source = null;
      let accepting = null;
      // The mempool first. A node that says it does not hold the transaction (kaspad's
      // "Transaction <id> not found", SDK_RPC_NOT_FOUND) is not an error here; any other refusal
      // is: a reply the SDK cannot read, a node that returns another transaction than asked for,
      // an error of the node's that is not "not found".
      status("working", "Looking in the node's mempool.");
      try {
        const { id, text } = await node.exchange((i) => sdk.rpcRequest(i, "getMempoolEntry", txid));
        found = sdk.rpcTransactionReply(text, id, "getMempoolEntry", txid).transaction;
        source = "mempool";
      } catch (e) {
        if (describe(e).code !== "SDK_RPC_NOT_FOUND") throw e;
      }
      // Whether the walk along the chain ended at the node's tip, as against at the bound.
      let reachedTip = false;
      if (found === null && from !== "") {
        let cursor = from;
        let seen = null;
        for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
          status("working", `Looking along the chain from ${cursor} (batch ${batch + 1}).`);
          const { id, text } = await node.exchange((i) => sdk.rpcRequest(i, "getVirtualChainFromBlockV2", cursor));
          const reply = sdk.rpcTransactionReply(text, id, "getVirtualChainFromBlockV2", txid);
          // A block that left the chain no longer accepts anything.
          if (seen !== null && reply.removed.includes(seen)) {
            found = null;
            accepting = null;
            seen = null;
          }
          if (reply.transaction !== null) {
            found = reply.transaction;
            accepting = reply.accepting_block;
            seen = accepting?.hash ?? null;
            source = "chain";
          }
          if (reply.added.length === 0) {
            reachedTip = true;
            break;
          }
          cursor = reply.added[reply.added.length - 1];
        }
      }
      if (found === null) {
        if (from !== "" && !reachedTip) {
          throw new Error(
            `Gave up after ${MAX_BATCHES} batches of the chain without reaching the node's tip, and the transaction was not in them: give a chain block nearer the submission.`,
          );
        }
        throw new Error(
          from === ""
            ? "Not found in the node's mempool. Give a chain block at or before the submission to look along the chain."
            : "Not found in the node's mempool, nor accepted on the chain from the block given.",
        );
      }
      const decoded = sdk.decodeFetched(found, txid, network);
      const info = await node.serverInfo();
      renderTrade(doc, decoded);
      renderTemplate(doc, decoded, template);
      renderReceipt(doc, { source, accepting, daa: info.virtual_daa_score });
      status(
        "ok",
        `Decoded ${txid} from the node's ${source === "mempool" ? "mempool" : "chain"}: ${decoded.legs.length} leg${decoded.legs.length === 1 ? "" : "s"}${decoded.refused.length > 0 ? `, ${decoded.refused.length} vault input${decoded.refused.length === 1 ? "" : "s"} refused` : ""}.`,
      );
    } catch (e) {
      const { code, message } = describe(e);
      status("refused", code === "" ? `Not decoded: ${message}` : `Refused: ${message}`, code);
    } finally {
      node.close();
    }
  }

  $("decode").addEventListener("click", decode);
  $("decode").disabled = false;
  status("idle", "Enter the node, the transaction ID, and optionally the chain block to look from.");
}

try {
  await init();
  await mount(document, window);
} catch (e) {
  const out = document.getElementById("decoder-status");
  out.dataset.state = "error";
  out.textContent = `The SDK did not start: ${e && e.message ? e.message : String(e)}`;
}
