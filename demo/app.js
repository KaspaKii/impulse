// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The trade page. It reads the form, hands the values to the SDK and shows what the SDK returns.
// Every check (the terms, the creation checks, the value cap, the vaults, the addresses, the
// funding URIs and the QR codes) runs in the SDK, which is impulse-core compiled to WebAssembly;
// nothing here decides whether a trade is valid or within the cap, or what an address or a URI
// is. The role check (which party the user is, their public key, pins) is the SDK's too: it runs
// before the SDK returns any instruction, and the page shows a funding URI and a QR code only for
// the leg the user's role funds.
// Settling, refunding and the wallets are in actions.js, wallets.js and node.js: the page reads the
// DAA score and the UTXOs from the node the user typed, builds, shows the review, signs with the
// in-page wallets and submits the one signed transaction. The creation DAA score may be read from
// that node; a score the user types is marked as typed, and mainnet refuses it.
// Terms text (pasted or fetched) goes to the SDK as text: its reader refuses a key named twice, a
// number where a u64 string belongs, an unknown key and a canonical or hash that disagrees, none
// of which a parsed JSON value could still show. The form is then filled from what the SDK read
// and read back, and the SDK compares the two before anything is derived.
// Text from the SDK or from a file is only ever set as text, never as markup.

import { describe, el } from "./dom.js";
import { NodeClient } from "./node.js";
import { mountWallets } from "./wallets.js";
import { mountActions } from "./actions.js";

const SVG_NS = "http://www.w3.org/2000/svg";

/** The QR code as an SVG: dark modules on a light square with the four-module quiet zone. */
function qrSvg(doc, qr) {
  const quiet = 4;
  const size = qr.width + 2 * quiet;
  let path = "";
  for (let y = 0; y < qr.width; y += 1) {
    for (let x = 0; x < qr.width; x += 1) {
      if (qr.modules[y * qr.width + x] === 1) path += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    }
  }
  const svg = doc.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "qr");
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "QR code of the funding URI");
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.dataset.width = String(qr.width);
  const ground = doc.createElementNS(SVG_NS, "rect");
  ground.setAttribute("width", String(size));
  ground.setAttribute("height", String(size));
  ground.setAttribute("fill", "#ffffff");
  const dark = doc.createElementNS(SVG_NS, "path");
  dark.setAttribute("d", path);
  dark.setAttribute("fill", "#000000");
  svg.append(ground, dark);
  return svg;
}

function getPath(object, path) {
  return path.split(".").reduce((o, k) => (o === null || o === undefined ? undefined : o[k]), object);
}

function setPath(object, path, value) {
  const keys = path.split(".");
  const last = keys.pop();
  let o = object;
  for (const k of keys) o = o[k] ??= {};
  o[last] = value;
}

/** What the form holds, as the JSON form of terms. Kind groups that are hidden are left out. */
function readForm(form) {
  const terms = {};
  for (const input of form.querySelectorAll("[data-path]")) {
    if (input.closest("[hidden]")) continue;
    const raw = input.value;
    let value = raw;
    // A number only when the text is plain digits; anything else stays text and the SDK refuses it.
    if (input.dataset.type === "int" && /^[0-9]+$/.test(raw)) value = Number(raw);
    if (input.dataset.type === "nullable" && raw === "") value = null;
    setPath(terms, input.dataset.path, value);
  }
  return terms;
}

function updateVisibility(form) {
  for (const group of form.querySelectorAll("[data-show-when]")) {
    const [path, wanted] = group.dataset.showWhen.split("=");
    const select = form.querySelector(`[data-path="${path}"]`);
    group.hidden = select.value !== wanted;
  }
}

function fillForm(form, terms) {
  for (const input of form.querySelectorAll("[data-path]")) {
    const v = getPath(terms, input.dataset.path);
    input.value = v === undefined || v === null ? "" : String(v);
  }
  updateVisibility(form);
}

function legTitle(leg) {
  return `${leg.name === "asset" ? "Asset" : "Cash"} leg, funded by the ${leg.depositor}`;
}

function legKind(leg) {
  if (leg.kind === "kas") return `Native KAS, ${leg.amount} sompi (${leg.amount_kas} KAS)`;
  if (leg.kind === "kcc20") return `KCC-20 token, ${leg.amount} units`;
  return `External cash, amount ${leg.amount} (settled outside Kaspa, opaque to Impulse)`;
}

const DESTINATION_TITLES = {
  buyer_delivery: "Buyer delivery (the asset arrives here)",
  seller_proceeds: "Seller proceeds (the cash arrives here)",
  seller_refund: "Seller refund (the asset returns here)",
  buyer_refund: "Buyer refund (the cash returns here)",
};

/**
 * The four destinations as the SDK decoded and marked them. A destination that pays the party
 * that does not own it, or the authority, is shown with a warning: the contract lets those
 * parties trigger a refund, which pays the leg to the refund destination of the terms.
 */
function renderDestinations(doc, destinations) {
  return destinations.map((d) => {
    const item = el(doc, "li", { class: "destination", "data-destination": d.name, "data-pays": d.pays });
    item.append(
      el(doc, "strong", { text: DESTINATION_TITLES[d.name] ?? d.name }),
      el(doc, "code", { class: "destination-text", text: d.destination }),
      el(doc, "span", { class: "destination-mark", text: d.mark }),
    );
    if (d.pays_counterparty_or_authority) {
      item.dataset.crosses = "true";
      item.classList.add("warn");
      item.append(
        el(doc, "p", {
          class: "destination-warning",
          text: `This ${d.owner} destination pays ${d.pays.replace("_key", "")}'s key, not the ${d.owner}'s. The contract lets that party trigger a refund, which pays the leg here. If you are the ${d.owner}, do not fund these terms.`,
        }),
      );
    }
    return item;
  });
}

function renderLeg(doc, sdk, leg, role) {
  const card = el(doc, "section", { class: "leg", "data-leg": leg.name, "data-you-fund": String(leg.you_fund) });
  card.append(el(doc, "h3", { text: legTitle(leg) }), el(doc, "p", { class: "leg-kind", text: legKind(leg) }));
  // Nothing was read about a token: say so on every KCC-20 leg, vault or no vault.
  for (const w of leg.token_warnings) {
    card.append(
      el(doc, "p", {
        class: "token-warning",
        "data-code": w.code,
        text: `${w.message}. Whether the token's issuer can create supply or move it was not examined: check the token yourself before you fund.`,
      }),
    );
  }
  if (leg.vault === null) {
    card.append(el(doc, "p", { class: "no-vault", text: `No vault on this leg: ${leg.no_vault_reason}` }));
    return card;
  }
  card.append(
    el(doc, "p", { class: "label", text: "Vault address" }),
    el(doc, "code", { class: "vault-address", text: leg.vault.address }),
  );
  if (!leg.you_fund) {
    // The counterparty's vault: the address is shown so it can be recognised, with no URI, no QR
    // code and no token owner. Anything sent here is not the user's.
    card.append(
      el(doc, "p", {
        class: "depositor-note send-nothing",
        text: `Not yours. You are the ${role}: send nothing to this address. Only the ${leg.depositor} funds this vault, and funds sent to it are refunded to the ${leg.depositor}'s refund destination, not to you.`,
      }),
    );
    return card;
  }
  card.append(
    el(doc, "p", {
      class: "depositor-note",
      text: `You fund this vault as the ${leg.depositor}. Check the address and the amount before you send.`,
    }),
  );
  if (leg.funding_uri !== null) {
    card.append(
      el(doc, "p", { class: "label", text: "Funding URI" }),
      el(doc, "code", { class: "funding-uri", text: leg.funding_uri }),
      el(doc, "p", {
        class: "uri-note",
        text: `Send exactly ${leg.amount_kas} KAS (${leg.amount} sompi). Confirm your wallet shows that amount before you send.`,
      }),
      qrSvg(doc, sdk.qrCode(leg.funding_uri)),
    );
  } else if (leg.kind === "kcc20") {
    card.append(
      el(doc, "p", { class: "label", text: "Escrowed token owner (SCRIPT_HASH)" }),
      el(doc, "code", { class: "token-owner", text: leg.vault.script_hash }),
      el(doc, "p", {
        class: "uri-note",
        text: "A KCC-20 leg is funded with the token and a little KAS in two outputs; there is no single funding URI for it.",
      }),
    );
  }
  return card;
}

/** Shows why the SDK did not start. The page derives nothing. */
export function showStartupFailure(doc, error) {
  const status = doc.getElementById("status");
  status.dataset.state = "error";
  status.textContent = `The SDK did not start: ${error && error.message ? error.message : String(error)}`;
}

/**
 * Wires the page. `sdk` is the SDK's module namespace, already initialised; `config` holds
 * `valueCapSompi`.
 */
export async function mount(doc, sdk, config) {
  const $ = (id) => doc.getElementById(id);
  const win = doc.defaultView;
  const form = $("terms-form");
  // `nodeDaa` is the creation score the node last gave, as text; the score counts as read from a
  // node only while the field still holds exactly that.
  const state = { mainnet: false, touched: false, nodeDaa: null };
  // The page's network is passed so that the client refuses a request on a connection checked for
  // the other network.
  const node = new NodeClient(sdk, win.WebSocket, () => (state.mainnet ? "mainnet" : "testnet"));
  let actions = null;
  let wallets = null;

  const showCap = () => {
    try {
      $("cap-kas").textContent = sdk.kasFromSompi(config.valueCapSompi);
    } catch {
      $("cap-kas").textContent = "an invalid cap, so every trade is refused";
    }
  };
  showCap();
  form.querySelector('[data-path="version"]').value = String(sdk.termsVersion());

  const echo = (id, sompi) => {
    try {
      $(id).textContent = sompi === "" ? "" : `${sdk.kasFromSompi(sompi)} KAS`;
    } catch {
      $(id).textContent = "";
    }
  };

  /**
   * What the user says about themselves: the role, their public key, optional pins, and the keys
   * that live only in this page's wallets (the SDK refuses, on mainnet, a destination of the role
   * that pays one of them, and says so on testnet).
   */
  const partyFromForm = () => {
    const role = $("role").value;
    if (role === "") return null;
    const pin = (id) => ($(id).value === "" ? null : $(id).value);
    return {
      role,
      key: $("my-key").value,
      pins: { receive: pin("pin-receive"), refund: pin("pin-refund") },
      held: wallets.heldKeys(),
    };
  };

  const clearResult = () => {
    $("summary").replaceChildren();
    $("destination-list").replaceChildren();
    $("destinations").hidden = true;
    $("legs").replaceChildren();
    $("decoded").hidden = true;
    $("terms-decoded").textContent = "";
  };

  const setStatus = (stateName, text, code = "") => {
    const status = $("status");
    status.dataset.state = stateName;
    status.dataset.code = code;
    status.textContent = text;
  };

  /** The whole derivation. Nothing is shown unless the SDK returns instructions. */
  const compute = () => {
    state.touched = true;
    clearResult();
    actions.available(false);
    const cashLeg = form.querySelector('[data-path="cash_leg.kind"]').value === "kas";
    echo("cash-kas", cashLeg ? form.querySelector('[data-path="cash_leg.amount"]').value : "");
    echo("kas-equivalent-kas", $("kas-equivalent").value);
    let terms;
    let validated;
    try {
      terms = sdk.Terms.fromJson(readForm(form));
      validated = terms.validateStructure();
      // Nothing is derived before the user says who they are: the SDK's role check is part of
      // every instruction it returns.
      const party = partyFromForm();
      if (party === null) {
        setStatus(
          "role",
          "Terms read. Say which party you are, and give your public key, to see what you fund. Nothing is shown until the destinations of your role have been checked.",
        );
        return;
      }
      const fromNode = state.nodeDaa !== null && $("creation-daa").value === state.nodeDaa;
      const options = {
        context: { network: state.mainnet ? "mainnet" : "testnet", creation_daa: $("creation-daa").value },
        // "node" only while the field holds the score the connected node gave and nothing else.
        creation_daa_source: fromNode ? "node" : "typed",
        party,
        cap: config.valueCapSompi,
      };
      if ($("kas-equivalent").value !== "") options.kas_equivalent = $("kas-equivalent").value;
      const out = validated.fundingInstructions(options);
      const v = out.value;
      const rows = [
        ["Network", out.network],
        ["You", `${out.role.role}, key ${out.role.key}`, "role"],
        ["Role check", out.role.lines.join("; "), "role-check"],
        ["Terms hash", out.terms_hash, "terms-hash"],
        ["Template hash", out.template_hash],
        [
          "Creation DAA score",
          out.creation_daa_source === "node"
            ? `${out.creation_daa} (read from the node at ${node.url})`
            : `${out.creation_daa} (as you entered it, not read from a node)`,
        ],
        [
          "Expiry",
          `DAA score ${out.expiry.expiry_daa}, ${out.expiry.time_left} after the creation score above, at the nominal 10 DAA scores a second (the real rate varies)`,
        ],
        [
          "Value",
          `${v.value_kas} KAS (${v.value} sompi; declared ${v.declared}, largest native KAS leg ${v.largest_kas_leg}), within the cap of ${v.cap_kas} KAS`,
        ],
      ];
      // Everything is built before anything is shown, so a failure part way shows nothing.
      const destinations = renderDestinations(doc, out.destinations);
      const cards = out.legs.map((leg) => renderLeg(doc, sdk, leg, out.role.role));
      const decoded = JSON.stringify(terms.toJson(), null, 2);
      for (const [k, text, field] of rows) {
        const dd = el(doc, "dd", { text });
        if (field) dd.dataset.field = field;
        $("summary").append(el(doc, "dt", { text: k }), dd);
      }
      $("destination-list").append(...destinations);
      $("destinations").hidden = false;
      $("legs").append(...cards);
      $("terms-decoded").textContent = decoded;
      $("decoded").hidden = false;
      const termsJson = terms.toJson();
      actions.setMode(termsJson.settlement_mode, out.role.role, termsJson.cash_leg.kind);
      actions.available(true);
      // What ran, and what did not.
      setStatus(
        "ok",
        "Terms structure, creation checks, the role check and the value cap passed. NOT checked: who controls a script destination you pinned, and the token. Read the four destinations below before you fund.",
      );
    } catch (e) {
      const code = e && typeof e.code === "string" ? e.code : "";
      setStatus("refused", `Refused: ${e && e.message ? e.message : String(e)}`, code);
    } finally {
      validated?.free();
      terms?.free();
    }
  };

  const refuse = (e) => {
    clearResult();
    const code = e && typeof e.code === "string" ? e.code : "";
    setStatus("refused", `Refused: ${e && e.message ? e.message : String(e)}`, code);
  };

  /**
   * Fills the form from terms the SDK read (`terms` stays the caller's), starts a fresh KAS
   * declaration, and has the SDK compare what the form now holds with `terms` before anything
   * is derived: a form that changed a field on the way is refused, not trusted.
   */
  const loadTerms = (terms) => {
    fillForm(form, terms.toJson());
    $("kas-equivalent").value = "";
    echo("kas-equivalent-kas", "");
    let back;
    try {
      back = sdk.Terms.fromJson(readForm(form));
      back.requireSameAs(terms);
    } catch (e) {
      refuse(e);
      return;
    } finally {
      back?.free();
    }
    compute();
  };

  /** Terms text, pasted or fetched, through the SDK's reader. */
  const loadText = (text) => {
    let terms;
    try {
      terms = sdk.Terms.fromFileText(text);
    } catch (e) {
      refuse(e);
      return;
    }
    try {
      loadTerms(terms);
    } finally {
      terms.free();
    }
  };

  const loadError = (text) => {
    $("load-error").hidden = text === "";
    $("load-error").textContent = text;
  };

  const setNodeStatus = (stateName, text, code = "") => {
    const out = $("node-status");
    out.dataset.state = stateName;
    out.dataset.code = code;
    out.textContent = text;
  };
  const network = () => (state.mainnet ? "mainnet" : "testnet");
  const ctx = {
    node,
    network,
    mainnet: () => state.mainnet,
    changed: () => actions?.refresh(),
    // A key was made: the role check reads the keys held in the page, so it runs again.
    walletsChanged: () => {
      if (state.touched) compute();
    },
    useKey(field, hex) {
      const input = field === "my-key" ? $("my-key") : form.querySelector(`[data-path="${field}"]`);
      input.value = hex;
      input.dispatchEvent(new win.Event("input", { bubbles: true }));
    },
    currentTerms() {
      const terms = sdk.Terms.fromJson(readForm(form));
      try {
        return terms.validateStructure();
      } finally {
        terms.free();
      }
    },
    termsMode: () => form.querySelector('[data-path="settlement_mode"]').value,
    valueDeclaration() {
      const declaration = { max_value: config.valueCapSompi };
      if ($("kas-equivalent").value !== "") declaration.kas_equivalent = $("kas-equivalent").value;
      return declaration;
    },
    get wallets() {
      return wallets;
    },
  };
  actions = mountActions(doc, win, sdk, ctx);
  wallets = mountWallets(doc, win, sdk, ctx);
  actions.refresh();

  $("node-connect").addEventListener("click", async () => {
    setNodeStatus("working", "Connecting.");
    try {
      const info = await node.connect($("node-url").value.trim(), network());
      setNodeStatus(
        "connected",
        `Connected to ${node.url}: ${info.network_id}, synced, at DAA score ${info.virtual_daa_score}.${info.has_utxo_index ? "" : " The node has no UTXO index, so it cannot list UTXOs."}`,
      );
    } catch (e) {
      const { code, message } = describe(e);
      setNodeStatus("error", code === "" ? `Not connected: ${message}` : `Refused: ${message}`, code);
    }
  });
  $("read-daa").addEventListener("click", async () => {
    try {
      const info = await node.serverInfo();
      $("creation-daa").value = info.virtual_daa_score;
      state.nodeDaa = info.virtual_daa_score;
      compute();
    } catch (e) {
      const { code, message } = describe(e);
      setNodeStatus("error", code === "" ? `Not read: ${message}` : `Refused: ${message}`, code);
    }
  });

  // Golden vectors, shipped beside the page.
  try {
    const names = await (await fetch("examples/index.json")).json();
    for (const name of names) $("example").append(el(doc, "option", { value: name, text: name.replace(/\.json$/, "") }));
  } catch (e) {
    loadError(`The golden vectors could not be listed: ${e.message}`);
  }
  $("load-example").addEventListener("click", async () => {
    loadError("");
    let text;
    try {
      const response = await fetch(`examples/${$("example").value}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      text = await response.text();
    } catch (e) {
      loadError(`The vector could not be loaded: ${e.message}`);
      return;
    }
    loadText(text);
  });
  $("load-json").addEventListener("click", () => {
    loadError("");
    loadText($("terms-json").value);
  });

  form.addEventListener("input", () => {
    updateVisibility(form);
    compute();
  });
  form.addEventListener("change", () => {
    updateVisibility(form);
    compute();
  });
  $("new-nonce").addEventListener("click", () => {
    // A nonce only tells otherwise identical trades apart; it is not a key.
    form.querySelector('[data-path="nonce"]').value = crypto.getRandomValues(new BigUint64Array(1))[0].toString();
    compute();
  });
  $("mainnet-switch").addEventListener("change", () => {
    state.mainnet = $("mainnet-switch").checked;
    $("mainnet-notice").hidden = !state.mainnet;
    $("network-name").textContent = state.mainnet ? "mainnet" : "testnet";
    doc.body.dataset.network = state.mainnet ? "mainnet" : "testnet";
    // A node was checked for the other network: the connection is closed, and one still opening is
    // abandoned, always; a score read from it is no longer one the page can call read from the node
    // of this network.
    const had = node.connected || node.connecting;
    node.close();
    if (had) setNodeStatus("idle", "Disconnected: the network changed. Connect again.");
    state.nodeDaa = null;
    wallets.refreshAddresses();
    if (state.touched) compute();
  });

  doc.body.dataset.network = "testnet";
  updateVisibility(form);
  setStatus("idle", "Fill the terms or load a golden vector.");
}
