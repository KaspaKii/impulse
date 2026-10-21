// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// demo/visual/app.js: plays the event feed of demo/xchain-demo.sh as a settlement monitor: two ledgers
// (Kaspa TN10, Solana), a vault and an escrow with status chips, the shared hash lock, a progress rail
// and an event log. No framework. It reads public data only: the feed never carries the secret, and the
// "preimage revealed" line is a drawing, not a value.
//
//   live:    GET /events from server.py, Next = POST /next (the script's Enter), Start = POST /start
//   replay:  ?replay=<file>  (or ?replay alone for the newest recorded run the server finds under
//            docs/evidence/<run>/events.jsonl), Next steps through the file
"use strict";

(() => {
  const DEFAULT_REPLAY = "/replay.jsonl";
  const params = new URLSearchParams(location.search);
  const replay = params.has("replay") ? params.get("replay") || DEFAULT_REPLAY : null;
  const speed = Number(params.get("speed")) > 0 ? Number(params.get("speed")) : 1;
  const KAS_API = "https://api-tn10.kaspa.org/transactions/"; // the TN10 explorer is offline; this is the public API
  const SVG = "http://www.w3.org/2000/svg";

  const $ = (id) => document.getElementById(id);
  const app = $("app");
  app.classList.add(replay ? "mode-replay" : "mode-live");
  $("mode-pill").textContent = replay ? "REPLAY OF A RECORDED RUN" : "LIVE";

  // ---- state ---------------------------------------------------------------------------------
  const S = {
    events: [],
    cursor: 0,
    waiting: false, // the script (or the replay) is paused and Next releases it
    busy: false, // an event is animating
    started: false,
    exited: false,
    cluster: "devnet",
    assetUnits: 1,
    usdcUnits: 100000,
    bal: null, // {kaspa:{seller,buyer}, solana:{seller,buyer}}
    vault: 0,
    htlc: 0,
    before: null,
    step: 0,
    hash: null,
    logged: 0,
  };

  // ---- helpers -------------------------------------------------------------------------------
  const short = (s, a = 8, b = 6) => (!s ? "" : s.length <= a + b + 1 ? s : `${s.slice(0, a)}…${s.slice(-b)}`);
  const fmtKas = (n) => String(n);
  const fmtUsdc = (n) => {
    const s = (n / 1e6).toFixed(6).replace(/0+$/, "");
    const [i, f = ""] = s.split(".");
    return `${i}.${f.padEnd(2, "0")}`;
  };
  const fmt = (chain, n) => (chain === "kaspa" ? fmtKas(n) : fmtUsdc(n));
  const clusterName = () => ({ devnet: "DEVNET", localnet: "LOCALNET" }[S.cluster] || String(S.cluster).toUpperCase());
  const clusterTitle = () => ({ devnet: "devnet", localnet: "localnet" }[S.cluster] || String(S.cluster));
  const chainName = (c) => ({ kaspa: "KASPA TN10", solana: `SOLANA ${clusterName()}`, offchain: "OFF CHAIN", both: "BOTH CHAINS" }[c] || "");
  const actorName = (a) => ({ seller: "SELLER", buyer: "BUYER" }[a] || "");
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  const waits = new Set();
  const anims = new Set();
  const wait = (ms) =>
    new Promise((res) => {
      const done = () => { clearTimeout(t); waits.delete(done); res(); };
      const t = setTimeout(done, ms / speed);
      waits.add(done);
    });
  function skip() {
    for (const f of [...waits]) f();
    for (const a of [...anims]) { try { a.finish(); } catch (_) { /* already gone */ } }
  }
  function animate(node, frames, opts) {
    const a = node.animate(frames, { ...opts, duration: opts.duration / speed });
    anims.add(a);
    const p = a.finished.catch(() => {}).then(() => anims.delete(a));
    return { a, p };
  }

  // A hash, an address or a txid: monospace, middle ellipsis, the full value in the title, a copy button.
  function monoVal(value, { a = 8, b = 6, href, prefix } = {}) {
    const box = el("span", "mono-v");
    let body = value;
    let pfx = null;
    if (prefix && value.startsWith(prefix)) { pfx = el("span", "pfx", prefix); body = value.slice(prefix.length); }
    const v = href ? el("a", "code", short(body, a, b)) : el("code", null, short(body, a, b));
    if (pfx) v.prepend(pfx);
    if (href) { v.href = href; v.target = "_blank"; v.rel = "noopener noreferrer"; }
    v.title = value;
    box.append(v);
    const c = el("button", "copy");
    c.type = "button";
    c.title = "Copy";
    c.setAttribute("aria-label", `Copy ${value}`);
    c.innerHTML = '<svg aria-hidden="true"><use href="#i-copy"/></svg>';
    c.addEventListener("click", () => {
      const ok = () => { c.classList.add("ok"); setTimeout(() => c.classList.remove("ok"), 900); };
      if (navigator.clipboard) navigator.clipboard.writeText(value).then(ok, () => {});
    });
    box.append(c);
    return box;
  }
  const txHref = (chain, txid, url) => (chain === "kaspa" ? KAS_API + txid : url);
  const txVal = (chain, txid, url, a = 8, b = 6) => monoVal(txid, { a, b, href: txHref(chain, txid, url) });

  function chipEl(state, text) {
    return el("span", `chip chip-${state}`, text);
  }
  function setChip(node, state, text) {
    node.replaceChildren(chipEl(state, text));
  }

  // ---- ledger rows ---------------------------------------------------------------------------
  const rowOf = { "kaspa.seller": "k-seller", "kaspa.buyer": "k-buyer", "solana.seller": "s-seller", "solana.buyer": "s-buyer" };
  const cell = (rowId, role) => $(rowId).querySelector(`[data-role="${role}"]`);

  function setNow(rowId, text, flash) {
    const n = cell(rowId, "now");
    if (n.textContent === text && !flash) return;
    n.textContent = text;
    if (flash) { n.classList.remove("chg"); void n.offsetWidth; n.classList.add("chg"); }
  }
  function renderBalances(flash) {
    if (!S.bal) return;
    for (const chain of ["kaspa", "solana"]) {
      for (const who of ["seller", "buyer"]) setNow(rowOf[`${chain}.${who}`], fmt(chain, S.bal[chain][who]), flash);
    }
    setNow("vault", fmtKas(S.vault));
    setNow("htlc", fmtUsdc(S.htlc));
  }
  function setStore(id, state, text) {
    setChip(cell(id, "status"), state, text);
  }
  function setAccountTag(rowId, state, text) {
    const n = cell(rowId, "status");
    if (!text) { n.replaceChildren(); return; }
    setChip(n, state, text);
  }
  function activate(ids) {
    for (const r of document.querySelectorAll(".ltable tr.active")) r.classList.remove("active");
    for (const id of ids) $(id) && $(id).classList.add("active");
  }
  function panelsLive(chain) {
    $("panel-kaspa").classList.toggle("live", chain === "kaspa" || chain === "both");
    $("panel-solana").classList.toggle("live", chain === "solana" || chain === "both");
  }
  // The per-ledger transaction table: PENDING until the feed reports the txid, FINAL when the run completes.
  function setTx(rowId, chain, txid, url) {
    const r = $(rowId);
    if (!r || !txid) return;
    r.classList.add("has");
    r.querySelector('[data-role="tx"]').replaceChildren(txVal(chain, txid, url, 10, 8));
    setChip(r.querySelector('[data-role="status"]'), "funded", "SUBMITTED");
  }

  // ---- timeline and caption -------------------------------------------------------------------
  function timeline(step, done) {
    for (const li of document.querySelectorAll("#timeline li")) {
      const n = Number(li.dataset.step);
      li.classList.toggle("done", n < step || (n === step && done));
      li.classList.toggle("cur", n === step && !done);
      if (n === step && !done) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
    }
  }
  function caption(e) {
    $("caption").hidden = false;
    app.classList.remove("nocap");
    $("cap-step").textContent = e.step >= 1 ? `STEP ${e.step} OF 7` : "";
    $("cap-chain").textContent = chainName(e.chain);
    $("cap-actor").textContent = actorName(e.actor);
    const t = $("cap-text");
    t.textContent = e.text || "";
    t.classList.remove("in"); void t.offsetWidth; t.classList.add("in");
  }
  function capItem(label, node) {
    const box = el("div", "kvi");
    box.append(el("span", null, label), node);
    return box;
  }
  // A static status with elapsed seconds, in place of an animated bar.
  function waitChip() {
    const c = el("span", "chip chip-info", "WAITING 0 s");
    const t0 = Date.now();
    const id = setInterval(() => {
      if (!c.isConnected) { clearInterval(id); return; }
      c.textContent = `WAITING ${Math.floor((Date.now() - t0) / 1000)} s`;
    }, 1000);
    return c;
  }
  function chips(list) {
    $("cap-chips").replaceChildren(...list);
  }

  // ---- event log ------------------------------------------------------------------------------
  const pad = (n) => String(n).padStart(2, "0");
  function logEvent(e) {
    const d = new Date();
    const tr = el("tr", e.phase === "warning" ? "warn" : e.phase === "error" ? "err" : e.reveals_secret ? "reveal" : "");
    const chainLabel = e.chain === "solana" ? `Solana ${clusterTitle()}` : { kaspa: "Kaspa TN10", offchain: "Off chain", both: "Both" }[e.chain] || "";
    const actor = { seller: "Seller", buyer: "Buyer", both: "Both" }[e.actor] || "";
    tr.append(
      el("td", "t-time", `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`),
      el("td", null, e.step >= 1 ? String(e.step) : "-"),
      el("td", null, chainLabel),
      el("td", null, actor),
      el("td", "t-text", e.text || "")
    );
    tr.lastChild.title = e.text || "";
    const tx = el("td");
    if (e.txid) tx.append(txVal(e.chain, e.txid, e.url, 10, 8));
    else tx.append(el("span", "muted", "-"));
    tr.append(tx);
    $("log-body").append(tr);
    S.logged++;
    $("log").classList.remove("empty");
    $("log-empty").hidden = true;
    $("log-count").textContent = `${S.logged} ${S.logged === 1 ? "event" : "events"}`;
    pinLog();
  }
  function pinLog() {
    const sc = $("log-scroll");
    sc.scrollTop = sc.scrollHeight;
  }
  // The log keeps its newest row in view when a warning or a resize changes its height.
  if (window.ResizeObserver) new ResizeObserver(pinLog).observe($("log-scroll"));

  // ---- transfer connectors --------------------------------------------------------------------
  // A thin line drawn from one row to another, with a small marker running along it. Skippable.
  function box(node) {
    const s = $("stage").getBoundingClientRect();
    const r = node.getBoundingClientRect();
    return { l: r.left - s.left, r: r.right - s.left, t: r.top - s.top, b: r.bottom - s.top, y: r.top - s.top + r.height / 2 };
  }
  async function trace(d, ms, kind) {
    const fly = $("fly");
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    if (kind) path.setAttribute("class", kind);
    fly.append(path);
    const len = path.getTotalLength();
    path.style.strokeDasharray = `${len}`;
    path.style.strokeDashoffset = `${len}`;
    const dot = document.createElementNS(SVG, "circle");
    dot.setAttribute("r", "3");
    if (kind) dot.setAttribute("class", kind);
    fly.append(dot);
    const steps = 24;
    const frames = Array.from({ length: steps + 1 }, (_, i) => {
      const p = path.getPointAtLength((len * i) / steps);
      return { transform: `translate(${p.x}px, ${p.y}px)` };
    });
    const line = animate(path, [{ strokeDashoffset: len }, { strokeDashoffset: 0 }], { duration: ms, easing: "ease-in-out", fill: "forwards" });
    const run = animate(dot, frames, { duration: ms, easing: "ease-in-out", fill: "forwards" });
    await Promise.all([line.p, run.p]);
    const fade = animate(path, [{ opacity: 1 }, { opacity: 0 }], { duration: 500, fill: "forwards" });
    dot.remove();
    await fade.p;
    path.remove();
  }
  // Within one ledger: a bracket just right of the "Now" column, from one row's value to the other's.
  function bracket(fromId, toId) {
    const a = box(cell(fromId, "now")), b = box(cell(toId, "now"));
    const x = a.r + 6;
    return `M ${a.r - 4} ${a.y} H ${x} V ${b.y} H ${a.r - 4}`;
  }

  // ---- hash lock ------------------------------------------------------------------------------
  function setHash(hash) {
    S.hash = hash;
    const v = $("hash-val");
    v.replaceChildren();
    const c = el("button", "copy");
    c.type = "button";
    c.title = "Copy";
    c.setAttribute("aria-label", "Copy the hash lock");
    c.innerHTML = '<svg aria-hidden="true"><use href="#i-copy"/></svg>';
    c.addEventListener("click", () => { if (navigator.clipboard) navigator.clipboard.writeText(hash).then(() => { c.classList.add("ok"); setTimeout(() => c.classList.remove("ok"), 900); }, () => {}); });
    v.append(c, document.createTextNode(hash.match(/.{1,16}/g).join(" ")));
    v.title = hash;
    $("hash").dataset.state = "set";
  }
  function bind(side) {
    $("centre").dataset[side === "kaspa" ? "k" : "s"] = "1";
    setChip($(side === "kaspa" ? "bind-k" : "bind-s"), "funded", "BOUND");
  }

  // ---- event handlers -------------------------------------------------------------------------
  async function handle(e) {
    S.busy = true;
    updateNext();
    try {
      await handlers(e);
    } finally {
      S.busy = false;
      updateNext();
    }
  }

  async function handlers(e) {
    if (e.phase === "boot") {
      showIdle("Starting", e.text, true);
      return;
    }
    if (e.phase === "ready") { logEvent(e); return onReady(e); }
    if (e.phase === "warning") { logEvent(e); return onWarning(e); }
    if (e.phase === "error") { logEvent(e); return onError(e); }
    if (e.phase === "complete") { logEvent(e); return onComplete(e); }
    if (e.phase === "info") {
      logEvent(e);
      if (e.step === 5) { caption({ ...e, step: 5 }); await wait(900); }
      return;
    }
    if (e.step >= 1) {
      S.step = e.step;
      panelsLive(e.chain);
      if (e.phase === "started") {
        timeline(e.step, false);
        caption(e);
        chips([]);
        activateFor(e);
        if (e.step === 7) chips([capItem("Kaspa claim depth", waitChip())]);
        await wait(700);
      } else if (e.phase === "done") {
        logEvent(e);
        caption(e);
        await onDone(e);
        timeline(e.step, true);
      }
    }
  }

  function activateFor(e) {
    const m = { 1: ["k-seller"], 2: ["k-buyer", "s-buyer"], 3: ["k-seller", "vault"], 4: ["s-buyer", "htlc"], 5: ["s-seller", "htlc"], 6: ["k-buyer", "vault"], 7: [] };
    activate(m[e.step] || []);
  }

  async function onDone(e) {
    if (e.step === 1) {
      setHash(e.hash_lock);
      cell("vault", "addr").replaceChildren(monoVal(e.vault, { prefix: "kaspatest:", a: 5, b: 4 }));
      setStore("vault", "empty", "EMPTY");
      setAccountTag("k-seller", "info", "HOLDS SECRET");
      setChip($("preimage"), "info", "SELLER ONLY");
      $("hash-sub").textContent = "Made by the seller. Only the preimage opens either lock.";
      chips([capItem("Vault", monoVal(e.vault, { prefix: "kaspatest:", a: 8, b: 8 }))]);
      await wait(1400);
    } else if (e.step === 2) {
      setChip($("terms"), "funded", "CHECKED");
      $("hash-sub").textContent = "Terms checked by the buyer. Nothing was sent.";
      await wait(1400);
    } else if (e.step === 3) {
      const units = Number(e.amount) || S.assetUnits;
      chips([capItem("Kaspa txid", txVal("kaspa", e.txid, e.url, 10, 8))]);
      await trace(bracket("k-seller", "vault"), 1100);
      S.bal.kaspa.seller -= units; S.vault += units;
      setNow("k-seller", fmtKas(S.bal.kaspa.seller), true);
      setNow("vault", fmtKas(S.vault), true);
      setStore("vault", "funded", "FUNDED");
      bind("kaspa");
      setTx("tx-k-lock", "kaspa", e.txid, e.url);
      await wait(700);
    } else if (e.step === 4) {
      const units = Number(e.amount) || S.usdcUnits;
      if (e.htlc) cell("htlc", "addr").replaceChildren(monoVal(e.htlc, { a: 6, b: 6 }));
      chips([capItem("Solana txid", txVal("solana", e.txid, e.url, 10, 8))]);
      await trace(bracket("s-buyer", "htlc"), 1100);
      S.bal.solana.buyer -= units; S.htlc += units;
      setNow("s-buyer", fmtUsdc(S.bal.solana.buyer), true);
      setNow("htlc", fmtUsdc(S.htlc), true);
      setStore("htlc", "funded", "FUNDED");
      bind("solana");
      setTx("tx-s-lock", "solana", e.txid, e.url);
      $("hash").dataset.state = "both";
      $("hash-sub").textContent = "The same hash now locks both legs.";
      await wait(700);
    } else if (e.step === 5) {
      // The claim moves the USDC to the seller, and the claim transaction publishes the preimage.
      const units = S.htlc;
      chips([capItem("Solana txid", txVal("solana", e.txid, e.url, 10, 8))]);
      await trace(bracket("htlc", "s-seller"), 1100);
      S.htlc = 0; S.bal.solana.seller += units;
      setNow("htlc", fmtUsdc(0), true);
      setNow("s-seller", fmtUsdc(S.bal.solana.seller), true);
      setStore("htlc", "settled", "SETTLED");
      setTx("tx-s-claim", "solana", e.txid, e.url);
      await wait(400);
      // The reveal: from the Solana claim transaction, to the preimage line of the hash lock, on to the Kaspa vault.
      const h = box($("hash")), c = box($("tx-s-claim")), pre = box($("preimage")), v = box($("vault"));
      const gr = (h.r + c.l) / 2, gl = (v.r + h.l) / 2;
      await trace(`M ${c.l} ${c.y} H ${gr} V ${pre.y} H ${h.r}`, 900, "secret");
      $("hash").classList.add("reveal");
      setChip($("preimage"), "funded", "PUBLIC");
      $("hash-sub").textContent = "The Solana claim published the preimage. Anyone can now open the Kaspa vault for the buyer.";
      await trace(`M ${h.l} ${pre.y} H ${gl} V ${v.y} H ${v.r}`, 900, "secret");
      await wait(700);
    } else if (e.step === 6) {
      const units = S.vault;
      chips([capItem("Kaspa txid", txVal("kaspa", e.txid, e.url, 10, 8))]);
      setAccountTag("k-buyer", "info", "USED PREIMAGE");
      await trace(bracket("vault", "k-buyer"), 1100);
      S.vault = 0; S.bal.kaspa.buyer += units;
      setNow("vault", fmtKas(0), true);
      setNow("k-buyer", fmtKas(S.bal.kaspa.buyer), true);
      setStore("vault", "settled", "SETTLED");
      setTx("tx-k-claim", "kaspa", e.txid, e.url);
      $("hash").classList.remove("reveal");
      await wait(700);
    }
  }

  function onReady(e) {
    S.cluster = e.cluster || "devnet";
    S.assetUnits = Number(e.asset_units) || 1;
    S.usdcUnits = Number(e.usdc_units) || 100000;
    S.bal = JSON.parse(JSON.stringify(e.bal));
    S.before = JSON.parse(JSON.stringify(e.bal));
    S.vault = 0; S.htlc = 0;
    $("sol-net").textContent = clusterName();
    $("panel-solana").setAttribute("aria-label", `Solana ${S.cluster} ledger`);
    const addr = { "k-seller": e.kaspa_seller, "k-buyer": e.kaspa_buyer, "s-seller": e.solana_seller, "s-buyer": e.solana_buyer };
    for (const [id, v] of Object.entries(addr)) {
      if (v) cell(id, "addr").replaceChildren(monoVal(v, { prefix: "kaspatest:", a: 5, b: 4 }));
    }
    for (const chain of ["kaspa", "solana"]) {
      for (const who of ["seller", "buyer"]) cell(rowOf[`${chain}.${who}`], "before").textContent = fmt(chain, S.before[chain][who]);
    }
    if (e.asset_covenant) $("k-covenant").replaceChildren(monoVal(e.asset_covenant, { a: 12, b: 10 }));
    if (e.solana_program) $("s-program").replaceChildren(monoVal(e.solana_program, { a: 12, b: 10 }));
    if (e.usdc_mint) $("s-mint").replaceChildren(monoVal(e.usdc_mint, { a: 12, b: 10 }));
    renderBalances(false);
    hideIdle();
    caption({ ...e, step: 0, text: "Two ledgers that never talk to each other, linked by one hash lock. Press Space for the first step." });
    $("cap-step").textContent = "READY";
    timeline(0, false);
    chips([]);
  }

  function onWarning(e) {
    $("freeze-text").textContent = `Freeze authority on the test mint${e.freeze_authority ? ` (${short(e.freeze_authority, 6, 4)})` : ""}, as on real USDC. The issuer could freeze the escrow.`;
    $("freeze").hidden = false;
  }

  function onError(e) {
    showError(e.text || "The demo stopped with an error.", []);
  }

  async function onComplete(e) {
    S.step = 7;
    panelsLive("both");
    timeline(7, true);
    // The authoritative balances replace the derived ones.
    S.bal = JSON.parse(JSON.stringify(e.bal));
    S.vault = 0; S.htlc = 0;
    renderBalances(false);
    setTx("tx-k-lock", "kaspa", e.fund_txid, e.fund_url);
    setTx("tx-s-lock", "solana", e.open_txid, e.open_url);
    setTx("tx-s-claim", "solana", e.claim_txid, e.claim_url);
    setTx("tx-k-claim", "kaspa", e.kaspa_claim_txid, e.kaspa_claim_url);
    if (e.complete !== false) for (const id of ["tx-k-lock", "tx-s-lock", "tx-s-claim", "tx-k-claim"]) setChip($(id).querySelector('[data-role="status"]'), "settled", "FINAL");
    caption({ ...e, step: 7, chain: "both", actor: "both" });
    activate([]);
    const ok = e.complete !== false;
    const st = $("final-status");
    st.className = ok ? "chip chip-settled" : "chip chip-warn";
    st.textContent = ok ? "SETTLED" : "CLAIM SENT, FINALITY PENDING";
    const body = $("final-body");
    body.replaceChildren();
    const sol = `Solana ${clusterTitle()}`;
    const rows = [
      ["Asset leg", "Kaspa TN10, test asset", "kaspa", "seller", "Lock", e.fund_txid, e.fund_url, "kaspa"],
      [null, null, "kaspa", "buyer", "Claim", e.kaspa_claim_txid, e.kaspa_claim_url, "kaspa"],
      ["Cash leg", `${sol}, test USDC`, "solana", "buyer", "Lock", e.open_txid, e.open_url, "solana"],
      [null, null, "solana", "seller", "Claim", e.claim_txid, e.claim_url, "solana"],
    ];
    for (const [leg, sub, chain, who, kind, txid, url, txc] of rows) {
      const tr = el("tr", leg ? "leg-first" : "");
      const lc = el("td", "leg");
      if (leg) { lc.append(document.createTextNode(leg)); lc.append(el("small", null, sub)); }
      const from = S.before[chain][who], to = S.bal[chain][who];
      const unit = chain === "kaspa" ? "units" : "USDC";
      const num = (n, cls) => { const c = el("td", `num ${cls}`, fmt(chain, n)); c.append(el("span", "unit", unit)); return c; };
      const txc2 = el("td");
      txc2.append(el("span", "txk", kind));
      if (txid) txc2.append(txVal(txc, txid, url, 12, 10)); else txc2.append(el("span", "muted", "-"));
      tr.append(lc, el("td", null, who === "seller" ? "Seller" : "Buyer"), num(from, ""), num(to, to > from ? "after gain" : "after"), txc2);
      body.append(tr);
    }
    const risk = $("final-risk");
    risk.replaceChildren(el("b", null, "RESIDUAL RISK"), document.createTextNode("Test networks, test tokens. A conditional exchange with residual risk, not atomic settlement."));
    chips([]);
    await wait(1500);
    $("final").hidden = false;
  }

  // ---- idle, errors, Next ---------------------------------------------------------------------
  function showIdle(title, sub, boot) {
    $("idle").hidden = false;
    $("idle").classList.toggle("boot", !!boot);
    $("idle-title").textContent = title;
    $("idle-sub").textContent = sub;
  }
  function hideIdle() { $("idle").hidden = true; }
  function showError(text, tail) {
    const bar = $("errbar");
    bar.hidden = false;
    bar.replaceChildren();
    const b = document.createElement("b"); b.textContent = "Stopped. ";
    bar.append(b, document.createTextNode(text));
    if (tail && tail.length) { const c = document.createElement("code"); c.textContent = tail.join("\n"); bar.append(c); }
  }
  function nodeState(state, label) {
    $("node").dataset.state = state;
    $("node-label").textContent = label;
  }

  function updateNext() {
    const b = $("next"), l = $("next-label");
    let mode, label;
    if (!replay && !S.started) { mode = "idle"; label = "Start"; }
    else if (S.busy) { mode = "busy"; label = "Skip"; }
    else if (S.waiting) { mode = "ready"; label = S.cursor >= S.events.length && S.step >= 7 ? "Done" : "Next"; }
    else if (replay && S.cursor >= S.events.length) { mode = "done"; label = "End"; }
    else if (S.exited && S.cursor >= S.events.length) { mode = "done"; label = S.step >= 7 ? "Done" : "Stopped"; }
    else { mode = "working"; label = "Working"; }
    b.dataset.mode = mode;
    l.textContent = label;
    app.dataset.state = mode;
  }

  async function post(path) {
    const r = await fetch(path, { method: "POST", headers: { "X-Impulse-Demo": "1" } });
    return r.ok;
  }

  async function onNext() {
    if (!$("final").hidden && S.step >= 7) { $("final").hidden = true; return; }
    if (!replay && !S.started) {
      S.started = true;
      showIdle("Starting", "Checking the tools, the keys, the balances and both networks.", true);
      updateNext();
      try { if (!(await post("/start"))) throw new Error("start refused"); } catch (err) {
        S.started = false; showIdle("Could not start", "The driver refused. Is another run going?", false); updateNext();
      }
      return;
    }
    if (S.busy) { skip(); return; }
    if (S.waiting) {
      S.waiting = false;
      updateNext();
      if (!replay) { try { await post("/next"); } catch (_) { /* shown by the status poll */ } }
      pump();
    }
  }

  async function pump() {
    if (pump.running) return;
    pump.running = true;
    while (S.cursor < S.events.length) {
      const e = S.events[S.cursor++];
      if (e.phase === "pause") { S.waiting = true; break; }
      await handle(e);
    }
    pump.running = false;
    updateNext();
  }

  // ---- feeds ----------------------------------------------------------------------------------
  function ingest(text) {
    const lines = text.split("\n").filter((l) => l.trim());
    let added = 0;
    for (let i = S.events.length; i < lines.length; i++) {
      try { S.events.push(JSON.parse(lines[i])); added++; } catch (_) { break; } // a half-written line: next poll
    }
    if (added) pump();
  }

  async function poll() {
    try {
      const r = await fetch("/events", { cache: "no-store" });
      if (r.ok) ingest(await r.text());
      const st = await (await fetch("/status", { cache: "no-store" })).json();
      nodeState("ok", st.state === "running" ? "Driver running" : st.state === "exited" ? "Driver idle" : "Driver ready");
      if (st.state === "running") S.started = true;
      if (st.state === "exited" && !S.exited) {
        S.exited = true;
        S.started = true;
        if (st.code !== 0 && !S.events.some((x) => x.phase === "error")) showError(`The script exited with code ${st.code}. The terminal has the reason.`, st.tail);
        else if (st.code !== 0) showError(`The script exited with code ${st.code}.`, st.tail);
      }
      updateNext();
    } catch (_) {
      nodeState("down", "Driver offline");
      showError("The driver is not answering. Is demo/visual/server.py still running?", []);
    }
    setTimeout(poll, 450);
  }

  async function loadReplay() {
    try {
      const r = await fetch(replay, { cache: "no-store" });
      if (!r.ok) throw new Error(String(r.status));
      ingest(await r.text());
      if (!S.events.length) throw new Error("empty");
      nodeState("wait", "Recorded feed");
    } catch (err) {
      nodeState("down", "No feed");
      showIdle("Replay file not found", `Could not read ${replay}`, false);
    }
  }

  // ---- keys -----------------------------------------------------------------------------------
  document.addEventListener("keydown", (ev) => {
    if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
    // Enter or Space on a focused link or copy button acts on that control, not on Next.
    const own = (ev.target instanceof HTMLAnchorElement || (ev.target instanceof HTMLButtonElement && ev.target.id !== "next"));
    if (own && (ev.key === " " || ev.key === "Enter")) return;
    if (ev.key === " " || ev.key === "Enter" || ev.key === "ArrowRight" || ev.key === "n") {
      ev.preventDefault();
      onNext();
    } else if (ev.key === "Escape") {
      if (S.step >= 7 && S.events.some((x) => x.phase === "complete")) $("final").hidden = !$("final").hidden;
    } else if (ev.key === "r" && replay) {
      location.reload();
    } else if (ev.key === "f") {
      if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen().catch(() => {});
    }
  });
  $("next").addEventListener("click", onNext);

  // The two hairlines from the hash lock meet the ledgers at the height of the vault and escrow rows.
  function placeLinks() {
    const c = $("centre").getBoundingClientRect(), v = $("vault").getBoundingClientRect();
    $("centre").style.setProperty("--ly", `${Math.round(v.top - c.top + v.height / 2)}px`);
  }
  addEventListener("resize", placeLinks);
  placeLinks();

  // ---- go -------------------------------------------------------------------------------------
  if (replay) {
    $("log-note").textContent = "Times are playback times of the recorded run.";
    showIdle("Replay", "Loading the recorded run.", true);
    loadReplay().then(updateNext);
  } else {
    showIdle("Press Space to start", "A Kaspa test asset against Solana test USDC, linked by one hash lock.", false);
    poll();
  }
  updateNext();
})();
