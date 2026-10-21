// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The two trades of the I11 exit test, as a key holder makes them on mainnet, in a real browser against an offline node (crates/impulse-wasm/npm/test/fakenode.ts
// behind Playwright's WebSocket routing), with the key holder's side played by the SDK:
//
//   Vault.  The seller, a key held outside the page, has funded the KCC-20 asset vault with the
//           command line. The buyer is wallet B of the page: it funds the KAS cash vault from the
//           page, and the page settles.
//   Direct. The seller's token is owned by a key the page does not hold. The page builds the Direct
//           transaction, wallets A and B sign their inputs, the page hands the partly signed
//           transaction over as text, the key holder signs the token input outside the page
//           (`impulse ipst sign --role seller`), and the page adds that signature and submits.
//
// "Outside the page" is a runtime throwaway key in this process, made by the SDK's Wallet and freed
// at the end of the test; it signs with the same checks, in the same order, as the command line's
// `ipst sign`. One difference, which the terms below allow for: the SDK's wallet refuses on mainnet
// to pay its own key (nothing in a page can spend it), so the seller's two destinations pay another
// key, which the key holder pins, where the command line would let them pay the seller's own key.
// No key is written anywhere: the command line itself reads a key file, so the real binary is not
// run here (the brief says so). The fake node runs no script and verifies no signature, so these
// tests show that the page drives the SDK through each sequence and sends only what it should, not
// that a real node accepts the result. Each refusal sits beside an accepted control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { schnorr } from "../../crates/impulse-wasm/npm/node_modules/@noble/curves/secp256k1.js";
import {
  NODE_URL,
  build,
  channelsOf,
  decode,
  drawnKeys,
  fact,
  frames,
  hexOf,
  kasText,
  needs,
  openDecoder,
  prepare,
  rows,
  sdkOf,
  sentCount,
  signWith,
  submitAndWait,
  text,
  until,
  withTrade,
  type TestSdk,
  type Trade,
} from "./session.ts";
import {
  AMOUNT_A,
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  CASH_ARTIFACT,
  EXPIRY,
  KAS_CASH,
  NOW,
  addressFor,
  externalTermsFor,
  kcc20CashTermsFor,
  ownToken,
  p2pk,
  termsFor,
  utxo,
  vaultUtxos,
  type Mode,
} from "./world.ts";
import { partyFor, pinOf, type PageParty } from "./party.ts";
import { spellingsOf } from "./spellings.ts";

const kasTo = (key: string) => ({ kind: "kas", version: 0, script: `20${key}ac` });
const ownerOf = (key: string) => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });

/** A public key held in no wallet of the page: an address elsewhere. */
function newKey(sdk: TestSdk): string {
  const w = sdk.Wallet.generate();
  const key = w.publicKey();
  w.free();
  return key;
}

/**
 * The terms of the page trade: the seller a key held outside the page, the buyer wallet B,
 * and the buyer's two destinations (the delivery and the refund) an address elsewhere, because on
 * mainnet the SDK refuses a destination that pays a key of the page. The seller's two destinations
 * pay `sellerCold`, a third key held outside the page (see the header).
 */
function pageTradeTerms(sdk: TestSdk, mode: Mode, seller: string, buyer: string, cold: string, sellerCold: string) {
  return {
    ...termsFor(sdk, mode, seller, buyer, "mainnet"),
    buyer_delivery: ownerOf(cold),
    buyer_refund: kasTo(cold),
    seller_proceeds: kasTo(sellerCold),
    seller_refund: ownerOf(sellerCold),
  };
}

/** The address of the cash vault of `terms`, written by the tests' own encoder. */
function cashVaultAddress(sdk: TestSdk, terms: unknown, network: "mainnet" | "testnet"): string {
  const spk = sdk.Terms.fromJson(terms).validateStructure().instantiateExisting(1).scriptPublicKey();
  return addressFor(network)({ version: spk.version, script: hexOf(spk.script) });
}

/** The address of the asset vault of `terms`, and of the token escrowed in it, as the tests' own encoder writes them. */
function assetLegAddresses(sdk: TestSdk, terms: unknown, network: "mainnet" | "testnet"): { vault: string; escrow: string } {
  const vault = sdk.Terms.fromJson(terms).validateStructure().instantiateExisting(0);
  const spk = vault.scriptPublicKey();
  const escrow = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
    identifier_type: "script_hash",
    identifier: hexOf(vault.scriptHash()),
    amount: AMOUNT_A.toString(),
    is_minter: false,
  });
  return { vault: addressFor(network)({ version: spk.version, script: hexOf(spk.script) }), escrow: addressFor(network)(escrow) };
}

/** The seller's funding of the asset leg, as it sits on the node: the authorizer and the escrowed token. */
function seedAssetLeg(t: Trade): void {
  const [assetAuthorizer, assetEscrow] = vaultUtxos(t.sdk, t.terms, t.keys.b);
  t.fake.add(assetAuthorizer);
  t.fake.add(assetEscrow);
}

/** What the key holder's `impulse ipst sign --role seller` does with an exported document. */
function holderSigns(
  sdk: TestSdk,
  holder: any,
  ipstText: string,
  party: PageParty | null,
  network: "mainnet" | "testnet" = "mainnet",
): string {
  const ipst = sdk.Ipst.fromJson(ipstText);
  const out = holder.sign(ipst, {
    artifacts: { asset: ASSET_ARTIFACT, cash: null },
    current_daa: NOW.toString(),
    value: { kas_equivalent: KAS_CASH.toString() },
    mainnet: network === "mainnet",
    ...(party === null ? {} : { pins: { receive: party.receive, refund: party.refund } }),
  });
  const signed = out.ipst.toJson() as string;
  out.ipst.free();
  ipst.free();
  return signed;
}

const importStatus = async (page: Trade["page"]) => ({
  state: (await page.getAttribute("#import-status", "data-state")) ?? "",
  code: (await page.getAttribute("#import-status", "data-code")) ?? "",
  text: (await text(page, "#import-status")) ?? "",
});

/** Pastes `value` into the import box, presses the button and returns what the page says. */
async function importText(page: Trade["page"], value: string) {
  await page.fill("#import-text", value);
  await page.click("#import-apply");
  return importStatus(page);
}

const signedFlags = async (page: Trade["page"]) => (await rows(page, "#review-inputs-body")).map((r) => r.signed);

// The Vault path.

test("Vault path on mainnet: the seller's key is outside the page, the buyer's wallet funds the KAS cash vault from the page, the page settles, and the decoder reads the trade back", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, addresses, s, terms } = t;
        const coldAddress = pinOf("mainnet", kasTo(cold));
        const buyer = partyFor("buyer", terms as never);
        assert.deepEqual([buyer.receive, buyer.refund], [`kcc20:pubkey:${cold}`, coldAddress]);
        // What the seller's command-line funding left on the node: the asset leg in its vault (the
        // authorizer and the escrowed token). The cash vault is empty. Wallet B holds the coin that
        // will fund it, wallet A the coin that will pay the settle's fee.
        const [assetAuthorizer, assetEscrow] = vaultUtxos(sdk, terms, keys.b);
        fake.add(assetAuthorizer);
        fake.add(assetEscrow);
        fake.add(utxo("buyer-funding-coin", 200_000_000n, p2pk(keys.b)));
        fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
        const vaultAddress = cashVaultAddress(sdk, terms, "mainnet");
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: coldAddress });
        assert.equal(await page.getAttribute("body", "data-network"), "mainnet");
        assert.equal(await page.isVisible("#mainnet-notice"), true, "the risk notice is up");

        // The funding is offered, to the buyer of this trade; the settle is too.
        assert.equal(await page.isVisible("#fund-options"), true);
        assert.equal(await page.isVisible("#build-fund"), true);
        assert.equal(await text(page, "#build-fund"), "Build the funding of the cash leg");
        const funding = await build(page, "#build-fund");
        assert.deepEqual([funding.state, funding.code], ["ok", ""], funding.text);
        // The page asked the node for the UTXOs of the cash vault, the asset vault, the token escrowed
        // in it and the buyer's wallet, and of no other address.
        const askedFor = frames(s).filter((f) => f.method === "getUtxosByAddresses");
        const assetLeg = assetLegAddresses(sdk, terms, "mainnet");
        assert.deepEqual(askedFor[askedFor.length - 1].params.addresses, [vaultAddress, assetLeg.vault, assetLeg.escrow, addresses.b]);
        assert.match((await text(page, "#review-title")) ?? "", /^Funding of the cash leg/);
        assert.equal(await fact(page, "network"), "mainnet");
        const inputs = await rows(page, "#review-inputs-body");
        assert.equal(inputs.length, 1);
        assert.equal(inputs[0].amount, kasText(200_000_000n));
        assert.equal(inputs[0].address, addresses.b);
        assert.equal(inputs[0].signer, needs(keys.b, "buyer"));
        const outputs = await rows(page, "#review-outputs-body");
        assert.equal(outputs.length, 2, "the deposit and the change");
        assert.equal(outputs[0].amount, kasText(KAS_CASH), "exactly the cash amount");
        assert.equal(outputs[0].address, vaultAddress);
        assert.equal(outputs[0].what, "the cash vault");
        assert.equal(outputs[1].address, coldAddress, "the change goes to the address given, not to a key of the page");
        assert.ok(outputs.every((r) => r.held === null), "no output pays a key that lives only in the page");
        const fee = BigInt(/\((\d+) sompi\)/.exec((await fact(page, "fee")) ?? "")?.[1] ?? "x");
        assert.equal(outputs[1].amount, kasText(200_000_000n - KAS_CASH - fee), "the change is the coin less the deposit and the fee");
        assert.equal(await fact(page, "payer-cost"), `${KAS_CASH} sompi (1.00000000 KAS), the deposit`);
        // The review says how the deposit comes back and what closing the page does to that way out.
        const exitNote =
          `Until this trade settles, the only way you can take this deposit back yourself is a refund of the cash leg signed with the buyer's key ${keys.b}, ` +
          `from DAA score ${EXPIRY + 1n} (earmarked funding: the depositor's refund opens after the expiry, DAA score ${EXPIRY}). ` +
          "That key lives only in a wallet of this page: closing or reloading the page, or wiping the wallet, destroys it, and nothing in this page can bring it back. " +
          `The seller can also trigger that refund at any time, and it pays the buyer's refund destination (${coldAddress} (pay to x-only key)) whoever signs it, but nothing makes them.`;
        // And how long the trade has left to settle: a settle is refused at or after the expiry.
        const windowNote =
          `A settle of this trade can be built only before the expiry, DAA score ${EXPIRY}: at or after it the settle is refused (TX_EXPIRED). ` +
          `The node is at DAA score ${NOW}, so this funding, once accepted, has ${EXPIRY - BigInt(NOW)} DAA scores (about 13 hours at the nominal 10 DAA scores a second; the real rate varies) to be listed by the node and settled. ` +
          "A trade that is not settled by then can only be refunded.";
        assert.deepEqual(await page.locator("#review-notes .review-note").allTextContents(), [exitNote, windowNote]);
        assert.deepEqual(
          await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)),
          ["Sign with wallet B (input 0)"],
          "only the buyer's wallet has anything to sign",
        );
        assert.equal(await page.isDisabled("#submit"), true, "nothing is signed yet");
        const signedFund = await signWith(page, "b");
        assert.deepEqual([signedFund.state, signedFund.code], ["ok", ""], signedFund.text);
        const sentFund = await submitAndWait(page);
        assert.equal(sentFund.state, "ok", sentFund.text);
        assert.ok(sentFund.text.includes("This is the funding of the cash leg."), sentFund.text);
        // What the person is told to do next, and what has and has not been observed.
        for (const sentence of [
          "Wait until the node lists the deposit at the cash vault before you build the settle",
          "that has not been observed against a real node",
          "a settle built before then is refused (SDK_UTXO_NOT_FOUND)",
          "Until the trade settles, the way you can take the deposit back yourself is a refund signed with wallet B's key, and closing this page or wiping that wallet destroys it.",
        ]) {
          assert.ok(sentFund.text.includes(sentence), `${sentence}\n${sentFund.text}`);
        }
        assert.equal(fake.accepted.length, 1);
        // The wallet that signed it is now the buyer's way to refund the deposit, and the page says
        // so on its card, and asks before it wipes it (one wallet, then both).
        const termsHash = await fact(page, "terms-hash");
        const escrowLine = `This wallet funded 1.00000000 KAS into the cash vault of the trade ${termsHash} (transaction ${fake.accepted[0].txid}), and this page has not seen it settled or refunded.`;
        assert.ok(((await text(page, "#wallet-b .wallet-escrow")) ?? "").startsWith(escrowLine), "the card of the funding wallet");
        assert.equal(await page.isVisible("#wallet-a .wallet-escrow"), false, "wallet A funded nothing");
        await page.click("#wallet-b .wallet-wipe");
        assert.equal(await page.isVisible("#wipe-confirm"), true, "Wipe asks about a wallet that funded a cash vault, though its balance was never read");
        const question = (await text(page, "#wipe-confirm-text")) ?? "";
        assert.ok(question.startsWith(`Wallet B funded 1.00000000 KAS into the cash vault of the trade ${termsHash} (transaction ${fake.accepted[0].txid}), and this page has not seen it settled or refunded. Until this trade settles, `), question);
        assert.ok(question.includes(exitNote), "the question carries the review's note");
        assert.ok(question.endsWith("A wiped wallet's key is gone, and so is whatever it holds: nothing here can send it anywhere. Wipe it anyway?"), question);
        await page.click("#wipe-confirm-no");
        assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "ready", "kept");
        await page.click("#wipe-all");
        assert.equal(await page.isVisible("#wipe-confirm"), true, "Wipe both wallets asks too");
        assert.ok(!((await text(page, "#wipe-confirm-text")) ?? "").includes("Wallet A"), "and names only the wallet that funded");
        await page.click("#wipe-confirm-no");
        // The deposit is at the cash vault, exactly the cash amount; the buyer's coin is spent.
        assert.deepEqual(fake.at(vaultAddress).map((u) => u.amount), [KAS_CASH.toString()]);
        assert.deepEqual(fake.at(addresses.b), [], "the coin is spent and its change went elsewhere");
        assert.deepEqual(fake.at(coldAddress).map((u) => u.amount), [(200_000_000n - KAS_CASH - fee).toString()]);

        // The settle: wallet A pays the fee. It builds from the deposit the funding made.
        await page.selectOption("#fee-payer", { value: "a" });
        const settle = await build(page, "#build-settle");
        assert.deepEqual([settle.state, settle.code], ["ok", ""], settle.text);
        assert.match((await text(page, "#review-title")) ?? "", /^Settle/);
        const settleInputs = await rows(page, "#review-inputs-body");
        assert.deepEqual(
          settleInputs.map((r) => r.what.replace(/ \(P2PK of the key .*$/, "")),
          ["the asset vault", "the cash vault", "the asset token escrowed in the asset vault", "a fee input"],
        );
        assert.equal(settleInputs[1].amount, kasText(KAS_CASH));
        assert.equal(settleInputs[3].address, addresses.a);
        assert.deepEqual(
          settleInputs.map((r) => r.signer),
          ["no signature", "no signature", "no signature", needs(keys.a, "other")],
          "self-settling: only the fee input takes a signature",
        );
        assert.equal((await signWith(page, "a")).state, "ok");
        const settled = await submitAndWait(page);
        assert.equal(settled.state, "ok", settled.text);
        assert.doesNotMatch(settled.text, /This is the funding/);
        assert.equal(fake.accepted.length, 2);
        // The trade settled from this page: no wallet is a refund key any more, and Wipe does not ask.
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, "the card no longer says it");
        await page.click("#wallet-b .wallet-wipe");
        assert.equal(await page.isVisible("#wipe-confirm"), false);
        assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "wiped");
        // What the node holds: the seller's side has the cash, and the seller's key the authorizer
        // back; the buyer's cold key the token.
        assert.deepEqual(fake.at(pinOf("mainnet", kasTo(sellerCold))).map((u) => u.amount), [KAS_CASH.toString()]);
        assert.deepEqual(fake.at(pinOf("mainnet", kasTo(seller.publicKey()))).map((u) => u.amount), [AUTHORIZER.toString()]);
        const tokenSpk = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
          identifier_type: "pubkey",
          identifier: cold,
          amount: AMOUNT_A.toString(),
          is_minter: false,
        });
        const delivered = fake.at(addressFor("mainnet")(tokenSpk));
        assert.deepEqual(delivered.map((u) => [u.amount, u.covenant_id]), [[CARRIER.toString(), ASSET_COV]]);
        assert.deepEqual(fake.at(vaultAddress), [], "the deposit is spent");

        // The decoder reads the settle back from the node, bound, on mainnet.
        const decoder = await openDecoder(t);
        const decoded = await decode(decoder, { network: "mainnet", txid: fake.accepted[1].txid, from: fake.genesis });
        assert.equal(decoded.state, "ok", decoded.text);
        const outcomes = await decoder.locator("#out-trade .outcome").allTextContents();
        assert.equal(outcomes[0], `Delivered ${AMOUNT_A} to KCC-20 owner pubkey ${cold}`);
        assert.equal(outcomes[1], `Delivered ${KAS_CASH} to KAS scriptPublicKey (version 0) 20${sellerCold}ac`);
        assert.equal(await decoder.getAttribute("#out-template .binding", "data-bound"), "true");
        await decoder.close();
        // Only the typed node was contacted; every address in the traffic is a mainnet address.
        assert.deepEqual([...new Set(s.contacted)], [new URL(NODE_URL).href]);
        assert.deepEqual(s.external, []);
        assert.deepEqual(s.errors, []);
        const asked = frames(s).filter((f) => f.method === "getUtxosByAddresses").flatMap((f) => f.params.addresses as string[]);
        assert.ok(asked.length > 0 && asked.every((a) => a.startsWith("kaspa:")), asked.join(","));
        // Two submissions, nothing else was sent that changes the node.
        assert.deepEqual(frames(s).filter((f) => f.method === "submitTransaction").length, 2);
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => pageTradeTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    seller.free();
  }
});

// The Direct path.

test("Direct path on mainnet: the page builds the transaction, wallets A and B sign their inputs, the key holder signs the token outside the page, the page adds that signature and submits", async () => {
  const sdk = await sdkOf();
  const holder = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "direct",
      async (t) => {
        const { page, fake, keys, addresses, s, terms } = t;
        const coldAddress = pinOf("mainnet", kasTo(cold));
        const buyer = partyFor("buyer", terms as never);
        const seller = partyFor("seller", terms as never);
        const holderKey = holder.publicKey();
        const sellerAddress = pinOf("mainnet", kasTo(sellerCold));
        // The seller's token UTXO, owned by the key outside the page and holding exactly the asset
        // amount; the buyer's cash at wallet B, exactly the cash amount; a coin of wallet A for the fee.
        fake.add(ownToken(sdk, "seller-token", holderKey, AMOUNT_A));
        fake.add(utxo("buyer-cash", KAS_CASH, p2pk(keys.b)));
        fake.add(utxo("fee-coin", 100_000_000n, p2pk(keys.a)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: coldAddress });
        await page.selectOption("#fee-payer", { value: "a" });
        assert.equal(await page.isVisible("#fund-options"), false, "a Direct trade funds nothing");
        assert.equal(await text(page, "#build-settle"), "Build the Direct trade");
        const built = await build(page);
        assert.deepEqual([built.state, built.code], ["ok", ""], built.text);

        // The review: the token of the key outside the page, the buyer's exact cash, the fee coin.
        const inputs = await rows(page, "#review-inputs-body");
        assert.deepEqual(inputs.map((r) => r.amount), [kasText(CARRIER), kasText(KAS_CASH), kasText(100_000_000n)]);
        assert.deepEqual(inputs.map((r) => r.signer), [
          needs(holderKey, "seller"),
          needs(keys.b, "buyer"),
          needs(keys.a, "other"),
        ]);
        const outputs = await rows(page, "#review-outputs-body");
        assert.equal(outputs[1].address, sellerAddress, "the cash goes to an address of the seller's, outside the page");
        assert.ok(outputs.every((r) => r.held === null));
        assert.equal(outputs[2].address, coldAddress, "the fee wallet's change goes elsewhere");
        // The wallets sign what they hold; the seller's input stays open and the page says whose it is.
        assert.deepEqual(
          await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)),
          ["Sign with wallet A (input 2)", "Sign with wallet B (input 1)"],
        );
        assert.deepEqual([(await signWith(page, "a")).state, (await signWith(page, "b")).state], ["ok", "ok"]);
        assert.deepEqual(await signedFlags(page), ["false", "true", "true"]);
        assert.equal(await page.isDisabled("#submit"), true, "the token is unsigned");
        assert.match(
          (await text(page, "#review-pending")) ?? "",
          new RegExp(`^Inputs still unsigned: 0\\. 1 of them needs a key this page does not hold \\(${holderKey}\\)`),
        );

        // Export: the text on the clipboard is the text on the page, and holds no key.
        await t.s.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: t.s.site.origin });
        await page.click("#ipst-copy");
        await page.waitForFunction(() => document.querySelector("#ipst-copy-status")?.getAttribute("data-state") === "ok");
        const exported = (await text(page, "#ipst-text")) ?? "";
        assert.equal(await page.evaluate(() => navigator.clipboard.readText()), exported);
        const doc = JSON.parse(exported) as { inputs: { signer: string | null; signature: string | null }[] };
        assert.deepEqual(doc.inputs.map((i) => i.signature !== null), [false, true, true]);
        const signedByHolder = holderSigns(sdk, holder, exported, seller);

        // Import: each refusal beside the accepted control; a refusal changes nothing.
        const unchanged = async () => {
          assert.deepEqual(await signedFlags(page), ["false", "true", "true"]);
          assert.equal(await page.isDisabled("#submit"), true);
        };
        // Nothing pasted.
        const empty = await importText(page, "   ");
        assert.deepEqual([empty.state, empty.code], ["refused", ""]);
        assert.equal(empty.text, "Not added: Paste the IPST text first.");
        await unchanged();
        // Not an IPST.
        const garbage = await importText(page, "{");
        assert.deepEqual([garbage.state, garbage.code], ["refused", "IPST_MALFORMED"], garbage.text);
        await unchanged();
        // The page's own export, which holds no signature it lacks.
        const nothing = await importText(page, exported);
        assert.deepEqual([nothing.state, nothing.code], ["refused", ""]);
        assert.match(nothing.text, /^Not added: The pasted transaction is this one but adds no signature the document under review lacks\./);
        await unchanged();
        // A signature that does not verify for its input: one hex digit of the holder's changed.
        const forged = JSON.parse(signedByHolder) as { inputs: { signature: string | null }[] };
        const real = forged.inputs[0].signature as string;
        forged.inputs[0].signature = `${real.slice(0, 10)}${real[10] === "0" ? "1" : "0"}${real.slice(11)}`;
        const badSignature = await importText(page, JSON.stringify(forged));
        assert.deepEqual([badSignature.state, badSignature.code], ["refused", "TX_SIGNATURE"], badSignature.text);
        await unchanged();
        // Another transaction of the same terms, signed by the key holder: a document that is not this one.
        const validated = (sdk as Record<string, any>).Terms.fromJson(terms).validateStructure();
        const addressesAsked = validated.directAddresses({ asset: ASSET_ARTIFACT, cash: null }, keys.a);
        const reply = fake.handle(sdk.rpcRequest(901, "getUtxosByAddresses", addressesAsked));
        const other = validated.directFromReply(
          { asset: ASSET_ARTIFACT, cash: null },
          reply,
          { payer: keys.a, fee: "9000000", change: coldAddress },
          NOW.toString(),
          { kas_equivalent: KAS_CASH.toString() },
        );
        const otherSigned = holderSigns(sdk, holder, other.toJson(), seller);
        other.free();
        assert.notEqual(otherSigned, signedByHolder);
        const conflict = await importText(page, otherSigned);
        assert.deepEqual([conflict.state, conflict.code], ["refused", "IPST_CONFLICT"], conflict.text);
        await unchanged();
        // The control: the document the key holder signed is this one, and adds the seller's signature.
        const added = await importText(page, signedByHolder);
        assert.deepEqual([added.state, added.code], ["ok", ""], added.text);
        assert.equal(added.text, "Added 1 signature. The review above is of the result, at the node's DAA score 1500000.");
        assert.equal(await page.inputValue("#import-text"), "", "the box is emptied");
        assert.deepEqual(await signedFlags(page), ["true", "true", "true"]);
        assert.equal(await page.isDisabled("#submit"), false);
        assert.equal(await page.locator("#sign-buttons button").count(), 0);
        assert.equal(await fact(page, "submit-ready"), "yes");

        const submitted = await submitAndWait(page);
        assert.equal(submitted.state, "ok", submitted.text);
        assert.equal(fake.accepted.length, 1);
        const submits = frames(s).filter((f) => f.method === "submitTransaction");
        assert.equal(submits.length, 1);
        assert.ok(submits[0].params.transaction.inputs.every((i: { signatureScript: string }) => i.signatureScript.length > 0));
        // What the node holds: the seller's address has the cash, the cold key the token and the change.
        assert.deepEqual(fake.at(sellerAddress).map((u) => u.amount), [KAS_CASH.toString()]);
        assert.deepEqual(fake.at(addresses.b), [], "the buyer's cash is spent");
        const tokenSpk = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
          identifier_type: "pubkey",
          identifier: cold,
          amount: AMOUNT_A.toString(),
          is_minter: false,
        });
        assert.equal(fake.at(addressFor("mainnet")(tokenSpk)).length, 1, "the token is the cold key's");
        // Only the typed node was contacted, and no pasted text went anywhere but into the transaction.
        assert.deepEqual([...new Set(s.contacted)], [new URL(NODE_URL).href]);
        assert.deepEqual(s.external, []);
        assert.deepEqual(s.errors, []);
        assert.ok(!s.sent.some((m) => m.text.includes(signedByHolder)), "the pasted document itself is not sent");
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => pageTradeTerms(sdk, "direct", holder.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    holder.free();
  }
});

test("Direct path, the other order: the key holder signs the exported document first, the page adds that signature, and then its wallets sign", async () => {
  const sdk = await sdkOf();
  const holder = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "direct",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const coldAddress = pinOf("mainnet", kasTo(cold));
        const buyer = partyFor("buyer", terms as never);
        fake.add(ownToken(sdk, "seller-token", holder.publicKey(), AMOUNT_A));
        fake.add(utxo("buyer-cash", KAS_CASH, p2pk(keys.b)));
        fake.add(utxo("fee-coin", 100_000_000n, p2pk(keys.a)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: coldAddress });
        await page.selectOption("#fee-payer", { value: "a" });
        assert.equal((await build(page)).state, "ok");
        // Nothing signed yet: the export holds no signature, and the key holder signs it as it is.
        await t.s.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: t.s.site.origin });
        await page.click("#ipst-copy");
        await page.waitForFunction(() => document.querySelector("#ipst-copy-status")?.getAttribute("data-state") === "ok");
        const exported = await page.evaluate(() => navigator.clipboard.readText());
        assert.deepEqual((JSON.parse(exported) as { inputs: { signature: string | null }[] }).inputs.map((i) => i.signature), [null, null, null]);
        const signedByHolder = holderSigns(sdk, holder, exported, partyFor("seller", terms as never));
        const added = await importText(page, signedByHolder);
        assert.deepEqual([added.state, added.code], ["ok", ""], added.text);
        assert.deepEqual(await signedFlags(page), ["true", "false", "false"]);
        assert.equal(await page.isDisabled("#submit"), true, "the wallets' inputs are unsigned");
        // The wallets sign what is left, and the document is complete.
        assert.deepEqual([(await signWith(page, "a")).state, (await signWith(page, "b")).state], ["ok", "ok"]);
        assert.deepEqual(await signedFlags(page), ["true", "true", "true"]);
        assert.equal(await page.isDisabled("#submit"), false);
        assert.equal((await submitAndWait(page)).state, "ok");
        assert.equal(fake.accepted.length, 1);
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => pageTradeTerms(sdk, "direct", holder.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    holder.free();
  }
});

test("Vault path on testnet: the same sequence with both wallets of the page as the parties, no pins and no change address needed", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, addresses, terms } = t;
      const [assetAuthorizer, assetEscrow] = vaultUtxos(t.sdk, terms, keys.b);
      fake.add(assetAuthorizer);
      fake.add(assetEscrow);
      fake.add(utxo("buyer-funding-coin", 200_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      assert.equal(await page.getAttribute("body", "data-network"), "testnet");
      const funding = await build(page, "#build-fund");
      assert.deepEqual([funding.state, funding.code], ["ok", ""], funding.text);
      const outputs = await rows(page, "#review-outputs-body");
      assert.equal(outputs[1].address, addresses.b, "the change comes back to wallet B's own key, which testnet allows");
      assert.equal(outputs[1].held, "true", "and the review marks it as a key that lives only in the page");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      await page.selectOption("#fee-payer", { value: "a" });
      assert.equal((await build(page)).state, "ok");
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(fake.accepted.length, 2);
    },
    { seed: "none" },
  );
});

test("a signature is added only to a document the page built: with none under review the import is refused, and the same text is taken once one is", async () => {
  const sdk = await sdkOf();
  const holder = sdk.Wallet.generate();
  try {
    await withTrade(
      "direct",
      async (t) => {
        const { page, fake, keys } = t;
        fake.add(ownToken(sdk, "seller-token", holder.publicKey(), AMOUNT_A));
        fake.add(utxo("buyer-cash", KAS_CASH, p2pk(keys.b)));
        fake.add(utxo("buyer-fee", 700_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer");
        // Nothing built yet: the review panel, and the box in it, are not on the screen. The press
        // is made from the page's own script all the same, and is refused whatever the box holds.
        assert.equal(await page.isVisible("#import-apply"), false);
        await page.evaluate(() => {
          (document.getElementById("import-text") as HTMLTextAreaElement).value = "{";
          document.getElementById("import-apply")?.click();
        });
        const before = await importStatus(page);
        assert.deepEqual([before.state, before.code], ["refused", ""]);
        assert.match(before.text, /^Not added: There is no document under review\. Build one first/);
        // Control: build, and the same press now reads the text.
        assert.equal((await build(page)).state, "ok");
        const after = await importText(page, "{");
        assert.deepEqual([after.state, after.code], ["refused", "IPST_MALFORMED"]);
        // A new build or a change under the review clears the box and its status.
        await page.fill("#import-text", "left over");
        await page.fill("#kas-equivalent", "99");
        await page.waitForFunction(() => document.querySelector("#import-status")?.getAttribute("data-state") === "idle");
        assert.equal(await page.inputValue("#import-text"), "");
      },
      {
        seed: "none",
        terms: (_sdk, k) => termsFor(sdk, "direct", holder.publicKey(), k.b),
      },
    );
  } finally {
    holder.free();
  }
});

// The funding: who is offered it, and who may pay it.

test("the funding of the cash leg is offered to the buyer of a Vault trade with KAS cash and to nobody else", async () => {
  const sdk = await sdkOf();
  const visible = async (t: Trade) => ({ actions: await t.page.isVisible("#actions"), fund: await t.page.isVisible("#fund-options") });
  // Control: the buyer of a Vault trade with a KAS cash leg.
  await withTrade("vault", async (t) => {
    await prepare(t, "buyer");
    assert.deepEqual(await visible(t), { actions: true, fund: true });
  });
  // The seller of the same trade, a Direct trade, external cash and a KCC-20 cash leg: no funding on offer.
  await withTrade("vault", async (t) => {
    await prepare(t, "seller");
    assert.deepEqual(await visible(t), { actions: true, fund: false }, "the seller of a Vault trade");
  });
  await withTrade("direct", async (t) => {
    await prepare(t, "buyer");
    assert.deepEqual(await visible(t), { actions: true, fund: false }, "a Direct trade");
  });
  await withTrade(
    "vault",
    async (t) => {
      await prepare(t, "buyer");
      assert.deepEqual(await visible(t), { actions: true, fund: false }, "external cash");
    },
    { terms: (_s, k) => externalTermsFor(sdk, k.a, k.b, newKey(sdk)) },
  );
  await withTrade(
    "vault",
    async (t) => {
      await prepare(t, "buyer", {}, { cash: CASH_ARTIFACT });
      assert.deepEqual(await visible(t), { actions: true, fund: false }, "a KCC-20 cash leg");
    },
    { terms: (_s, k) => kcc20CashTermsFor(sdk, "vault", k.a, k.b) },
  );
});

test("the wallet that pays the funding must hold the buyer's key, and must hold a coin", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys } = t;
      const [assetAuthorizer, assetEscrow] = vaultUtxos(t.sdk, t.terms, keys.b);
      fake.add(assetAuthorizer);
      fake.add(assetEscrow);
      fake.add(utxo("seller-coin", 200_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      // The wallet chosen to pay is wallet A, the seller's: not the buyer's key.
      await page.selectOption("#fee-payer", { value: "a" });
      const notBuyer = await build(page, "#build-fund");
      assert.deepEqual([notBuyer.state, notBuyer.code], ["refused", "SDK_FUND_NOT_YOUR_LEG"], notBuyer.text);
      assert.equal(await page.isVisible("#review-panel"), false, "nothing is shown to sign");
      // The buyer's wallet, with no coin on the node: the builder has nothing to pay with.
      await page.selectOption("#fee-payer", { value: "b" });
      const noCoin = await build(page, "#build-fund");
      assert.deepEqual([noCoin.state, noCoin.code], ["refused", "TX_KAS_INPUT"], noCoin.text);
      assert.equal(await page.isVisible("#review-panel"), false);
      // Control: the buyer's wallet with a coin.
      fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
      const funded = await build(page, "#build-fund");
      assert.deepEqual([funded.state, funded.code], ["ok", ""], funded.text);
      assert.equal(await page.isVisible("#review-panel"), true);
    },
    { seed: "none" },
  );
});

test("on mainnet the funding's change to the wallet's own key is refused at signing, and an address elsewhere signs", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund });
        // No change address: the change would go to wallet B's own key, which only this page holds.
        assert.equal((await build(page, "#build-fund")).state, "ok");
        const refused = await signWith(page, "b");
        assert.deepEqual([refused.state, refused.code], ["refused", "SDK_DESTINATION_IN_WALLET"], refused.text);
        assert.equal(await page.isDisabled("#submit"), true);
        // Control: an address elsewhere.
        await page.fill("#change-address", pinOf("mainnet", kasTo(cold)));
        assert.equal((await build(page, "#build-fund")).state, "ok");
        const signed = await signWith(page, "b");
        assert.deepEqual([signed.state, signed.code], ["ok", ""], signed.text);
        assert.equal(await page.isDisabled("#submit"), false);
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => pageTradeTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    seller.free();
  }
});

test("the role check comes first: a key that is not the buyer's, or a buyer destination that pays a key of the page on mainnet, offers no funding", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    // Wallet A's key as the buyer: not the buyer's key.
    await withTrade(
      "vault",
      async (t) => {
        const { page, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund });
        assert.equal(await page.isVisible("#fund-options"), true, "control: wallet B is the buyer");
        await page.click("#wallet-a .wallet-use-me");
        await page.waitForSelector("#status[data-state='refused'][data-code='SDK_ROLE_KEY_MISMATCH']");
        assert.equal(await page.isVisible("#actions"), false);
        assert.equal(await page.isVisible("#fund-options"), false);
      },
      { network: "mainnet", terms: (_sdk, k) => pageTradeTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold) },
    );
    // The buyer's destinations pay wallet B's own key, on mainnet, with no pin elsewhere.
    await withTrade(
      "vault",
      async (t) => {
        const { page } = t;
        await prepare(t, "buyer", {}, { expect: "SDK_DESTINATION_IN_WALLET" });
        assert.equal(await page.isVisible("#actions"), false);
        assert.equal(await page.isVisible("#build-fund"), false);
      },
      { network: "mainnet", terms: (_sdk, k) => termsFor(sdk, "vault", seller.publicKey(), k.b, "mainnet") },
    );
  } finally {
    seller.free();
  }
});

test("the value cap holds in the funding: a cash leg above the cap is not derived, and one at the cap is refused at signing because the fee counts, beside a smaller one that signs", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  const withCash = (amount: bigint) => (_sdk: TestSdk, k: { a: string; b: string }) => ({
    ...pageTradeTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold),
    cash_leg: { kind: "kas", amount: amount.toString() },
  });
  try {
    // Control: 5 KAS builds and signs.
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 800_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        assert.equal((await build(page, "#build-fund")).state, "ok");
        const signed = await signWith(page, "b");
        assert.deepEqual([signed.state, signed.code], ["ok", ""], signed.text);
      },
      { network: "mainnet", seed: "none", terms: withCash(500_000_000n) },
    );
    // Exactly the cap: the leg is within it, the funding moves the leg and the fee, and is refused at signing.
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 1_500_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        assert.equal((await build(page, "#build-fund")).state, "ok", "a leg of exactly 10 KAS is within the cap");
        const refused = await signWith(page, "b");
        assert.deepEqual([refused.state, refused.code], ["refused", "SDK_VALUE_CAP_EXCEEDED"], refused.text);
        assert.equal(await page.isDisabled("#submit"), true);
      },
      { network: "mainnet", seed: "none", terms: withCash(1_000_000_000n) },
    );
    // One sompi above the cap: the page derives nothing, so nothing is offered to fund.
    await withTrade(
      "vault",
      async (t) => {
        const { page, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { expect: "SDK_VALUE_CAP_EXCEEDED" });
        assert.equal(await page.isVisible("#actions"), false);
        assert.equal(await page.isVisible("#build-fund"), false);
      },
      { network: "mainnet", seed: "none", terms: withCash(1_000_000_001n) },
    );
  } finally {
    seller.free();
  }
});

test("a funding the node accepts while the terms are edited under the page is still reported as submitted, not as a failure", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        assert.equal((await build(page, "#build-fund")).state, "ok");
        assert.equal((await signWith(page, "b")).state, "ok");
        // The node takes the transaction, and its answer is held back while the terms are edited.
        let release: () => void = () => {};
        const gate = new Promise<void>((done) => (release = done));
        t.handler.current = async (request) => {
          const reply = fake.handle(request);
          if ((JSON.parse(request) as { method: string }).method === "submitTransaction") await gate;
          return reply;
        };
        await page.click("#submit");
        await until(() => sentCount(t.s, "submitTransaction") === 1, "the submission");
        await page.fill('[data-path="nonce"]', "7");
        assert.equal(await page.isVisible("#review-panel"), false, "the edit dropped the document under review");
        release();
        await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "ok");
        assert.match((await text(page, "#submit-status")) ?? "", /^Submitted\. The node accepted the transaction /);
        assert.equal(fake.accepted.length, 1);
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => pageTradeTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    seller.free();
  }
});

// No key in any channel, through each new path.

test("no wallet's key appears in the page, its storage, its traffic or its console through the funding and the settle, or through the export and the import of a Direct trade", async () => {
  const sdk = await sdkOf();
  const holder = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    for (const flow of ["vault", "direct"] as const) {
      await withTrade(
        flow,
        async (t) => {
          const { page, fake, keys, terms } = t;
          const coldAddress = pinOf("mainnet", kasTo(cold));
          const buyer = partyFor("buyer", terms as never);
          // The wallets' keys are the first two 32-byte draws of the page; an independent
          // implementation derives each public key from its draw.
          const draws = (await drawnKeys(page)).slice(0, 2);
          assert.equal(draws.length, 2);
          const derived = draws.map((d) => Buffer.from(schnorr.getPublicKey(Uint8Array.from(Buffer.from(d, "hex")))).toString("hex"));
          assert.deepEqual(derived, [keys.a, keys.b]);
          if (flow === "vault") {
            const [assetAuthorizer, assetEscrow] = vaultUtxos(sdk, terms, keys.b);
            fake.add(assetAuthorizer);
            fake.add(assetEscrow);
            fake.add(utxo("buyer-funding-coin", 200_000_000n, p2pk(keys.b)));
            fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
            await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: coldAddress });
            assert.equal((await build(page, "#build-fund")).state, "ok");
            assert.equal((await signWith(page, "b")).state, "ok");
            assert.equal((await submitAndWait(page)).state, "ok");
            await page.selectOption("#fee-payer", { value: "a" });
            assert.equal((await build(page)).state, "ok");
            assert.equal((await signWith(page, "a")).state, "ok");
            assert.equal((await submitAndWait(page)).state, "ok");
          } else {
            fake.add(ownToken(sdk, "seller-token", holder.publicKey(), AMOUNT_A));
            fake.add(utxo("buyer-cash", KAS_CASH, p2pk(keys.b)));
            fake.add(utxo("fee-coin", 100_000_000n, p2pk(keys.a)));
            await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: coldAddress });
            await page.selectOption("#fee-payer", { value: "a" });
            assert.equal((await build(page)).state, "ok");
            await signWith(page, "a");
            await signWith(page, "b");
            await t.s.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: t.s.site.origin });
            await page.click("#ipst-copy");
            await page.waitForFunction(() => document.querySelector("#ipst-copy-status")?.getAttribute("data-state") === "ok");
            const signedText = holderSigns(sdk, holder, (await text(page, "#ipst-text")) ?? "", partyFor("seller", terms as never));
            assert.equal((await importText(page, signedText)).state, "ok");
            assert.equal((await submitAndWait(page)).state, "ok");
          }
          const seen = await channelsOf(t);
          assert.ok(seen.includes(keys.a) && seen.includes(keys.b), `${flow}: the scan reads real text with the public keys in it`);
          for (const [who, secret] of [["A", draws[0]], ["B", draws[1]]] as const) {
            assert.ok(!spellingsOf(secret).some((x) => seen.includes(x)), `${flow}: wallet ${who}'s key appears somewhere`);
          }
          // Control: a stand-in drawn here and put into the page is found by the same scan.
          const stand = randomBytes(32).toString("hex");
          await page.evaluate((v) => {
            const p = document.createElement("p");
            p.textContent = v;
            document.body.append(p);
          }, stand);
          assert.ok((await channelsOf(t)).includes(stand), `${flow}: the scan finds a stand-in key where one is planted`);
        },
        {
          network: "mainnet",
          seed: "none",
          terms: (_sdk, k) => pageTradeTerms(sdk, flow, holder.publicKey(), k.b, cold, sellerCold),
        },
      );
    }
  } finally {
    holder.free();
  }
});

