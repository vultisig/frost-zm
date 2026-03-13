import { pbkdf2Sync } from "crypto";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPkgDir = join(__dirname, "..", "..", "..", "crates", "frozt-wasm", "pkg");

const wasmBytes = readFileSync(join(wasmPkgDir, "frozt_wasm_bg.wasm"));
const wasmJs = await import(join(wasmPkgDir, "frozt_wasm.js"));
wasmJs.initSync({ module: wasmBytes });

const {
  FroztKeyImportSession,
  froztKeyImportSetupMsgNew,
  frozt_keyshare_bundle_pub_key_package,
  frozt_keyshare_bundle_sapling_extras,
  frozt_sapling_build_dfvk,
  frozt_sapling_derive_keys,
} = wasmJs;
const { scan } = await import("../dist/scanner.js");

function mnemonicToSeed(mnemonic) {
  return pbkdf2Sync(mnemonic, "mnemonic", 2048, 64, "sha512");
}

function encodeParties(parties) {
  const parts = [];
  const countBuf = new Uint8Array(2);
  new DataView(countBuf.buffer).setUint16(0, parties.length, true);
  parts.push(countBuf);
  for (const p of parties) {
    const idBuf = new Uint8Array(2);
    new DataView(idBuf.buffer).setUint16(0, p.frostId, true);
    parts.push(idBuf);
    const nameBytes = new TextEncoder().encode(p.name);
    const lenBuf = new Uint8Array(2);
    new DataView(lenBuf.buffer).setUint16(0, nameBytes.length, true);
    parts.push(lenBuf);
    parts.push(nameBytes);
  }
  const total = parts.reduce((s, b) => s + b.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const b of parts) { result.set(b, off); off += b.length; }
  return result;
}

function routeMsg(senderId, rawMsg) {
  const payload = rawMsg.slice(2);
  const input = new Uint8Array(2 + payload.length);
  input[0] = senderId & 0xff;
  input[1] = (senderId >> 8) & 0xff;
  input.set(payload, 2);
  return input;
}

function runKeyImport(seed) {
  const parties = [{ frostId: 1, name: "alice" }, { frostId: 2, name: "bob" }];
  const partiesData = encodeParties(parties);
  const birthday = BigInt(0);

  const setup = froztKeyImportSetupMsgNew(2, 2, partiesData, birthday, 1, new Uint8Array(seed), 0);

  const s1 = FroztKeyImportSession.fromSetup(setup, "alice", new Uint8Array(seed), 0, birthday);
  const s2 = FroztKeyImportSession.fromSetup(setup, "bob", new Uint8Array(0), 0, birthday);

  const sessions = [
    { id: 1, session: s1, finished: false },
    { id: 2, session: s2, finished: false },
  ];

  for (let round = 0; round < 50; round++) {
    if (sessions.every(s => s.finished)) break;

    const outgoing = [];
    for (let idx = 0; idx < sessions.length; idx++) {
      let msg;
      while ((msg = sessions[idx].session.takeMsg()) !== undefined) {
        outgoing.push({ senderIdx: idx, msg });
      }
    }

    if (outgoing.length === 0) continue;

    for (const { senderIdx, msg } of outgoing) {
      const senderId = sessions[senderIdx].id;
      const recipientId = msg[0] | (msg[1] << 8);

      const targets = recipientId === 0
        ? sessions.filter((_, i) => i !== senderIdx)
        : sessions.filter(s => s.id === recipientId);

      for (const target of targets) {
        if (target.finished) continue;
        if (target.session.feed(routeMsg(senderId, msg))) {
          target.finished = true;
        }
      }
    }
  }

  const bundle = s1.result();
  s1.free();
  s2.free();

  const pubKeyPackage = frozt_keyshare_bundle_pub_key_package(bundle);
  const extras = frozt_keyshare_bundle_sapling_extras(bundle);
  return { pubKeyPackage, extras };
}

// --- Main ---
const LIGHTWALLETD = process.env.FROZT_LIGHTWALLETD_URL || "https://zec.rocks:443";

const mnemonics = [];
for (const [suffix, envName] of [["", "FROZT_MNEMONIC"], ["_2", "FROZT_MNEMONIC_2"], ["_3", "FROZT_MNEMONIC_3"]]) {
  const phrase = process.env[envName];
  if (!phrase) { console.error(`${envName} not set`); process.exit(1); }
  const birthday = Number(process.env[`FROZT_BIRTHDAY${suffix}`] || "0");
  const expectedAddress = process.env[`FROZT_EXPECTED_ADDRESS${suffix}`] || "";
  mnemonics.push({ name: envName, phrase, birthday, expectedAddress });
}

console.log("=== frozt TS SDK Balance Scan (with spent filtering) ===");
console.log(`Lightwalletd: ${LIGHTWALLETD}\n`);

for (const m of mnemonics) {
  console.log(`--- ${m.name} ---`);

  const seed = mnemonicToSeed(m.phrase);
  const { pubKeyPackage, extras } = runKeyImport(seed);

  const keys = frozt_sapling_derive_keys(pubKeyPackage, extras);
  if (keys.address !== m.expectedAddress) {
    console.error(`  FAIL: address mismatch`);
    continue;
  }
  console.log(`  Address: ${keys.address} OK`);

  const start = Date.now();
  const result = await scan({
    lightwalletdUrl: LIGHTWALLETD,
    ivk: new Uint8Array(keys.ivk),
    dfvk: new Uint8Array(frozt_sapling_build_dfvk(pubKeyPackage, extras)),
    startHeight: m.birthday,
    onProgress: (p) => {
      if (p.scannedBlocks % 1000 === 0) {
        process.stdout.write(`\r  Scanned ${p.scannedBlocks}/${p.totalBlocks} blocks...`);
      }
    },
  });
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  process.stdout.write("\r");

  console.log(`  Balance: ${result.spendableBalance} zatoshis (${(result.spendableBalance / 1e8).toFixed(8)} ZEC)`);
  console.log(`  Notes: ${result.notes.length}/${result.totalNotes} unspent`);
  console.log(`  Spent notes: ${result.spentNotes}`);
  console.log(`  Chain height: ${result.chainHeight}`);
  console.log(`  Time: ${elapsed}s`);
  console.log(result.spendableBalance > 0 ? `  PASS` : `  WARN: zero balance`);
  console.log();
}
process.exit(0);
