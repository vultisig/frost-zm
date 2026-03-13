import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPkgDir = join(__dirname, "..", "..", "..", "pkg", "fromt");

const wasmBytes = readFileSync(join(wasmPkgDir, "fromt_wasm_bg.wasm"));
const wasmJs = await import(join(wasmPkgDir, "fromt_wasm.js"));
wasmJs.initSync({ module: wasmBytes });

const {
  FromtKeyImportSession,
  FromtKeyImageSession,
  fromtKeyImportSetupMsgNew,
  fromtKeyImageSetupMsgNew,
  fromt_derive_keys_from_seed,
  fromt_derive_view_key,
  fromt_derive_address,
  fromt_derive_key_offset,
} = wasmJs;

const moneroTs = (await import("monero-ts")).default;
globalThis.HttpClient = moneroTs.HttpClient;
globalThis.LibraryUtils = moneroTs.LibraryUtils;
globalThis.GenUtils = moneroTs.GenUtils;

// --- Helpers ---

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

function runSessionCeremony(sessions) {
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
}

function runKeyImport(seed32, network, birthday) {
  const keysResult = fromt_derive_keys_from_seed(new Uint8Array(seed32));
  const spendKey = keysResult.slice(0, 32);

  const parties = [{ frostId: 1, name: "alice" }, { frostId: 2, name: "bob" }];
  const partiesData = encodeParties(parties);

  const setup = fromtKeyImportSetupMsgNew(
    2, 2, partiesData, network, birthday, 1, new Uint8Array(seed32), 0,
  );

  const s1 = FromtKeyImportSession.fromSetup(setup, "alice", new Uint8Array(spendKey), network, birthday);
  const s2 = FromtKeyImportSession.fromSetup(setup, "bob", new Uint8Array(0), network, birthday);

  const sessions = [
    { id: 1, session: s1, finished: false },
    { id: 2, session: s2, finished: false },
  ];

  runSessionCeremony(sessions);

  const bundle1 = s1.result();
  const bundle2 = s2.result();
  s1.free();
  s2.free();
  return [bundle1, bundle2];
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function fetchTxPubKeys(daemonUrl, txHashes) {
  const uniqueHashes = [...new Set(txHashes)];
  const result = new Map();

  for (let i = 0; i < uniqueHashes.length; i += 50) {
    const batch = uniqueHashes.slice(i, i + 50);
    const resp = await fetch(`${daemonUrl}/get_transactions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ txs_hashes: batch, decode_as_json: true }),
    });
    const data = await resp.json();

    for (let j = 0; j < batch.length; j++) {
      const txJson = JSON.parse(data.txs[j].as_json);
      const extra = txJson.extra;
      if (extra && extra[0] === 1 && extra.length >= 33) {
        const pubKeyBytes = new Uint8Array(extra.slice(1, 33));
        result.set(batch[j], pubKeyBytes);
      }
    }
  }

  return result;
}

async function checkKeyImagesSpent(daemonUrl, keyImages) {
  const kiHex = keyImages.map(ki => bytesToHex(ki));
  const resp = await fetch(`${daemonUrl}/is_key_image_spent`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_images: kiHex }),
  });
  const data = await resp.json();
  return data.spent_status.map(s => s !== 0);
}

// --- Main ---
const DAEMON_URL = process.env.MONERO_DAEMON_URL || "http://node.monerodevs.org:18089";

const seedHex = process.env.FROMT_SEED_HEX;
if (!seedHex) { console.error("FROMT_SEED_HEX not set"); process.exit(1); }

const birthday = Number(process.env.FROMT_BIRTHDAY || "0");
const expectedAddress = process.env.FROMT_EXPECTED_ADDRESS || "";

console.log("=== fromt TS SDK — Threshold Key Image Scan ===");
console.log(`Daemon: ${DAEMON_URL}\n`);

const seed32 = Buffer.from(seedHex, "hex");
const [bundle1, bundle2] = runKeyImport(seed32, 0, BigInt(birthday));

const address = fromt_derive_address(bundle1);
if (expectedAddress && address !== expectedAddress) {
  console.error(`FAIL: address mismatch\n  got:    ${address}\n  expect: ${expectedAddress}`);
  process.exit(1);
}
console.log(`Address: ${address.slice(0, 30)}...`);

const viewKeyBytes = fromt_derive_view_key(bundle1);
const viewKeyHex = bytesToHex(viewKeyBytes);
console.log(`View key: ${viewKeyHex.slice(0, 16)}...`);

// Step 1: Scan with view key only (no spend key)
console.log("\n--- Step 1: View-only scan ---");
const startScan = Date.now();

const wallet = await moneroTs.createWalletFull({
  networkType: moneroTs.MoneroNetworkType.MAINNET,
  primaryAddress: address,
  privateViewKey: viewKeyHex,
  restoreHeight: birthday,
  server: { uri: DAEMON_URL },
  proxyToWorker: false,
});

const listener = new moneroTs.MoneroWalletListener();
listener.onSyncProgress = async (height, startHeight, endHeight) => {
  if ((height - startHeight) % 1000 === 0) {
    process.stdout.write(`\r  Scanned ${height - startHeight}/${endHeight - startHeight} blocks...`);
  }
};
await wallet.sync(listener);
process.stdout.write("\r");

const chainHeight = await wallet.getHeight();
const allOutputs = await wallet.getOutputs();
await wallet.close();

const scanTime = ((Date.now() - startScan) / 1000).toFixed(1);
console.log(`  Found ${allOutputs.length} outputs in ${scanTime}s (chain height: ${chainHeight})`);

if (allOutputs.length === 0) {
  console.log("  No outputs found — nothing to do");
  process.exit(0);
}

// Step 2: Derive key_offset for each output
console.log("\n--- Step 2: Derive key offsets ---");

const txHashes = allOutputs.map(o => o.getTx().getHash());
const txPubKeys = await fetchTxPubKeys(DAEMON_URL, txHashes);
console.log(`  Fetched tx pub keys for ${txPubKeys.size} transactions`);

const outputs = [];
for (const output of allOutputs) {
  const tx = output.getTx();
  const txHash = tx.getHash();
  const txPubKey = txPubKeys.get(txHash);
  if (!txPubKey) {
    console.log(`  WARN: no tx pub key for ${txHash}, skipping`);
    continue;
  }

  const outputIndex = output.getIndex() ?? 0;
  const outputKey = hexToBytes(output.getStealthPublicKey());
  const keyOffset = fromt_derive_key_offset(viewKeyBytes, txPubKey, BigInt(outputIndex));
  const amount = Number(output.getAmount());

  outputs.push({ outputKey, keyOffset, amount, txHash, outputIndex });
}
console.log(`  Derived key offsets for ${outputs.length} outputs`);

// Step 3: Run threshold key image ceremony
console.log("\n--- Step 3: Key image ceremony ---");

const parties = [{ frostId: 1, name: "alice" }, { frostId: 2, name: "bob" }];
const partiesData = encodeParties(parties);

const count = outputs.length;
const outputsBuf = new Uint8Array(4 + count * 64);
const dv = new DataView(outputsBuf.buffer);
dv.setUint32(0, count, true);
for (let i = 0; i < count; i++) {
  const off = 4 + i * 64;
  outputsBuf.set(outputs[i].outputKey.slice(0, 32), off);
  outputsBuf.set(outputs[i].keyOffset.slice(0, 32), off + 32);
}

const kiSetup = fromtKeyImageSetupMsgNew(partiesData, outputsBuf);

const s1 = FromtKeyImageSession.fromSetup(kiSetup, "alice", bundle1);
const s2 = FromtKeyImageSession.fromSetup(kiSetup, "bob", bundle2);

const kiSessions = [
  { id: 1, session: s1, finished: false },
  { id: 2, session: s2, finished: false },
];

runSessionCeremony(kiSessions);

const keyImagesRaw = s1.result();
s1.free();
s2.free();

const keyImages = [];
for (let i = 0; i < count; i++) {
  keyImages.push(keyImagesRaw.slice(i * 32, (i + 1) * 32));
}
console.log(`  Computed ${keyImages.length} key images via threshold ceremony`);

// Step 4: Check spent status
console.log("\n--- Step 4: Check spent status ---");
const spentFlags = await checkKeyImagesSpent(DAEMON_URL, keyImages);

let spentCount = 0;
let unspentBalance = 0;
for (let i = 0; i < outputs.length; i++) {
  if (spentFlags[i]) {
    spentCount++;
  } else {
    unspentBalance += outputs[i].amount;
  }
}

// Step 5: Results
console.log("\n--- Results ---");
console.log(`  Total outputs: ${outputs.length}`);
console.log(`  Spent: ${spentCount}`);
console.log(`  Unspent: ${outputs.length - spentCount}`);
console.log(`  Balance: ${unspentBalance} piconero (${(unspentBalance / 1e12).toFixed(12)} XMR)`);
console.log(unspentBalance > 0 ? "  PASS" : "  WARN: zero balance");

process.exit(0);
