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
  fromtKeyImportSetupMsgNew,
  fromt_derive_keys_from_seed,
  fromt_derive_view_key,
  fromt_derive_address,
} = wasmJs;

// monero-ts WASM expects HttpClient/LibraryUtils/GenUtils on globalThis (Node.js v24+)
const moneroTs = (await import("monero-ts")).default;
globalThis.HttpClient = moneroTs.HttpClient;
globalThis.LibraryUtils = moneroTs.LibraryUtils;
globalThis.GenUtils = moneroTs.GenUtils;

const { scan } = await import("../dist/scanner.js");

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
  return bundle;
}

// --- Main ---
const DAEMON_URL = process.env.MONERO_DAEMON_URL || "http://node.monerodevs.org:18089";

const seedHex = process.env.FROMT_SEED_HEX;
if (!seedHex) { console.error("FROMT_SEED_HEX not set"); process.exit(1); }

const mnemonics = [
  {
    name: "FROMT_MNEMONIC",
    seed32hex: seedHex,
    birthday: Number(process.env.FROMT_BIRTHDAY || "0"),
    expectedAddress: process.env.FROMT_EXPECTED_ADDRESS || "",
  },
];

console.log("=== fromt TS SDK Balance Scan ===");
console.log(`Daemon: ${DAEMON_URL}\n`);

for (const m of mnemonics) {
  console.log(`--- ${m.name} ---`);

  const seed32 = Buffer.from(m.seed32hex, "hex");
  const bundle = runKeyImport(seed32, 0, BigInt(m.birthday));

  const address = fromt_derive_address(bundle);
  if (address !== m.expectedAddress) {
    console.error(`  FAIL: address mismatch\n    got:    ${address}\n    expect: ${m.expectedAddress}`);
    continue;
  }
  console.log(`  Address: ${address.slice(0, 30)}... OK`);

  const keysResult = fromt_derive_keys_from_seed(new Uint8Array(seed32));
  const spendKey = Buffer.from(keysResult.slice(0, 32)).toString("hex");
  const viewKeyBytes = fromt_derive_view_key(bundle);
  const viewKey = Buffer.from(viewKeyBytes).toString("hex");
  console.log(`  View key: ${viewKey.slice(0, 16)}...`);

  try {
    const start = Date.now();
    const result = await scan({
      daemonUrl: DAEMON_URL,
      primaryAddress: address,
      privateViewKey: viewKey,
      privateSpendKey: spendKey,
      restoreHeight: m.birthday,
      networkType: "mainnet",
      onProgress: (p) => {
        if (p.scannedBlocks % 1000 === 0) {
          process.stdout.write(`\r  Scanned ${p.scannedBlocks}/${p.totalBlocks} blocks...`);
        }
      },
    });
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    process.stdout.write("\r");

    console.log(`  Balance: ${result.balance} piconero (${(result.balance / 1e12).toFixed(12)} XMR)`);
    console.log(`  Outputs: ${result.outputs.length}/${result.totalOutputs} unspent`);
    console.log(`  Spent outputs: ${result.spentOutputs}`);
    console.log(`  Chain height: ${result.chainHeight}`);
    console.log(`  Time: ${elapsed}s`);
    console.log(result.balance > 0 ? "  PASS" : "  WARN: zero balance");
  } catch (err) {
    console.error(`  SCAN ERROR: ${err.message}`);
    console.log("  Note: Monero daemon must be reachable and synced");
  }
  console.log();
}

process.exit(0);
