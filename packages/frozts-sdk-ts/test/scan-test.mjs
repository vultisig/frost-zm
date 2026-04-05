import { pbkdf2Sync } from "crypto";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPkgDir = join(__dirname, "..", "..", "..", "crates", "frozts-wasm", "pkg");
const protoDir = join(__dirname, "..", "..", "..", "client", "frozts", "internal", "lightwalletd");

const wasmBytes = readFileSync(join(wasmPkgDir, "frozts_wasm_bg.wasm"));
const wasmJs = await import(join(wasmPkgDir, "frozts_wasm.js"));
wasmJs.initSync({ module: wasmBytes });

const {
  FroztKeyImportSession,
  froztsKeyImportSetupMsgNew,
  frozts_keyshare_bundle_pub_key_package,
  frozts_keyshare_bundle_sapling_extras,
  frozts_sapling_build_dfvk,
  frozts_sapling_derive_keys,
} = wasmJs;
const { scan } = await import("../dist/scanner.js");

// Native gRPC client adapter for Node.js (zec.rocks doesn't support gRPC-web)
const packageDefinition = protoLoader.loadSync(
  join(protoDir, "compact_formats.proto"),
  { keepCase: true, longs: Number, enums: String, defaults: true, oneofs: true }
);
const proto = grpc.loadPackageDefinition(packageDefinition);
const CompactTxStreamer = proto.cash.z.wallet.sdk.rpc.CompactTxStreamer;

function createNativeGrpcClient(url) {
  // @grpc/grpc-js expects "host:port", not "https://host:port"
  const grpcTarget = url.replace(/^https?:\/\//, "");
  const rpc = new CompactTxStreamer(grpcTarget, grpc.credentials.createSsl());

  return {
    getLatestBlockHeight() {
      return new Promise((resolve, reject) => {
        rpc.GetLatestBlock({}, (err, resp) => err ? reject(err) : resolve(resp.height));
      });
    },
    getBlockRange(startHeight, endHeight) {
      return new Promise((resolve, reject) => {
        const blocks = [];
        const stream = rpc.GetBlockRange({
          start: { height: startHeight },
          end: { height: endHeight },
        });
        stream.on("data", (block) => {
          const transactions = (block.vtx || []).map((tx) => ({
            hash: tx.hash ? Buffer.from(tx.hash) : new Uint8Array(0),
            spends: (tx.spends || []).map((s) => ({ nf: s.nf ? new Uint8Array(s.nf) : new Uint8Array(0) })),
            outputs: (tx.outputs || []).map((o) => ({
              cmu: o.cmu ? new Uint8Array(o.cmu) : new Uint8Array(0),
              ephemeralKey: o.ephemeralKey ? new Uint8Array(o.ephemeralKey) : new Uint8Array(0),
              ciphertext: o.ciphertext ? new Uint8Array(o.ciphertext) : new Uint8Array(0),
            })),
          }));
          blocks.push({ height: block.height, transactions });
        });
        stream.on("end", () => resolve(blocks));
        stream.on("error", reject);
      });
    },
    getTransaction(txHash) {
      return new Promise((resolve, reject) => {
        rpc.GetTransaction({ hash: txHash }, (err, resp) => {
          if (err) reject(err);
          else resolve(new Uint8Array(resp.data));
        });
      });
    },
    getTreeState(height) {
      return new Promise((resolve, reject) => {
        rpc.GetTreeState({ height }, (err, resp) => {
          if (err) reject(err);
          else resolve(resp.saplingTree);
        });
      });
    },
  };
}

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

  const setup = froztsKeyImportSetupMsgNew(2, 2, partiesData, birthday, 1, new Uint8Array(seed), 0);

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

  const pubKeyPackage = frozts_keyshare_bundle_pub_key_package(bundle);
  const extras = frozts_keyshare_bundle_sapling_extras(bundle);
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

const nativeClient = createNativeGrpcClient(LIGHTWALLETD);

console.log("=== frozts TS SDK Balance Scan (with spent filtering) ===");
console.log(`Lightwalletd: ${LIGHTWALLETD}\n`);

for (const m of mnemonics) {
  console.log(`--- ${m.name} ---`);

  const seed = mnemonicToSeed(m.phrase);
  const { pubKeyPackage, extras } = runKeyImport(seed);

  const keys = frozts_sapling_derive_keys(pubKeyPackage, extras);
  if (keys.address !== m.expectedAddress) {
    console.error(`  FAIL: address mismatch`);
    continue;
  }
  console.log(`  Address: ${keys.address} OK`);

  const start = Date.now();
  const result = await scan({
    lightwalletdUrl: LIGHTWALLETD,
    client: nativeClient,
    ivk: new Uint8Array(keys.ivk),
    dfvk: new Uint8Array(frozts_sapling_build_dfvk(pubKeyPackage, extras)),
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
