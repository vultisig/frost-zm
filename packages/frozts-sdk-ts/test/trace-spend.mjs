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
  frozts_sapling_try_decrypt_compact,
  frozts_sapling_decrypt_note_full,
  frozts_sapling_compute_nullifier,
  frozts_sapling_try_output_recovery,
  frozts_sapling_tree_size,
} = wasmJs;

// --- Native gRPC client ---
const packageDefinition = protoLoader.loadSync(
  join(protoDir, "compact_formats.proto"),
  { keepCase: true, longs: Number, enums: String, defaults: true, oneofs: true }
);
const proto = grpc.loadPackageDefinition(packageDefinition);
const CompactTxStreamer = proto.cash.z.wallet.sdk.rpc.CompactTxStreamer;

function createNativeGrpcClient(url) {
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

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
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

// --- v5 tx parser ---
function readCompactSize(data, offset) {
  const first = data[offset];
  if (first < 253) return { value: first, offset: offset + 1 };
  if (first === 253) {
    const view = new DataView(data.buffer, data.byteOffset);
    return { value: view.getUint16(offset + 1, true), offset: offset + 3 };
  }
  if (first === 254) {
    const view = new DataView(data.buffer, data.byteOffset);
    return { value: view.getUint32(offset + 1, true), offset: offset + 5 };
  }
  return { value: 0, offset: offset + 9 };
}

function parseSaplingOutputsV5(rawTx) {
  const view = new DataView(rawTx.buffer, rawTx.byteOffset, rawTx.byteLength);
  let offset = 0;

  const header = view.getUint32(offset, true);
  offset += 4;
  if ((header & 0x80000000) === 0) return null;
  offset += 4; // versionGroupId
  offset += 4 + 4 + 4; // consensusBranchId + lockTime + expiryHeight

  // transparent inputs
  const nTxIn = readCompactSize(rawTx, offset);
  offset = nTxIn.offset;
  for (let i = 0; i < nTxIn.value; i++) {
    offset += 36;
    const scriptLen = readCompactSize(rawTx, offset);
    offset = scriptLen.offset + scriptLen.value;
    offset += 4;
  }

  // transparent outputs
  const nTxOut = readCompactSize(rawTx, offset);
  offset = nTxOut.offset;
  for (let i = 0; i < nTxOut.value; i++) {
    offset += 8;
    const scriptLen = readCompactSize(rawTx, offset);
    offset = scriptLen.offset + scriptLen.value;
  }

  // sapling spends
  const nSpends = readCompactSize(rawTx, offset);
  offset = nSpends.offset;
  for (let i = 0; i < nSpends.value; i++) {
    offset += 32 + 32 + 32; // cv + anchor + nullifier
  }

  // sapling outputs: cv(32) + cmu(32) + ephemeralKey(32) + encCiphertext(580) + outCiphertext(80) = 756
  const nOutputs = readCompactSize(rawTx, offset);
  offset = nOutputs.offset;

  const outputs = [];
  for (let i = 0; i < nOutputs.value; i++) {
    const cv = rawTx.slice(offset, offset + 32);
    const cmu = rawTx.slice(offset + 32, offset + 64);
    const ephemeralKey = rawTx.slice(offset + 64, offset + 96);
    const encCiphertext = rawTx.slice(offset + 96, offset + 96 + 580);
    const outCiphertext = rawTx.slice(offset + 96 + 580, offset + 96 + 580 + 80);
    outputs.push({ cv, cmu, ephemeralKey, encCiphertext, outCiphertext });
    offset += 756;
  }

  return outputs;
}

// --- Main ---
const LIGHTWALLETD = process.env.FROZT_LIGHTWALLETD_URL || "https://zec.rocks:443";
const walletNum = process.argv[2] || "1";
const suffix = walletNum === "1" ? "" : `_${walletNum}`;
const envMnemonic = `FROZT_MNEMONIC${suffix}`;
const envBirthday = `FROZT_BIRTHDAY${suffix}`;
const envAddress = `FROZT_EXPECTED_ADDRESS${suffix}`;

const phrase = process.env[envMnemonic];
if (!phrase) { console.error(`${envMnemonic} not set`); process.exit(1); }
const birthday = Number(process.env[envBirthday] || "0");
const expectedAddress = process.env[envAddress] || "";

const client = createNativeGrpcClient(LIGHTWALLETD);

console.log(`=== Trace ${envMnemonic} Spending Transactions ===\n`);

const seed = mnemonicToSeed(phrase);
const { pubKeyPackage, extras } = runKeyImport(seed);

const keys = frozts_sapling_derive_keys(pubKeyPackage, extras);
if (keys.address !== expectedAddress) {
  console.error(`Address mismatch: got ${keys.address}, expected ${expectedAddress}`);
  process.exit(1);
}
console.log(`Address: ${keys.address}`);

const ivk = new Uint8Array(keys.ivk);
const dfvk = new Uint8Array(frozts_sapling_build_dfvk(pubKeyPackage, extras));
const ovk = new Uint8Array(extras.slice(32, 64));
console.log(`OVK: ${toHex(ovk)}`);

const endHeight = await client.getLatestBlockHeight();
const totalBlocks = endHeight - birthday + 1;

// Get initial tree size at block before birthday
let initialTreeSize = 0;
if (birthday > 0) {
  const treeState = await client.getTreeState(birthday - 1);
  initialTreeSize = Number(frozts_sapling_tree_size(treeState));
  console.log(`\nInitial Sapling tree size at block ${birthday - 1}: ${initialTreeSize}`);
}
console.log(`Scanning blocks ${birthday} to ${endHeight} (${totalBlocks} blocks)...\n`);

// Phase 1: Scan — find our notes AND track nullifier → tx mapping
const rawNotes = [];
const nullifierToTx = new Map(); // nullifier hex → { txHash, height }
let commitmentPos = initialTreeSize;
let scannedBlocks = 0;
const batchSize = 10000;

for (let batchStart = birthday; batchStart <= endHeight; batchStart += batchSize) {
  const batchEnd = Math.min(batchStart + batchSize - 1, endHeight);
  const blocks = await client.getBlockRange(batchStart, batchEnd);

  for (const block of blocks) {
    scannedBlocks++;

    for (const tx of block.transactions) {
      for (const spend of tx.spends) {
        if (spend.nf.length === 32) {
          nullifierToTx.set(toHex(spend.nf), {
            txHash: tx.hash,
            height: block.height,
          });
        }
      }

      for (let i = 0; i < tx.outputs.length; i++) {
        const output = tx.outputs[i];
        if (output.cmu.length !== 32) { commitmentPos++; continue; }
        const notePos = commitmentPos;
        commitmentPos++;

        if (output.ephemeralKey.length !== 32 || output.ciphertext.length !== 52) continue;

        const value = frozts_sapling_try_decrypt_compact(
          ivk, output.cmu, output.ephemeralKey, output.ciphertext, BigInt(block.height),
        );

        if (value !== null && value !== undefined) {
          rawNotes.push({
            height: block.height,
            txHash: tx.hash,
            index: i,
            value: Number(value),
            position: notePos,
            cmu: output.cmu,
            ephemeralKey: output.ephemeralKey,
          });
        }
      }
    }

    if (scannedBlocks % 2000 === 0) {
      process.stdout.write(`\r  Scanned ${scannedBlocks}/${totalBlocks} blocks...`);
    }
  }
}
process.stdout.write("\r" + " ".repeat(60) + "\r");

console.log(`Found ${rawNotes.length} notes belonging to this wallet\n`);

// Phase 2: Compute nullifiers for our notes, find which were spent
console.log("--- Our Notes ---");
for (const note of rawNotes) {
  const fullTxData = await client.getTransaction(note.txHash);
  const outputs = parseSaplingOutputsV5(fullTxData);
  if (!outputs || !outputs[note.index]) {
    console.log(`  Note at height ${note.height}: ${note.value} zat — could not extract full tx`);
    continue;
  }

  const noteData = frozts_sapling_decrypt_note_full(
    ivk, note.cmu, note.ephemeralKey, outputs[note.index].encCiphertext, BigInt(note.height),
  );

  const nullifier = frozts_sapling_compute_nullifier(dfvk, noteData, BigInt(note.position), BigInt(note.height));
  const nfHex = toHex(nullifier);
  note.nullifierHex = nfHex;

  const spendInfo = nullifierToTx.get(nfHex);
  const status = spendInfo ? `SPENT in block ${spendInfo.height}` : "UNSPENT";
  console.log(`  Height ${note.height} | ${(note.value / 1e8).toFixed(8)} ZEC | ${status} | nf=${nfHex.slice(0, 16)}...`);

  if (spendInfo) {
    note.spentBy = spendInfo;
  }
}

// Phase 3: For spent notes, find the spending tx outputs and try OVK recovery
const spentNotes = rawNotes.filter(n => n.spentBy);
if (spentNotes.length === 0) {
  console.log("\nNo spent notes found.");
  process.exit(0);
}

console.log(`\n--- Spending Transaction Analysis ---`);

// Deduplicate spending txs
const spendingTxs = new Map();
for (const note of spentNotes) {
  const txKey = toHex(note.spentBy.txHash);
  if (!spendingTxs.has(txKey)) {
    spendingTxs.set(txKey, { txHash: note.spentBy.txHash, height: note.spentBy.height, notes: [] });
  }
  spendingTxs.get(txKey).notes.push(note);
}

for (const [txKey, info] of spendingTxs) {
  console.log(`\nSpending TX at block ${info.height} (hash: ${txKey.slice(0, 32)}...)`);
  console.log(`  Spent ${info.notes.length} of our notes worth ${info.notes.reduce((s, n) => s + n.value, 0) / 1e8} ZEC`);

  const fullTxData = await client.getTransaction(info.txHash);
  const outputs = parseSaplingOutputsV5(fullTxData);

  if (!outputs || outputs.length === 0) {
    console.log("  No Sapling outputs in spending tx (possibly transparent-only)");
    continue;
  }

  console.log(`  ${outputs.length} Sapling output(s) in this tx:`);

  for (let i = 0; i < outputs.length; i++) {
    const out = outputs[i];
    console.log(`\n  Output #${i}:`);

    // Try OVK recovery
    try {
      const recovered = frozts_sapling_try_output_recovery(
        ovk,
        new Uint8Array(out.cv),
        new Uint8Array(out.cmu),
        new Uint8Array(out.ephemeralKey),
        new Uint8Array(out.encCiphertext),
        new Uint8Array(out.outCiphertext),
        BigInt(info.height),
      );

      if (recovered !== null && recovered !== undefined) {
        const isSelf = recovered.address === expectedAddress;
        console.log(`    Recipient: ${recovered.address}${isSelf ? " (SELF - change)" : ""}`);
        console.log(`    Value: ${(Number(recovered.value) / 1e8).toFixed(8)} ZEC (${recovered.value} zat)`);
        const memoText = new TextDecoder().decode(new Uint8Array(recovered.memo).filter(b => b !== 0));
        if (memoText.length > 0) {
          console.log(`    Memo: ${memoText}`);
        }
      } else {
        console.log(`    OVK recovery failed — output was NOT created by our wallet`);
      }
    } catch (err) {
      console.log(`    OVK recovery error: ${err.message}`);
    }
  }
}

console.log("\nDone.");
process.exit(0);
