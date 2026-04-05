import {
  frozts_sapling_try_decrypt_compact,
  frozts_sapling_decrypt_note_full,
  frozts_sapling_compute_nullifier,
  frozts_sapling_tree_size,
} from "./wasm.js";
import type {
  FoundNote,
  LightwalletTransport,
  ScanProgress,
  ScanResult,
} from "./types.js";
import { LightwalletClient } from "./lightwalletd.js";

export interface ScanOptions {
  lightwalletdUrl: string;
  ivk: Uint8Array;
  dfvk: Uint8Array;
  startHeight: number;
  endHeight?: number;
  initialTreeSize?: number;
  onProgress?: (progress: ScanProgress) => void;
  batchSize?: number;
  client?: LightwalletTransport;
}

interface RawNote extends FoundNote {
  cmu: Uint8Array;
  ephemeralKey: Uint8Array;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const {
    lightwalletdUrl,
    ivk,
    dfvk,
    startHeight,
    onProgress,
    batchSize = 10000,
  } = options;

  const client = options.client ?? new LightwalletClient(lightwalletdUrl);

  const endHeight = options.endHeight ?? await client.getLatestBlockHeight();
  const totalBlocks = endHeight - startHeight + 1;

  const initialTreeSize = await resolveInitialTreeSize(client, startHeight, options.initialTreeSize);

  const rawNotes: RawNote[] = [];
  const spentNullifiers = new Set<string>();
  let commitmentPos = initialTreeSize;
  let scannedBlocks = 0;

  for (let batchStart = startHeight; batchStart <= endHeight; batchStart += batchSize) {
    const batchEnd = Math.min(batchStart + batchSize - 1, endHeight);
    const blocks = await client.getBlockRange(batchStart, batchEnd);

    for (const block of blocks) {
      scannedBlocks++;

      for (const tx of block.transactions) {
        for (const spend of tx.spends) {
          if (spend.nf.length === 32) {
            spentNullifiers.add(toHex(spend.nf));
          }
        }

        for (let i = 0; i < tx.outputs.length; i++) {
          const output = tx.outputs[i];

          if (output.cmu.length !== 32) {
            commitmentPos++;
            continue;
          }

          const notePos = commitmentPos;
          commitmentPos++;

          if (output.ephemeralKey.length !== 32 || output.ciphertext.length !== 52) {
            continue;
          }

          const value = frozts_sapling_try_decrypt_compact(
            ivk,
            output.cmu,
            output.ephemeralKey,
            output.ciphertext,
            BigInt(block.height),
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

      if (onProgress && scannedBlocks % 1000 === 0) {
        onProgress({ scannedBlocks, totalBlocks });
      }
    }
  }

  // Filter spent notes: for each found note, fetch full tx, decrypt fully,
  // compute nullifier, check against on-chain spent nullifiers
  const unspentNotes: FoundNote[] = [];

  for (const note of rawNotes) {
    try {
      const fullTxData = await client.getTransaction(note.txHash);
      const encCiphertext = extractSaplingEncCiphertext(fullTxData, note.index);
      if (!encCiphertext) {
        unspentNotes.push(note);
        continue;
      }

      const noteData = frozts_sapling_decrypt_note_full(
        ivk,
        note.cmu,
        note.ephemeralKey,
        encCiphertext,
        BigInt(note.height),
      );

      const nullifier = frozts_sapling_compute_nullifier(
        dfvk,
        noteData,
        BigInt(note.position),
        BigInt(note.height),
      );

      const nfHex = toHex(nullifier);
      if (!spentNullifiers.has(nfHex)) {
        unspentNotes.push(note);
      }
    } catch {
      unspentNotes.push(note);
    }
  }

  let spendableBalance = 0;
  for (const note of unspentNotes) {
    spendableBalance += note.value;
  }

  const totalNotes = rawNotes.length;
  const spentNotes = totalNotes - unspentNotes.length;

  return {
    notes: unspentNotes,
    spendableBalance,
    totalNotes,
    spentNotes,
    spentNullifiers,
    chainHeight: endHeight,
    scannedHeight: endHeight,
  };
}

async function resolveInitialTreeSize(
  client: LightwalletTransport,
  startHeight: number,
  initialTreeSize?: number,
): Promise<number> {
  if (initialTreeSize !== undefined) {
    return initialTreeSize;
  }

  if (startHeight === 0) {
    return 0;
  }

  if (!client.getTreeState) {
    throw new Error("initialTreeSize is required when getTreeState is unavailable");
  }

  const treeState = await client.getTreeState(startHeight - 1);
  return Number(frozts_sapling_tree_size(treeState));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Parse Zcash v5 tx to extract the 580-byte Sapling enc_ciphertext for output at `index`
function extractSaplingEncCiphertext(
  rawTx: Uint8Array,
  outputIndex: number,
): Uint8Array | null {
  const view = new DataView(rawTx.buffer, rawTx.byteOffset, rawTx.byteLength);
  let offset = 0;

  // header (4) + versionGroupId (4)
  const header = view.getUint32(offset, true);
  offset += 4;
  if ((header & 0x80000000) === 0) return null;
  offset += 4; // versionGroupId

  // consensusBranchId (4) + lockTime (4) + expiryHeight (4)
  offset += 4 + 4 + 4;

  // transparent inputs
  const nTxIn = readCompactSize(rawTx, offset);
  offset = nTxIn.offset;
  for (let i = 0; i < nTxIn.value; i++) {
    offset += 36; // prevout
    const scriptLen = readCompactSize(rawTx, offset);
    offset = scriptLen.offset + scriptLen.value;
    offset += 4; // sequence
  }

  // transparent outputs
  const nTxOut = readCompactSize(rawTx, offset);
  offset = nTxOut.offset;
  for (let i = 0; i < nTxOut.value; i++) {
    offset += 8; // value
    const scriptLen = readCompactSize(rawTx, offset);
    offset = scriptLen.offset + scriptLen.value;
  }

  // sapling spends
  const nSpendsSapling = readCompactSize(rawTx, offset);
  offset = nSpendsSapling.offset;
  for (let i = 0; i < nSpendsSapling.value; i++) {
    offset += 32 + 32 + 32; // cv + anchor + nullifier (96 bytes total for v5 spend)
  }

  // sapling outputs
  const nOutputsSapling = readCompactSize(rawTx, offset);
  offset = nOutputsSapling.offset;

  for (let i = 0; i < nOutputsSapling.value; i++) {
    // v5 (ZIP 225): cv(32) + cmu(32) + ephemeralKey(32) + encCiphertext(580) + outCiphertext(80) = 756
    const outputStart = offset;
    if (i === outputIndex) {
      const encStart = outputStart + 32 + 32 + 32;
      if (encStart + 580 > rawTx.length) return null;
      return rawTx.slice(encStart, encStart + 580);
    }
    offset += 756;
  }

  return null;
}

function readCompactSize(
  data: Uint8Array,
  offset: number,
): { value: number; offset: number } {
  const first = data[offset];
  if (first < 253) {
    return { value: first, offset: offset + 1 };
  } else if (first === 253) {
    const view = new DataView(data.buffer, data.byteOffset);
    return { value: view.getUint16(offset + 1, true), offset: offset + 3 };
  } else if (first === 254) {
    const view = new DataView(data.buffer, data.byteOffset);
    return { value: view.getUint32(offset + 1, true), offset: offset + 5 };
  }
  return { value: 0, offset: offset + 9 };
}
