import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getLatestBlockHeight: vi.fn<() => Promise<number>>(),
  getBlockRange: vi.fn<() => Promise<unknown[]>>(),
  getTransaction: vi.fn<() => Promise<Uint8Array>>(),
  tryDecryptCompact: vi.fn(),
  decryptNoteFull: vi.fn(),
  computeNullifier: vi.fn(),
}));

vi.mock("../src/lightwalletd.js", () => ({
  LightwalletClient: class {
    getLatestBlockHeight = mocks.getLatestBlockHeight;
    getBlockRange = mocks.getBlockRange;
    getTransaction = mocks.getTransaction;
  },
}));

vi.mock("../src/wasm.js", () => ({
  frozt_sapling_try_decrypt_compact: mocks.tryDecryptCompact,
  frozt_sapling_decrypt_note_full: mocks.decryptNoteFull,
  frozt_sapling_compute_nullifier: mocks.computeNullifier,
}));

import { scan } from "../src/scanner.js";

describe("scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("filters spent notes out of the balance and counts them", async () => {
    const txHash = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
    const spentNullifier = new Uint8Array(32).fill(0xaa);
    const unspentNullifier = new Uint8Array(32).fill(0xbb);

    mocks.getBlockRange.mockResolvedValue([
      {
        height: 100,
        transactions: [
          {
            hash: txHash,
            spends: [{ nf: spentNullifier }],
            outputs: [
              {
                cmu: new Uint8Array(32).fill(1),
                ephemeralKey: new Uint8Array(32).fill(2),
                ciphertext: new Uint8Array(52).fill(3),
              },
              {
                cmu: new Uint8Array(32).fill(4),
                ephemeralKey: new Uint8Array(32).fill(5),
                ciphertext: new Uint8Array(52).fill(6),
              },
            ],
          },
        ],
      },
    ]);
    mocks.getTransaction.mockResolvedValue(
      buildSaplingTx([
        new Uint8Array(580).fill(7),
        new Uint8Array(580).fill(8),
      ]),
    );
    mocks.tryDecryptCompact
      .mockReturnValueOnce(5n)
      .mockReturnValueOnce(7n);
    mocks.decryptNoteFull
      .mockReturnValueOnce(new Uint8Array([1]))
      .mockReturnValueOnce(new Uint8Array([2]));
    mocks.computeNullifier
      .mockReturnValueOnce(spentNullifier)
      .mockReturnValueOnce(unspentNullifier);

    const result = await scan({
      lightwalletdUrl: "https://lightwalletd.example",
      ivk: new Uint8Array(32),
      dfvk: new Uint8Array(32),
      startHeight: 100,
      endHeight: 100,
    });

    expect(result.spendableBalance).toBe(7);
    expect(result.totalNotes).toBe(2);
    expect(result.spentNotes).toBe(1);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]?.value).toBe(7);
    expect(result.spentNullifiers.has(toHex(spentNullifier))).toBe(true);
  });
});

function buildSaplingTx(encCiphertexts: Uint8Array[]): Uint8Array {
  const bytes: number[] = [];

  pushU32(bytes, 0x80000005);
  pushU32(bytes, 0x26a7270a);
  pushU32(bytes, 0);
  pushU32(bytes, 0);
  pushU32(bytes, 0);
  bytes.push(0x00);
  bytes.push(0x00);
  bytes.push(0x00);
  bytes.push(encodeCompactSize(encCiphertexts.length));

  for (const encCiphertext of encCiphertexts) {
    bytes.push(...new Uint8Array(32).fill(0x11));
    bytes.push(...new Uint8Array(32).fill(0x22));
    bytes.push(...new Uint8Array(32).fill(0x33));
    bytes.push(...encCiphertext);
    bytes.push(...new Uint8Array(80).fill(0x44));
  }

  return Uint8Array.from(bytes);
}

function pushU32(bytes: number[], value: number): void {
  bytes.push(value & 0xff);
  bytes.push((value >>> 8) & 0xff);
  bytes.push((value >>> 16) & 0xff);
  bytes.push((value >>> 24) & 0xff);
}

function encodeCompactSize(value: number): number {
  if (value >= 253) {
    throw new Error("test helper only supports compact sizes < 253");
  }
  return value;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
