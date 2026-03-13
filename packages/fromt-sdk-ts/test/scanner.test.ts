import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createWalletFull: vi.fn(),
}));

vi.mock("monero-ts", () => ({
  default: {
    MoneroNetworkType: {
      MAINNET: "mainnet",
      TESTNET: "testnet",
      STAGENET: "stagenet",
    },
    MoneroWalletListener: class {
      onSyncProgress?: (
        height: number,
        startHeight: number,
        endHeight: number,
        percentDone: number,
        message: string,
      ) => Promise<void>;
    },
    createWalletFull: mocks.createWalletFull,
  },
}));

import { scan } from "../src/scanner.js";

describe("scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("rescans spent outputs when a spend key is provided", async () => {
    const progress: Array<{ scannedBlocks: number; totalBlocks: number }> = [];
    const wallet = makeWallet([
      makeOutput({
        amount: 4n,
        isSpent: true,
        height: 101,
        hash: "spent",
        index: 0,
        stealthPublicKey: "aa".repeat(32),
        outputIndices: [11],
      }),
      makeOutput({
        amount: 6n,
        isSpent: false,
        height: 102,
        hash: "unspent-1",
        index: 0,
        stealthPublicKey: "bb".repeat(32),
        outputIndices: [21],
      }),
      makeOutput({
        amount: 8n,
        isSpent: false,
        height: 103,
        hash: "unspent-2",
        index: 1,
        stealthPublicKey: "cc".repeat(32),
        outputIndices: [30, 31],
      }),
    ]);
    mocks.createWalletFull.mockResolvedValue(wallet);

    const result = await scan({
      daemonUrl: "http://daemon.example",
      primaryAddress: "4moneroAddress",
      privateViewKey: "11".repeat(32),
      privateSpendKey: "22".repeat(32),
      restoreHeight: 100,
      onProgress: (update) => {
        progress.push(update);
      },
    });

    expect(mocks.createWalletFull).toHaveBeenCalledWith(expect.objectContaining({
      primaryAddress: "4moneroAddress",
      privateViewKey: "11".repeat(32),
      privateSpendKey: "22".repeat(32),
      restoreHeight: 100,
      server: { uri: "http://daemon.example" },
    }));
    expect(wallet.rescanSpent).toHaveBeenCalledTimes(1);
    expect(result.balance).toBe(14);
    expect(result.totalOutputs).toBe(3);
    expect(result.spentOutputs).toBe(1);
    expect(result.outputs).toHaveLength(2);
    expect(result.outputs[0]).toMatchObject({
      height: 102,
      txHash: "unspent-1",
      amount: 6,
      globalIndex: 21,
    });
    expect(Array.from(result.outputs[0]?.outputKey ?? [])).toHaveLength(32);
    expect(result.outputs[1]).toMatchObject({
      height: 103,
      txHash: "unspent-2",
      amount: 8,
      globalIndex: 31,
    });
    expect(progress).toEqual([{ scannedBlocks: 5, totalBlocks: 10 }]);
    expect(wallet.close).toHaveBeenCalledTimes(1);
  });

  it("skips the spent rescan without a spend key", async () => {
    const wallet = makeWallet([]);
    mocks.createWalletFull.mockResolvedValue(wallet);

    await scan({
      daemonUrl: "http://daemon.example",
      primaryAddress: "4moneroAddress",
      privateViewKey: "11".repeat(32),
      restoreHeight: 100,
    });

    expect(wallet.rescanSpent).not.toHaveBeenCalled();
  });
});

function makeWallet(outputs: unknown[]) {
  return {
    sync: vi.fn(async (listener?: {
      onSyncProgress?: (
        height: number,
        startHeight: number,
        endHeight: number,
        percentDone: number,
        message: string,
      ) => Promise<void>;
    }) => {
      await listener?.onSyncProgress?.(105, 100, 110, 0.5, "syncing");
    }),
    rescanSpent: vi.fn(async () => {}),
    getHeight: vi.fn(async () => 123),
    getOutputs: vi.fn(async () => outputs),
    close: vi.fn(async () => {}),
  };
}

function makeOutput({
  amount,
  isSpent,
  height,
  hash,
  index,
  stealthPublicKey,
  outputIndices,
}: {
  amount: bigint;
  isSpent: boolean;
  height: number;
  hash: string;
  index: number;
  stealthPublicKey: string;
  outputIndices: number[];
}) {
  const tx = {
    getHeight: () => height,
    getHash: () => hash,
    getOutputIndices: () => outputIndices,
  };

  return {
    getTx: () => tx,
    getAmount: () => amount,
    getIsSpent: () => isSpent,
    getIndex: () => index,
    getStealthPublicKey: () => stealthPublicKey,
  };
}
