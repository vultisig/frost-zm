import moneroTs from "monero-ts";
import type { ScanResult, ScanProgress, FoundOutput } from "./types.js";

export interface ScanOptions {
  daemonUrl: string;
  primaryAddress: string;
  privateViewKey: string;
  privateSpendKey?: string;
  restoreHeight: number;
  networkType?: "mainnet" | "stagenet" | "testnet";
  onProgress?: (progress: ScanProgress) => void;
  rescanSpent?: boolean;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const {
    daemonUrl,
    primaryAddress,
    privateViewKey,
    privateSpendKey,
    restoreHeight,
    networkType = "mainnet",
  } = options;

  const netType =
    networkType === "stagenet"
      ? moneroTs.MoneroNetworkType.STAGENET
      : networkType === "testnet"
        ? moneroTs.MoneroNetworkType.TESTNET
        : moneroTs.MoneroNetworkType.MAINNET;

  const wallet = await moneroTs.createWalletFull({
    networkType: netType,
    primaryAddress,
    privateViewKey,
    privateSpendKey,
    restoreHeight,
    server: { uri: daemonUrl },
    proxyToWorker: false,
  });

  if (options.onProgress) {
    const progressCb = options.onProgress;
    const listener = new moneroTs.MoneroWalletListener();
    listener.onSyncProgress = async (
      height: number,
      startHeight: number,
      endHeight: number,
      _percentDone: number,
      _message: string,
    ) => {
      progressCb({
        scannedBlocks: height - startHeight,
        totalBlocks: endHeight - startHeight,
      });
    };
    await wallet.sync(listener);
  } else {
    await wallet.sync();
  }

  if (privateSpendKey && options.rescanSpent !== false) {
    await wallet.rescanSpent();
  }

  const chainHeight = await wallet.getHeight();
  const walletOutputs = await wallet.getOutputs();
  const unspentOutputs = walletOutputs.filter((output) => !output.getIsSpent());
  const outputs = unspentOutputs.map(mapWalletOutput);

  let balance = 0;
  for (const output of outputs) {
    balance += output.amount;
  }

  await wallet.close();

  return {
    outputs,
    balance,
    totalOutputs: walletOutputs.length,
    spentOutputs: walletOutputs.length - unspentOutputs.length,
    chainHeight,
    scannedHeight: chainHeight,
  };
}

function mapWalletOutput(output: {
  getTx(): {
    getHeight(): number | undefined;
    getHash(): string | undefined;
    getOutputIndices(): number[] | undefined;
  } | undefined;
  getAmount(): bigint;
  getIndex(): number | undefined;
  getStealthPublicKey(): string | undefined;
}): FoundOutput {
  const tx = output.getTx();
  const outputIndex = output.getIndex() ?? 0;
  const globalIndex = tx?.getOutputIndices()?.[outputIndex] ?? 0;

  return {
    height: tx?.getHeight() ?? 0,
    txHash: tx?.getHash() ?? "",
    amount: Number(output.getAmount()),
    keyOffset: new Uint8Array(0),
    outputKey: hexToBytes(output.getStealthPublicKey()),
    globalIndex,
  };
}

function hexToBytes(value: string | undefined): Uint8Array {
  if (!value || value.length % 2 !== 0) {
    return new Uint8Array(0);
  }

  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    const byte = Number.parseInt(value.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) {
      return new Uint8Array(0);
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}
