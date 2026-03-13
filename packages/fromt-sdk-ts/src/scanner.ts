import moneroTs from "monero-ts";
import type { ScanResult, ScanProgress, FoundOutput, ScannedOutputs, SpendInput, DecoyRing } from "./types.js";

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

export async function scanOutputs(options: Omit<ScanOptions, "privateSpendKey" | "rescanSpent">): Promise<ScannedOutputs> {
  const {
    daemonUrl,
    primaryAddress,
    privateViewKey,
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

  const chainHeight = await wallet.getHeight();
  const walletOutputs = await wallet.getOutputs();
  const outputs = walletOutputs.map(mapWalletOutput);

  await wallet.close();

  return { outputs, chainHeight };
}

export function encodeOutputsForKeyImage(outputs: FoundOutput[]): Uint8Array {
  const count = outputs.length;
  const buf = new Uint8Array(4 + count * 64);
  const view = new DataView(buf.buffer);
  view.setUint32(0, count, true);

  for (let i = 0; i < count; i++) {
    const off = 4 + i * 64;
    buf.set(outputs[i].outputKey.slice(0, 32), off);
    buf.set(outputs[i].keyOffset.slice(0, 32), off + 32);
  }

  return buf;
}

export function encodeOutputsWithAmounts(outputs: FoundOutput[]): Uint8Array {
  const count = outputs.length;
  const buf = new Uint8Array(4 + count * 72);
  const view = new DataView(buf.buffer);
  view.setUint32(0, count, true);

  for (let i = 0; i < count; i++) {
    const off = 4 + i * 72;
    buf.set(outputs[i].outputKey.slice(0, 32), off);
    buf.set(outputs[i].keyOffset.slice(0, 32), off + 32);
    const lo = outputs[i].amount & 0xffffffff;
    const hi = Math.floor(outputs[i].amount / 0x100000000) & 0xffffffff;
    view.setUint32(off + 64, lo, true);
    view.setUint32(off + 68, hi, true);
  }

  return buf;
}

export function filterSpentOutputs(
  outputs: FoundOutput[],
  spentFlags: boolean[],
): ScanResult {
  if (spentFlags.length < outputs.length) {
    throw new Error(`expected ${outputs.length} spent flags, got ${spentFlags.length}`);
  }

  const unspent: FoundOutput[] = [];
  let spentCount = 0;
  for (let i = 0; i < outputs.length; i++) {
    if (spentFlags[i]) {
      spentCount++;
    } else {
      unspent.push(outputs[i]);
    }
  }

  let balance = 0;
  for (const out of unspent) {
    balance += out.amount;
  }

  return {
    outputs: unspent,
    balance,
    totalOutputs: outputs.length,
    spentOutputs: spentCount,
    chainHeight: 0,
    scannedHeight: 0,
  };
}

export function encodeSpendInputs(inputs: SpendInput[]): Uint8Array {
  const recordSize = 8 + 32 + 32 + 32 + 8;
  const buf = new Uint8Array(4 + inputs.length * recordSize);
  const view = new DataView(buf.buffer);
  view.setUint32(0, inputs.length, true);

  let off = 4;
  for (const input of inputs) {
    const lo = input.amount & 0xffffffff;
    const hi = Math.floor(input.amount / 0x100000000) & 0xffffffff;
    view.setUint32(off, lo, true);
    view.setUint32(off + 4, hi, true);
    off += 8;
    buf.set(input.keyOffset.slice(0, 32), off);
    off += 32;
    buf.set(input.outputKey.slice(0, 32), off);
    off += 32;
    buf.set(input.commitmentMask.slice(0, 32), off);
    off += 32;
    const glo = input.globalIndex & 0xffffffff;
    const ghi = Math.floor(input.globalIndex / 0x100000000) & 0xffffffff;
    view.setUint32(off, glo, true);
    view.setUint32(off + 4, ghi, true);
    off += 8;
  }

  return buf;
}

export function encodeDecoyRings(rings: DecoyRing[]): Uint8Array {
  let totalSize = 4;
  for (const ring of rings) {
    totalSize += 4 + 4 + ring.members.length * (32 + 32 + 8);
  }

  const buf = new Uint8Array(totalSize);
  const view = new DataView(buf.buffer);
  view.setUint32(0, rings.length, true);

  let off = 4;
  for (const ring of rings) {
    view.setUint32(off, ring.members.length, true);
    off += 4;
    view.setUint32(off, ring.realIndex, true);
    off += 4;
    for (const member of ring.members) {
      buf.set(member.outputKey.slice(0, 32), off);
      off += 32;
      buf.set(member.commitment.slice(0, 32), off);
      off += 32;
      const mlo = member.globalIndex & 0xffffffff;
      const mhi = Math.floor(member.globalIndex / 0x100000000) & 0xffffffff;
      view.setUint32(off, mlo, true);
      view.setUint32(off + 4, mhi, true);
      off += 8;
    }
  }

  return buf;
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
