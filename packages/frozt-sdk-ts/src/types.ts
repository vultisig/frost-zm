export interface ScanProgress {
  scannedBlocks: number;
  totalBlocks: number;
}

export interface FoundNote {
  height: number;
  txHash: Uint8Array;
  index: number;
  value: number;
  position: number;
}

export interface ScanResult {
  notes: FoundNote[];
  spendableBalance: number;
  totalNotes: number;
  spentNotes: number;
  spentNullifiers: Set<string>;
  chainHeight: number;
  scannedHeight: number;
}

export interface CompactOutput {
  cmu: Uint8Array;
  ephemeralKey: Uint8Array;
  ciphertext: Uint8Array;
}

export interface CompactSpend {
  nf: Uint8Array;
}

export interface CompactTx {
  hash: Uint8Array;
  spends: CompactSpend[];
  outputs: CompactOutput[];
}

export interface CompactBlock {
  height: number;
  transactions: CompactTx[];
}

export interface KeygenMetadata {
  extras: Uint8Array;
  birthday: bigint;
}

export interface SaplingKeys {
  address: string;
  ivk: Uint8Array;
  nk: Uint8Array;
}
