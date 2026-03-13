export interface ScanProgress {
  scannedBlocks: number;
  totalBlocks: number;
}

export interface FoundOutput {
  height: number;
  txHash: string;
  amount: number;
  keyOffset: Uint8Array;
  outputKey: Uint8Array;
  globalIndex: number;
}

export interface ScanResult {
  outputs: FoundOutput[];
  balance: number;
  totalOutputs: number;
  spentOutputs: number;
  chainHeight: number;
  scannedHeight: number;
}

export interface ScannedOutputs {
  outputs: FoundOutput[];
  chainHeight: number;
}

export interface MoneroKeys {
  address: string;
  viewKey: Uint8Array;
  spendPubKey: Uint8Array;
}
