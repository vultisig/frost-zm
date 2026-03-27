export interface EthKeys {
  address: string;          // EIP-55 checksummed 0x address
  verifyingKey: Uint8Array; // compressed secp256k1 public key (33 bytes)
}

export interface UserOperation {
  sender: string;
  nonce: bigint;
  initCode: Uint8Array;
  callData: Uint8Array;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData: Uint8Array;
  signature: Uint8Array;
}

export interface BundlerConfig {
  bundlerUrl: string;
  entryPointAddress: string;
  factoryAddress: string;
}

export interface UserOpReceipt {
  userOpHash: string;
  transactionHash: string;
  success: boolean;
  actualGasCost: bigint;
  actualGasUsed: bigint;
}

export interface DeriveResult {
  privateKey: Uint8Array;
  chainCode: Uint8Array;
  publicKey: Uint8Array;
}
