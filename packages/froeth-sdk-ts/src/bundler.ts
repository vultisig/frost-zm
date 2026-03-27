import type { BundlerConfig, UserOpReceipt } from "./types.js";

export class BundlerClient {
  private url: string;
  private entryPoint: string;

  constructor(config: BundlerConfig) {
    this.url = config.bundlerUrl;
    this.entryPoint = config.entryPointAddress;
  }

  async sendUserOperation(userOp: Record<string, unknown>): Promise<string> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_sendUserOperation",
        params: [userOp, this.entryPoint],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Bundler error: ${result.error.message}`);
    }
    return result.result as string;
  }

  async getUserOperationReceipt(userOpHash: string): Promise<UserOpReceipt | null> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getUserOperationReceipt",
        params: [userOpHash],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Bundler error: ${result.error.message}`);
    }
    if (!result.result) return null;

    const r = result.result;
    return {
      userOpHash: r.userOpHash,
      transactionHash: r.receipt.transactionHash,
      success: r.success,
      actualGasCost: BigInt(r.actualGasCost),
      actualGasUsed: BigInt(r.actualGasUsed),
    };
  }

  async estimateUserOperationGas(
    userOp: Record<string, unknown>,
  ): Promise<{ callGasLimit: bigint; verificationGasLimit: bigint; preVerificationGas: bigint }> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_estimateUserOperationGas",
        params: [userOp, this.entryPoint],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Bundler error: ${result.error.message}`);
    }

    const r = result.result;
    return {
      callGasLimit: BigInt(r.callGasLimit),
      verificationGasLimit: BigInt(r.verificationGasLimit),
      preVerificationGas: BigInt(r.preVerificationGas),
    };
  }

  async getSupportedEntryPoints(): Promise<string[]> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_supportedEntryPoints",
        params: [],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Bundler error: ${result.error.message}`);
    }
    return result.result as string[];
  }
}
