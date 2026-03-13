import {
  fromt_derive_view_key,
  fromt_derive_spend_pub_key,
  fromt_derive_address,
  fromt_derive_subaddress,
  fromt_keyshare_birthday,
  fromt_keyshare_network,
  fromt_compute_key_image,
  fromt_outputs_for_key_image,
} from "./wasm.js";
import { scan, scanOutputs, encodeOutputsForKeyImage, encodeOutputsWithAmounts, filterSpentOutputs } from "./scanner.js";
import type { MoneroKeys, ScanResult, ScanProgress, ScannedOutputs } from "./types.js";

export class FromtWallet {
  private keyShare: Uint8Array;

  constructor(keyShare: Uint8Array) {
    this.keyShare = keyShare;
  }

  getAddress(): string {
    return fromt_derive_address(this.keyShare);
  }

  getSubaddress(account: number, index: number): string {
    return fromt_derive_subaddress(this.keyShare, account, index);
  }

  deriveKeys(): MoneroKeys {
    return {
      address: this.getAddress(),
      viewKey: fromt_derive_view_key(this.keyShare),
      spendPubKey: fromt_derive_spend_pub_key(this.keyShare),
    };
  }

  getBirthday(): number {
    return Number(fromt_keyshare_birthday(this.keyShare));
  }

  getNetwork(): number {
    return fromt_keyshare_network(this.keyShare);
  }

  getNetworkName(): "mainnet" | "stagenet" | "testnet" {
    const n = this.getNetwork();
    if (n === 1) return "testnet";
    if (n === 2) return "stagenet";
    return "mainnet";
  }

  computeKeyImage(keyOffset: Uint8Array, outputKey: Uint8Array, spendKey: Uint8Array): Uint8Array {
    return fromt_compute_key_image(keyOffset, outputKey, spendKey);
  }

  async scanBalance(
    daemonUrl: string,
    onProgress?: (progress: ScanProgress) => void,
    privateSpendKey?: Uint8Array,
  ): Promise<ScanResult> {
    const viewKey = fromt_derive_view_key(this.keyShare);
    const viewKeyHex = toHex(viewKey);
    const address = this.getAddress();

    return scan({
      daemonUrl,
      primaryAddress: address,
      privateViewKey: viewKeyHex,
      privateSpendKey: privateSpendKey ? toHex(privateSpendKey) : undefined,
      restoreHeight: this.getBirthday(),
      networkType: this.getNetworkName(),
      onProgress,
    });
  }

  async getBalance(daemonUrl: string, privateSpendKey?: Uint8Array): Promise<number> {
    const result = await this.scanBalance(daemonUrl, undefined, privateSpendKey);
    return result.balance;
  }

  async scanForKeyImageCeremony(
    daemonUrl: string,
    onProgress?: (progress: ScanProgress) => void,
  ): Promise<ScannedOutputs> {
    const viewKey = fromt_derive_view_key(this.keyShare);
    const viewKeyHex = toHex(viewKey);
    const address = this.getAddress();

    return scanOutputs({
      daemonUrl,
      primaryAddress: address,
      privateViewKey: viewKeyHex,
      restoreHeight: this.getBirthday(),
      networkType: this.getNetworkName(),
      onProgress,
    });
  }

  encodeOutputsForKeyImage(outputs: ScannedOutputs["outputs"]): Uint8Array {
    return encodeOutputsForKeyImage(outputs);
  }

  encodeOutputsWithAmounts(outputs: ScannedOutputs["outputs"]): Uint8Array {
    return encodeOutputsWithAmounts(outputs);
  }

  outputsForKeyImageFromBinary(outputsData: Uint8Array): Uint8Array {
    return fromt_outputs_for_key_image(outputsData);
  }

  async filterSpentOutputs(
    daemonUrl: string,
    outputs: ScannedOutputs["outputs"],
    keyImages: Uint8Array,
  ): Promise<ScanResult> {
    return filterSpentOutputs(daemonUrl, outputs, keyImages);
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
