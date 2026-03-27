import {
  froeth_keyshare_bundle_pub_key_package,
  froeth_keyshare_bundle_key_package,
  froeth_keyshare_bundle_chain_code,
  froeth_keyshare_bundle_network,
  froeth_keyshare_bundle_birthday,
  froeth_derive_root_address,
  froeth_derive_child_address,
  froeth_derive_child_pubkey,
} from "./wasm.js";
import type { EthKeys } from "./types.js";

export class FroethWallet {
  private bundle: Uint8Array;
  private pubKeyPackage: Uint8Array;
  private keyPackage: Uint8Array;
  private chainCode: Uint8Array;

  constructor(bundle: Uint8Array) {
    this.bundle = bundle;
    this.pubKeyPackage = froeth_keyshare_bundle_pub_key_package(bundle);
    this.keyPackage = froeth_keyshare_bundle_key_package(bundle);
    this.chainCode = froeth_keyshare_bundle_chain_code(bundle);
  }

  getAddress(): string {
    return froeth_derive_root_address(this.bundle);
  }

  deriveKeys(): EthKeys {
    const address = this.getAddress();
    return { address, verifyingKey: this.pubKeyPackage };
  }

  deriveChildAddress(change: number, index: number): string {
    return froeth_derive_child_address(this.bundle, change, index);
  }

  deriveChildPubkey(change: number, index: number): Uint8Array {
    return froeth_derive_child_pubkey(this.bundle, change, index);
  }

  getNetwork(): number {
    return froeth_keyshare_bundle_network(this.bundle);
  }

  getBirthday(): number {
    return Number(froeth_keyshare_bundle_birthday(this.bundle));
  }

  getPubKeyPackage(): Uint8Array {
    return this.pubKeyPackage;
  }

  getKeyPackage(): Uint8Array {
    return this.keyPackage;
  }

  getChainCode(): Uint8Array {
    return this.chainCode;
  }

  getBundle(): Uint8Array {
    return this.bundle;
  }
}
