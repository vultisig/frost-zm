import {
  frozt_sapling_build_dfvk,
  frozt_sapling_derive_keys,
  frozt_keyshare_bundle_birthday,
  frozt_keyshare_bundle_pub_key_package,
  frozt_keyshare_bundle_sapling_extras,
  frozt_keyshare_bundle_key_package,
} from "./wasm.js";
import { scan, type ScanOptions } from "./scanner.js";
import type { SaplingKeys, ScanResult, ScanProgress } from "./types.js";

export class FroztWallet {
  private bundle: Uint8Array;
  private pubKeyPackage: Uint8Array;
  private saplingExtras: Uint8Array;
  private keyPackage: Uint8Array;
  private birthday: number;

  constructor(bundle: Uint8Array) {
    this.bundle = bundle;
    this.pubKeyPackage = frozt_keyshare_bundle_pub_key_package(bundle);
    this.saplingExtras = frozt_keyshare_bundle_sapling_extras(bundle);
    this.keyPackage = frozt_keyshare_bundle_key_package(bundle);
    this.birthday = Number(frozt_keyshare_bundle_birthday(bundle));
  }

  getAddress(): string {
    return this.deriveKeys().address;
  }

  deriveKeys(): SaplingKeys {
    const keys = frozt_sapling_derive_keys(this.pubKeyPackage, this.saplingExtras);
    return {
      address: keys.address as unknown as string,
      ivk: keys.ivk as Uint8Array,
      nk: keys.nk as Uint8Array,
    };
  }

  getDfvk(): Uint8Array {
    return frozt_sapling_build_dfvk(this.pubKeyPackage, this.saplingExtras);
  }

  getBirthday(): number {
    return this.birthday;
  }

  getKeyPackage(): Uint8Array {
    return this.keyPackage;
  }

  getPubKeyPackage(): Uint8Array {
    return this.pubKeyPackage;
  }

  getSaplingExtras(): Uint8Array {
    return this.saplingExtras;
  }

  async scan(
    lightwalletdUrl: string,
    onProgress?: (progress: ScanProgress) => void,
  ): Promise<ScanResult> {
    const keys = this.deriveKeys();

    return scan({
      lightwalletdUrl,
      ivk: keys.ivk,
      dfvk: this.getDfvk(),
      startHeight: this.birthday,
      onProgress,
    });
  }

  async getBalance(lightwalletdUrl: string): Promise<number> {
    const result = await this.scan(lightwalletdUrl);
    return result.spendableBalance;
  }
}
