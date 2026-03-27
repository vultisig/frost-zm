import {
  frobt_derive_address_from_bundle,
  frobt_derive_root_address,
  frobt_keyshare_public_key,
  frobt_keyshare_chain_code,
  frobt_keyshare_birthday,
  frobt_keyshare_network,
  frobt_ckd_derive,
  frobt_derive_child_pubkey,
} from "./wasm.js";
import type { KeyShareInfo } from "./types.js";

export class FrobtWallet {
  private keyShare: Uint8Array;

  constructor(keyShare: Uint8Array) {
    this.keyShare = keyShare;
  }

  getAddress(change: number, index: number): string {
    return frobt_derive_address_from_bundle(this.keyShare, change, index);
  }

  getRootAddress(): string {
    return frobt_derive_root_address(this.keyShare);
  }

  getChainCode(): Uint8Array {
    return frobt_keyshare_chain_code(this.keyShare);
  }

  getBirthday(): number {
    return Number(frobt_keyshare_birthday(this.keyShare));
  }

  getNetwork(): number {
    return frobt_keyshare_network(this.keyShare);
  }

  getKeyShareInfo(): KeyShareInfo {
    return {
      publicKey: frobt_keyshare_public_key(this.keyShare),
      chainCode: frobt_keyshare_chain_code(this.keyShare),
      birthday: this.getBirthday(),
      network: this.getNetwork(),
    };
  }

  ckdDerive(change: number, index: number): Uint8Array {
    return frobt_ckd_derive(this.keyShare, change, index);
  }

  deriveChildPubkey(change: number, index: number): Uint8Array {
    return frobt_derive_child_pubkey(this.keyShare, change, index);
  }
}
