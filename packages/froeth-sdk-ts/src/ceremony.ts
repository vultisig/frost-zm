import { froeth_keyshare_bundle_pack, encode_map } from "./wasm.js";

export function packBundle(
  keyPackage: Uint8Array,
  pubKeyPackage: Uint8Array,
  chainCode: Uint8Array,
  network: number,
  birthday: number,
): Uint8Array {
  return froeth_keyshare_bundle_pack(keyPackage, pubKeyPackage, chainCode, network, BigInt(birthday));
}

export { encode_map as encodeMap };
