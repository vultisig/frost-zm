import {
  frozts_keyshare_bundle_pack,
} from "./wasm.js";

export function packBundle(
  keyPackage: Uint8Array,
  pubKeyPackage: Uint8Array,
  saplingExtras: Uint8Array,
  birthday: number,
): Uint8Array {
  return frozts_keyshare_bundle_pack(
    keyPackage,
    pubKeyPackage,
    saplingExtras,
    BigInt(birthday),
  );
}

export { encode_map as encodeMap } from "./wasm.js";
