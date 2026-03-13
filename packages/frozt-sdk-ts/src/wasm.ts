import {
  frozt_sapling_build_dfvk,
  frozt_sapling_derive_keys,
  frozt_sapling_generate_extras,
  frozt_sapling_try_decrypt_compact,
  frozt_sapling_decrypt_note_full,
  frozt_sapling_compute_nullifier,
  frozt_keyshare_bundle_pack,
  frozt_keyshare_bundle_birthday,
  frozt_keyshare_bundle_key_package,
  frozt_keyshare_bundle_pub_key_package,
  frozt_keyshare_bundle_sapling_extras,
  encode_map,
  frozt_encode_identifier,
  frozt_keypackage_identifier,
  frozt_pubkeypackage_verifying_key,
  type WasmSaplingKeys,
  WasmShieldingTxBuilder,
} from "frozt-wasm";

export async function initWasm(): Promise<void> {
  // No-op for bundler target — WASM is loaded by the bundler
}

export {
  WasmShieldingTxBuilder,
  frozt_sapling_build_dfvk,
  frozt_sapling_derive_keys,
  frozt_sapling_generate_extras,
  frozt_sapling_try_decrypt_compact,
  frozt_sapling_decrypt_note_full,
  frozt_sapling_compute_nullifier,
  frozt_keyshare_bundle_pack,
  frozt_keyshare_bundle_birthday,
  frozt_keyshare_bundle_key_package,
  frozt_keyshare_bundle_pub_key_package,
  frozt_keyshare_bundle_sapling_extras,
  encode_map,
  frozt_encode_identifier,
  frozt_keypackage_identifier,
  frozt_pubkeypackage_verifying_key,
  type WasmSaplingKeys,
};
