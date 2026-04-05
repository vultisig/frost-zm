import {
  frozts_sapling_build_dfvk,
  frozts_sapling_derive_keys,
  frozts_sapling_generate_extras,
  frozts_sapling_try_decrypt_compact,
  frozts_sapling_decrypt_note_full,
  frozts_sapling_compute_nullifier,
  frozts_sapling_tree_size,
  frozts_keyshare_bundle_pack,
  frozts_keyshare_bundle_birthday,
  frozts_keyshare_bundle_key_package,
  frozts_keyshare_bundle_pub_key_package,
  frozts_keyshare_bundle_sapling_extras,
  encode_map,
  frozts_encode_identifier,
  frozts_keypackage_identifier,
  frozts_pubkeypackage_verifying_key,
  type WasmSaplingKeys,
  WasmShieldingTxBuilder,
} from "frozts-wasm";

export async function initWasm(): Promise<void> {
  // No-op for bundler target — WASM is loaded by the bundler
}

export {
  WasmShieldingTxBuilder,
  frozts_sapling_build_dfvk,
  frozts_sapling_derive_keys,
  frozts_sapling_generate_extras,
  frozts_sapling_try_decrypt_compact,
  frozts_sapling_decrypt_note_full,
  frozts_sapling_compute_nullifier,
  frozts_sapling_tree_size,
  frozts_keyshare_bundle_pack,
  frozts_keyshare_bundle_birthday,
  frozts_keyshare_bundle_key_package,
  frozts_keyshare_bundle_pub_key_package,
  frozts_keyshare_bundle_sapling_extras,
  encode_map,
  frozts_encode_identifier,
  frozts_keypackage_identifier,
  frozts_pubkeypackage_verifying_key,
  type WasmSaplingKeys,
};
