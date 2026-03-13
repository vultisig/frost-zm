import {
  fromt_derive_view_key,
  fromt_derive_spend_pub_key,
  fromt_derive_address,
  fromt_derive_subaddress,
  fromt_compute_key_image,
  fromt_derive_key_offset,
  fromt_outputs_for_key_image,
  fromt_filter_spent_outputs,
  fromt_keyshare_birthday,
  fromt_keyshare_network,
  fromt_derive_keys_from_seed,
  fromt_spend_preprocess,
  fromt_spend_sign,
  fromt_spend_complete,
  fromt_handle_free,
  type SpendPreprocessResult,
  type SpendSignResult,
} from "fromt-wasm";

export async function initWasm(): Promise<void> {
  // No-op for bundler target
}

export {
  fromt_derive_view_key,
  fromt_derive_spend_pub_key,
  fromt_derive_address,
  fromt_derive_subaddress,
  fromt_compute_key_image,
  fromt_derive_key_offset,
  fromt_outputs_for_key_image,
  fromt_filter_spent_outputs,
  fromt_keyshare_birthday,
  fromt_keyshare_network,
  fromt_derive_keys_from_seed,
  fromt_spend_preprocess,
  fromt_spend_sign,
  fromt_spend_complete,
  fromt_handle_free,
  type SpendPreprocessResult,
  type SpendSignResult,
};
