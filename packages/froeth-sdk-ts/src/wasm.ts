export {
  froeth_keyshare_bundle_pack,
  froeth_keyshare_bundle_pub_key_package,
  froeth_keyshare_bundle_key_package,
  froeth_keyshare_bundle_chain_code,
  froeth_keyshare_bundle_network,
  froeth_keyshare_bundle_birthday,
  froeth_eth_address,
  froeth_derive_root_address,
  froeth_derive_child_address,
  froeth_derive_child_pubkey,
  froeth_derive_from_seed,
  encode_map,
} from "froeth-wasm";

export function initWasm(): void {
  // no-op for bundler target
}
