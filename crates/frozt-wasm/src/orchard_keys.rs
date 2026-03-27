use wasm_bindgen::prelude::*;
use crate::to_js_err;
use zcash_address::unified::Encoding;

#[wasm_bindgen]
pub fn frozt_orchard_generate_extras() -> Result<Vec<u8>, JsError> {
	froztlib::orchard_keys::generate_orchard_extras_raw()
		.map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frozt_orchard_derive_extras_from_seed(
	seed: &[u8],
	account_index: u32,
) -> Result<Vec<u8>, JsError> {
	froztlib::orchard_keys::derive_orchard_extras_from_seed(seed, account_index)
		.map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frozt_orchard_build_fvk(
	pub_key_package: &[u8],
	orchard_extras: &[u8],
) -> Result<Vec<u8>, JsError> {
	let fvk = froztlib::orchard_keys::build_orchard_fvk(pub_key_package, orchard_extras)
		.map_err(to_js_err)?;
	Ok(fvk.to_bytes().to_vec())
}

#[wasm_bindgen]
pub struct WasmOrchardKeys {
	address: Vec<u8>,
	ivk: Vec<u8>,
}

#[wasm_bindgen]
impl WasmOrchardKeys {
	#[wasm_bindgen(getter)]
	pub fn address(&self) -> Vec<u8> {
		self.address.clone()
	}

	#[wasm_bindgen(getter)]
	pub fn ivk(&self) -> Vec<u8> {
		self.ivk.clone()
	}
}

#[wasm_bindgen]
pub fn frozt_orchard_derive_keys(
	pub_key_package: &[u8],
	orchard_extras: &[u8],
) -> Result<WasmOrchardKeys, JsError> {
	let fvk = froztlib::orchard_keys::build_orchard_fvk(pub_key_package, orchard_extras)
		.map_err(to_js_err)?;

	let ivk = fvk.to_ivk(orchard::keys::Scope::External);
	let address = fvk.address_at(0u64, orchard::keys::Scope::External);

	Ok(WasmOrchardKeys {
		address: address.to_raw_address_bytes().to_vec(),
		ivk: ivk.to_bytes().to_vec(),
	})
}

#[wasm_bindgen]
pub fn frozt_orchard_build_unified_address(
	pub_key_package: &[u8],
	orchard_extras: &[u8],
	diversifier_index: u64,
) -> Result<String, JsError> {
	let fvk = froztlib::orchard_keys::build_orchard_fvk(pub_key_package, orchard_extras)
		.map_err(to_js_err)?;

	let address = fvk.address_at(diversifier_index, orchard::keys::Scope::External);
	let orchard_receiver = zcash_address::unified::Receiver::Orchard(
		address.to_raw_address_bytes(),
	);

	let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])
		.map_err(|e| JsError::new(&format!("unified address error: {:?}", e)))?;

	Ok(ua.encode(&zcash_protocol::consensus::NetworkType::Main))
}

/// Build a unified address containing both Sapling and Orchard receivers.
#[wasm_bindgen]
pub fn frozt_build_combined_unified_address(
	sapling_pub_key_package: &[u8],
	sapling_extras: &[u8],
	orchard_pub_key_package: &[u8],
	orchard_extras: &[u8],
) -> Result<String, JsError> {
	let sapling_dfvk_raw = froztlib::sapling::build_dfvk_raw(sapling_pub_key_package, sapling_extras)
		.map_err(to_js_err)?;
	let sapling_dfvk = sapling_crypto::zip32::DiversifiableFullViewingKey::from_bytes(&sapling_dfvk_raw)
		.ok_or_else(|| JsError::new("invalid sapling dfvk"))?;
	let (_, sapling_addr) = sapling_dfvk.default_address();

	let orchard_fvk = froztlib::orchard_keys::build_orchard_fvk(orchard_pub_key_package, orchard_extras)
		.map_err(to_js_err)?;
	let orchard_addr = orchard_fvk.address_at(0u64, orchard::keys::Scope::External);

	let receivers = vec![
		zcash_address::unified::Receiver::Orchard(orchard_addr.to_raw_address_bytes()),
		zcash_address::unified::Receiver::Sapling(sapling_addr.to_bytes()),
	];

	let ua = zcash_address::unified::Address::try_from_items(receivers)
		.map_err(|e| JsError::new(&format!("unified address error: {:?}", e)))?;

	Ok(ua.encode(&zcash_protocol::consensus::NetworkType::Main))
}

/// Build an encoded UFVK string containing both Sapling DFVK and Orchard FVK from FROST keys.
/// This is used to pass to the wallet scanner service for detecting Orchard+Sapling notes.
///
/// Constructs the UFVK using raw FVK bytes via zcash_address::unified::Ufvk, which avoids
/// needing the test-dependencies feature on zcash_keys.
#[wasm_bindgen]
pub fn frozt_build_combined_ufvk(
	sapling_pub_key_package: &[u8],
	sapling_extras: &[u8],
	orchard_pub_key_package: &[u8],
	orchard_extras: &[u8],
) -> Result<String, JsError> {
	let sapling_dfvk_raw = froztlib::sapling::build_dfvk_raw(sapling_pub_key_package, sapling_extras)
		.map_err(to_js_err)?;
	let sapling_arr: [u8; 128] = sapling_dfvk_raw.try_into()
		.map_err(|_| JsError::new("sapling dfvk wrong length"))?;

	let orchard_fvk = froztlib::orchard_keys::build_orchard_fvk(orchard_pub_key_package, orchard_extras)
		.map_err(to_js_err)?;
	let orchard_arr = orchard_fvk.to_bytes();

	let items = vec![
		zcash_address::unified::Fvk::Orchard(orchard_arr),
		zcash_address::unified::Fvk::Sapling(sapling_arr),
	];

	let ufvk = zcash_address::unified::Ufvk::try_from_items(items)
		.map_err(|e| JsError::new(&format!("UFVK construction error: {:?}", e)))?;

	Ok(ufvk.encode(&zcash_protocol::consensus::NetworkType::Main))
}

/// Build an encoded UFVK string containing only Orchard FVK from FROST keys.
#[wasm_bindgen]
pub fn frozt_build_orchard_ufvk(
	orchard_pub_key_package: &[u8],
	orchard_extras: &[u8],
) -> Result<String, JsError> {
	let orchard_fvk = froztlib::orchard_keys::build_orchard_fvk(orchard_pub_key_package, orchard_extras)
		.map_err(to_js_err)?;
	let orchard_arr = orchard_fvk.to_bytes();

	let items = vec![
		zcash_address::unified::Fvk::Orchard(orchard_arr),
	];

	let ufvk = zcash_address::unified::Ufvk::try_from_items(items)
		.map_err(|e| JsError::new(&format!("UFVK construction error: {:?}", e)))?;

	Ok(ufvk.encode(&zcash_protocol::consensus::NetworkType::Main))
}
