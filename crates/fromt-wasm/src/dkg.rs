use wasm_bindgen::prelude::*;

use fromtlib::ceremony::key_import;

use crate::to_js_err;

#[wasm_bindgen]
pub fn fromt_derive_keys_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("seed must be 32 bytes"));
    }
    let arr: &[u8; 32] = seed.try_into().map_err(to_js_err)?;
    let (sk, vk) = key_import::derive_keys_from_seed(arr).map_err(to_js_err)?;
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&sk);
    result.extend_from_slice(&vk);
    Ok(result)
}
