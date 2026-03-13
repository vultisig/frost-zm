use wasm_bindgen::prelude::*;

use fromtlib::keyshare::bundle::KeyShareBundle;

use crate::to_js_err;

#[wasm_bindgen]
pub fn fromt_derive_view_key(key_share: &[u8]) -> Result<Vec<u8>, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.view_key.to_vec())
}

#[wasm_bindgen]
pub fn fromt_derive_spend_pub_key(key_share: &[u8]) -> Result<Vec<u8>, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    bundle.verifying_key_bytes().map_err(to_js_err)
}

#[wasm_bindgen]
pub fn fromt_derive_address(key_share: &[u8]) -> Result<String, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let spend_pub = bundle.verifying_key_bytes().map_err(to_js_err)?;
    let mut sp = [0u8; 32];
    sp.copy_from_slice(&spend_pub);
    fromtlib::monero::address::derive_address(&sp, &bundle.view_key, bundle.network)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn fromt_derive_subaddress(
    key_share: &[u8],
    account: u32,
    index: u32,
) -> Result<String, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let spend_pub = bundle.verifying_key_bytes().map_err(to_js_err)?;
    let mut sp = [0u8; 32];
    sp.copy_from_slice(&spend_pub);
    fromtlib::monero::subaddress::derive_subaddress(&sp, &bundle.view_key, account, index, bundle.network)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn fromt_compute_key_image(
    key_offset: &[u8],
    output_key: &[u8],
    spend_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use monero_wallet::ed25519::Point;

    if key_offset.len() != 32 || output_key.len() != 32 || spend_key.len() != 32 {
        return Err(JsValue::from_str("all inputs must be 32 bytes"));
    }

    let mut ko_arr = [0u8; 32];
    ko_arr.copy_from_slice(key_offset);
    let ko_scalar = curve25519_dalek::Scalar::from_canonical_bytes(ko_arr);
    if bool::from(ko_scalar.is_none()) {
        return Err(JsValue::from_str("invalid key offset scalar"));
    }
    let ko_scalar = ko_scalar.unwrap();

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(spend_key);
    let sk_scalar = curve25519_dalek::Scalar::from_canonical_bytes(sk_arr);
    if bool::from(sk_scalar.is_none()) {
        return Err(JsValue::from_str("invalid spend key scalar"));
    }
    let sk_scalar = sk_scalar.unwrap();

    let x = ko_scalar + sk_scalar;

    let mut ok_arr = [0u8; 32];
    ok_arr.copy_from_slice(output_key);
    let hp = Point::biased_hash(ok_arr);
    let hp_dalek: curve25519_dalek::EdwardsPoint = hp.into();
    let ki = x * hp_dalek;

    Ok(ki.compress().to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn fromt_outputs_for_key_image(outputs_data: &[u8]) -> Result<Vec<u8>, JsValue> {
    if outputs_data.len() < 4 {
        return Err(JsValue::from_str("outputs data too short"));
    }
    let count = u32::from_le_bytes(
        outputs_data[0..4]
            .try_into()
            .map_err(|_| JsValue::from_str("bad count"))?,
    ) as usize;
    let expected = 4 + count * 72;
    if outputs_data.len() < expected {
        return Err(JsValue::from_str("outputs data too short for count"));
    }

    let mut buf = Vec::with_capacity(4 + count * 64);
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let src = 4 + i * 72;
        buf.extend_from_slice(&outputs_data[src..src + 64]);
    }
    Ok(buf)
}

#[wasm_bindgen]
pub fn fromt_filter_spent_outputs(
    outputs_data: &[u8],
    spent_flags: &[u8],
) -> Result<Vec<u32>, JsValue> {
    let (balance, num_unspent) =
        fromtlib::monero::spend::filter_spent_outputs(outputs_data, spent_flags)
            .map_err(to_js_err)?;
    let bal_lo = (balance & 0xFFFFFFFF) as u32;
    let bal_hi = (balance >> 32) as u32;
    Ok(vec![bal_lo, bal_hi, num_unspent])
}

#[wasm_bindgen]
pub fn fromt_keyshare_birthday(key_share: &[u8]) -> Result<u64, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.birthday)
}

#[wasm_bindgen]
pub fn fromt_keyshare_network(key_share: &[u8]) -> Result<u8, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.network)
}
