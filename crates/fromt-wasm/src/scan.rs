use wasm_bindgen::prelude::*;

use fromtlib::keyshare::bundle::KeyShareBundle;

use crate::to_js_err;

#[wasm_bindgen]
pub fn fromt_derive_view_key(key_share: &[u8]) -> Result<Vec<u8>, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.metadata.view_key.to_vec())
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
    fromtlib::monero::address::derive_address(&sp, &bundle.metadata.view_key, bundle.metadata.network)
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
    fromtlib::monero::subaddress::derive_subaddress(&sp, &bundle.metadata.view_key, account, index, bundle.metadata.network)
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
pub fn fromt_derive_key_offset(
    view_secret_key: &[u8],
    tx_pub_key: &[u8],
    output_index: u64,
) -> Result<Vec<u8>, JsValue> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use tiny_keccak::{Hasher, Keccak};

    if view_secret_key.len() != 32 || tx_pub_key.len() != 32 {
        return Err(JsValue::from_str("inputs must be 32 bytes"));
    }

    let mut a_arr = [0u8; 32];
    a_arr.copy_from_slice(view_secret_key);
    let a = curve25519_dalek::Scalar::from_canonical_bytes(a_arr);
    if bool::from(a.is_none()) {
        return Err(JsValue::from_str("invalid view key scalar"));
    }
    let a = a.unwrap();

    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(tx_pub_key);
    let r_point = CompressedEdwardsY(r_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("invalid tx pub key point"))?;

    let shared = (a * r_point).mul_by_cofactor();
    let derivation = shared.compress().to_bytes();

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&derivation);
    let mut idx = output_index;
    loop {
        let byte = (idx & 0x7F) as u8;
        idx >>= 7;
        if idx == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }

    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(hash);
    Ok(scalar.to_bytes().to_vec())
}

/// Check if an output belongs to us. Returns key_offset (32 bytes) if yes, empty vec if no.
#[wasm_bindgen]
pub fn fromt_check_output(
    view_secret_key: &[u8],
    spend_pub_key: &[u8],
    tx_pub_key: &[u8],
    output_index: u64,
    output_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use tiny_keccak::{Hasher, Keccak};

    if view_secret_key.len() != 32 || spend_pub_key.len() != 32
        || tx_pub_key.len() != 32 || output_key.len() != 32
    {
        return Err(JsValue::from_str("all inputs must be 32 bytes"));
    }

    let mut a_arr = [0u8; 32];
    a_arr.copy_from_slice(view_secret_key);
    let a = curve25519_dalek::Scalar::from_canonical_bytes(a_arr);
    if bool::from(a.is_none()) {
        return Err(JsValue::from_str("invalid view key scalar"));
    }
    let a = a.unwrap();

    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(tx_pub_key);
    let r_point = CompressedEdwardsY(r_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("invalid tx pub key point"))?;

    let shared = (a * r_point).mul_by_cofactor();
    let derivation = shared.compress().to_bytes();

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&derivation);
    let mut idx = output_index;
    loop {
        let byte = (idx & 0x7F) as u8;
        idx >>= 7;
        if idx == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }

    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let key_offset = curve25519_dalek::Scalar::from_bytes_mod_order(hash);

    // P = key_offset * G + B
    let mut b_arr = [0u8; 32];
    b_arr.copy_from_slice(spend_pub_key);
    let b_point = CompressedEdwardsY(b_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("invalid spend pub key point"))?;

    let expected = ED25519_BASEPOINT_TABLE * &key_offset + b_point;
    let expected_bytes = expected.compress().to_bytes();

    if expected_bytes == <[u8; 32]>::try_from(output_key).unwrap() {
        Ok(key_offset.to_bytes().to_vec())
    } else {
        Ok(vec![])
    }
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
pub fn fromt_derive_commitment_mask(
    view_secret_key: &[u8],
    tx_pub_key: &[u8],
    output_index: u64,
) -> Result<Vec<u8>, JsValue> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use tiny_keccak::{Hasher, Keccak};

    if view_secret_key.len() != 32 || tx_pub_key.len() != 32 {
        return Err(JsValue::from_str("inputs must be 32 bytes"));
    }

    let mut a_arr = [0u8; 32];
    a_arr.copy_from_slice(view_secret_key);
    let a = curve25519_dalek::Scalar::from_canonical_bytes(a_arr);
    if bool::from(a.is_none()) {
        return Err(JsValue::from_str("invalid view key scalar"));
    }
    let a = a.unwrap();

    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(tx_pub_key);
    let r_point = CompressedEdwardsY(r_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("invalid tx pub key point"))?;

    let shared = (a * r_point).mul_by_cofactor();
    let derivation = shared.compress().to_bytes();

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&derivation);
    let mut idx = output_index;
    loop {
        let byte = (idx & 0x7F) as u8;
        idx >>= 7;
        if idx == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }

    let mut derivation_hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    keccak.finalize(&mut derivation_hash);

    let mut mask_buf = Vec::with_capacity(48);
    mask_buf.extend_from_slice(b"commitment_mask");
    mask_buf.extend_from_slice(&derivation_hash);

    let mut mask_hash = [0u8; 32];
    let mut keccak2 = Keccak::v256();
    keccak2.update(&mask_buf);
    keccak2.finalize(&mut mask_hash);

    let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(mask_hash);
    Ok(scalar.to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn fromt_keyshare_birthday(key_share: &[u8]) -> Result<u64, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.metadata.birthday)
}

#[wasm_bindgen]
pub fn fromt_keyshare_network(key_share: &[u8]) -> Result<u8, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.metadata.network)
}
