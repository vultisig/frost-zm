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

/// Pedersen commitment `C = mask*G + amount*H` for a wallet output.
/// Use this for the *real* ring member — LWS `rct` leading bytes are
/// not always the on-chain commitment point that `monero-wallet`
/// validates during CLSAG setup.
#[wasm_bindgen]
pub fn fromt_pedersen_commitment(
    commitment_mask: &[u8],
    amount: u64,
) -> Result<Vec<u8>, JsValue> {
    use monero_wallet::ed25519::{Commitment, Scalar as MScalar};

    if commitment_mask.len() != 32 {
        return Err(JsValue::from_str("commitment_mask must be 32 bytes"));
    }
    let mut mask_arr = [0u8; 32];
    mask_arr.copy_from_slice(commitment_mask);
    let mask_scalar = curve25519_dalek::Scalar::from_canonical_bytes(mask_arr);
    if bool::from(mask_scalar.is_none()) {
        return Err(JsValue::from_str("invalid commitment mask scalar"));
    }
    let commitment = Commitment::new(MScalar::from(mask_scalar.unwrap()), amount);
    Ok(commitment.commit().compress().to_bytes().to_vec())
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

    // Monero's `genCommitmentMask` expects the *reduced* scalar form of
    // `derivation_to_scalar(derivation, output_index)` as its input —
    // see `src/crypto/crypto.cpp` in `monero-project/monero`. Earlier
    // revisions of this helper hashed the raw keccak digest, which only
    // matches reference behaviour when the hash already happens to be
    // `< l` (about 7/8 of the time). When it doesn't, the resulting
    // Pedersen commitment differs from the on-chain output, and CLSAG
    // verification fails at broadcast with `verRctCLSAGSimple failed
    // for input N`. Reducing mod l before the second hash keeps us
    // bit-for-bit compatible with monero-wallet-cli and `monero-oxide`.
    let derivation_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(derivation_hash);
    let derivation_scalar_bytes = derivation_scalar.to_bytes();

    let mut mask_buf = Vec::with_capacity(15 + 32);
    mask_buf.extend_from_slice(b"commitment_mask");
    mask_buf.extend_from_slice(&derivation_scalar_bytes);

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
    Ok(bundle.birthday)
}

#[wasm_bindgen]
pub fn fromt_keyshare_network(key_share: &[u8]) -> Result<u8, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.network)
}

/// Number of signing parties in this bundle's FROST group. A return of
/// `1` means the bundle is a true 1-of-1 share — the `signing_share`
/// inside `KeyPackage` IS the full Monero spend secret and the wallet
/// can compute key images locally without any MPC ceremony. Anything
/// `>= 2` means the spend secret is sharded and the proper key-image
/// path is `fromt_key_image_part1` / `_part2`.
#[wasm_bindgen]
pub fn fromt_keyshare_max_signers(key_share: &[u8]) -> Result<u16, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    Ok(bundle.pub_key_package.verifying_shares().len() as u16)
}

/// Extract the 32-byte Monero spend secret from a *single-party*
/// `KeyShareBundle`. Errors if the bundle is threshold (max_signers
/// >= 2); the spend secret can only be reconstructed via an MPC
/// ceremony in that case.
///
/// Used by the receive panel to compute the wallet's real key image
/// for each LWS-reported unspent output so we can filter out outputs
/// that have actually been spent (LWS only returns ring-decoy
/// candidate key images and cannot do this check itself).
#[wasm_bindgen]
pub fn fromt_keyshare_spend_secret_singleparty(
    key_share: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use frost_core::keys::SigningShare;
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let max_signers = bundle.pub_key_package.verifying_shares().len();
    if max_signers != 1 {
        return Err(JsValue::from_str(&format!(
            "spend secret extraction requires a 1-of-1 share (got {max_signers}-party bundle)"
        )));
    }
    let signing_share: &SigningShare<frost_ed25519::Ed25519Sha512> =
        bundle.key_package.signing_share();
    let bytes: Vec<u8> = signing_share.serialize();
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "unexpected signing share length: {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the CLSAG broadcast failure (May 2026).
    ///
    /// The fixture is the live "Jittery" test wallet's first UTXO
    /// (tx `dc6089e…`, output index 1). We feed the same view-secret
    /// and tx pub key the WASM sees in production and assert the
    /// commitment we build is `monerod`'s on-chain `mask` byte-for-byte.
    /// Without the `sc_reduce32(H_s)` fix in
    /// `fromt_derive_commitment_mask` this case produced
    /// `7478c117…`, which CLSAG rejected at broadcast with
    /// `verRctCLSAGSimple failed for input 0`.
    #[test]
    fn commitment_mask_matches_monero_for_real_utxo() {
        let view = hex_to_bytes(
            "5fa6accbc81497385fb1c94139618eeb83b6caacff75b052f1620bc29c4f410c",
        );
        let tx_pub = hex_to_bytes(
            "3b56e8c4248603a462fd27625b14b348ea920f1a97d3e629e7a525de03591b77",
        );
        let mask = fromt_derive_commitment_mask(&view, &tx_pub, 1).expect("mask");
        let commitment = fromt_pedersen_commitment(&mask, 722_980_000u64).expect("commit");
        let expected = hex_to_bytes(
            "d97475b2e3b4f50351826b845343615b591dfdeca18859bdd0ecd6163cc465a4",
        );
        assert_eq!(
            commitment, expected,
            "commitment derivation drifted from monerod's on-chain mask",
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
