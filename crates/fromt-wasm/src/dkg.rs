use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

use frost_core::{
    Field, Group, Identifier, VerifyingKey,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
};
use frost_ed25519::Ed25519Sha512;

use fromtlib::ceremony::key_import;

use crate::to_js_err;

type E = Ed25519Sha512;
type Ident = Identifier<E>;
type G = <E as frost_core::Ciphersuite>::Group;
type F = <G as Group>::Field;
type Scalar = frost_core::Scalar<E>;

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

/// Build a 1-of-1 Monero FROST `KeyShareBundle` directly from a 32-byte
/// seed. Returns the same binary layout that the multi-party DKG emits
/// (`KeyShareBundle::serialize`) so `MoneroAccount` and every other
/// downstream consumer treat phrase-derived shares identically to FROST
/// shares.
///
/// Uses the same `derive_keys_from_seed` primitive that the key-import
/// ceremony uses, so a phrase-only wallet and a FROST-imported vault
/// (with the matching seed) land on the same Monero address.
#[wasm_bindgen]
pub fn fromt_singleparty_bundle_from_seed(
    seed: &[u8],
    network: u8,
    birthday: u64,
) -> Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("seed must be 32 bytes"));
    }
    let arr: &[u8; 32] = seed.try_into().map_err(to_js_err)?;

    let (sk_bytes, vk_bytes) = key_import::derive_keys_from_seed(arr).map_err(to_js_err)?;

    let sk_scalar: Scalar = F::deserialize(&sk_bytes)
        .map_err(|_| JsValue::from_str("could not deserialize derived spend key"))?;

    let spend_point = <G as Group>::generator() * sk_scalar;
    let signing_share = SigningShare::<E>::new(sk_scalar);
    let verifying_share = VerifyingShare::<E>::new(spend_point);
    let verifying_key = VerifyingKey::<E>::new(spend_point);

    let identifier = Ident::try_from(1u16)
        .map_err(|_| JsValue::from_str("could not construct identifier=1"))?;

    let key_package = KeyPackage::<E>::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        1,
    );

    let mut verifying_shares: BTreeMap<Ident, VerifyingShare<E>> = BTreeMap::new();
    verifying_shares.insert(identifier, verifying_share);
    let pub_key_package = PublicKeyPackage::<E>::new(verifying_shares, verifying_key);

    let bundle = fromtlib::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        vk_bytes,
        network,
        birthday,
    );

    bundle.serialize().map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}
