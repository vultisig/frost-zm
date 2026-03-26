use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Field, Group, Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use frost_secp256k1::Secp256K1Sha256;
use wasm_bindgen::prelude::*;

use frost_session::{
    message,
    relay::FrostChannel,
    session::{Ceremony, Protocol},
    setup::{KeyImportSetup, PartyEntry, SetupMsg, SignSetup, ReshareSetup},
};

type E = Secp256K1Sha256;
type Ident = Identifier<E>;
type Scalar = frost_core::Scalar<E>;
type F = <<E as Ciphersuite>::Group as Group>::Field;

const CC_LEN: usize = 32;

fn to_js_err<Err: std::fmt::Debug>(e: Err) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

fn js_obj() -> js_sys::Object {
    js_sys::Object::new()
}

fn set_bytes(obj: &js_sys::Object, key: &str, data: &[u8]) {
    let arr = js_sys::Uint8Array::from(data);
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &arr).unwrap();
}

fn dkg_ser_err<Err: std::fmt::Debug>(e: Err) -> frobtlib::errors::lib_error {
    let _ = e;
    frobtlib::errors::lib_error::LIB_SERIALIZATION_ERROR
}

// === Handle ===

#[wasm_bindgen]
pub fn frobt_handle_free(handle_id: i32) -> Result<(), JsValue> {
    use frobtlib::handle::Handle;
    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    Handle::free(handle).map_err(to_js_err)
}

// === DKG (round-based) ===

#[wasm_bindgen]
pub fn frobt_dkg_part1(id: u16, max_signers: u16, min_signers: u16) -> Result<JsValue, JsValue> {
    let (secret, pkg_bytes) = frobtlib::ceremony::dkg::dkg_part1(id, max_signers, min_signers)
        .map_err(to_js_err)?;

    let handle = frobtlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_dkg_part2(handle_id: i32, r1_packages: &[u8]) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let secret: frobtlib::ceremony::dkg::DkgRound1Secret =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    let (secret2, r2_bytes) = frobtlib::ceremony::dkg::dkg_part2(secret, r1_packages)
        .map_err(to_js_err)?;

    let handle2 = frobtlib::handle::Handle::allocate(secret2).map_err(to_js_err)?;
    let handle_id2: i32 = unsafe { std::mem::transmute(handle2) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id2)).unwrap();
    set_bytes(&obj, "package", &r2_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_dkg_part3(
    handle_id: i32,
    r1_packages: &[u8],
    r2_packages: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let secret: frobtlib::ceremony::dkg::DkgRound2Secret =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    let (bundle_bytes, pub_key) =
        frobtlib::ceremony::dkg::dkg_part3(secret, r1_packages, r2_packages, network, birthday)
            .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "publicKey", &pub_key);
    Ok(obj.into())
}

// === Key Import (round-based) ===

#[wasm_bindgen]
pub fn frobt_derive_from_seed(seed: &[u8], account_index: u32) -> Result<JsValue, JsValue> {
    let (sk, cc, pub_key) = frobtlib::ceremony::key_import::derive_from_seed(seed, account_index)
        .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "privateKey", &sk);
    set_bytes(&obj, "chainCode", &cc);
    set_bytes(&obj, "publicKey", &pub_key);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_key_import_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    private_key: &[u8],
    chain_code: &[u8],
) -> Result<JsValue, JsValue> {
    let sk_opt: Option<&[u8; 32]> = if private_key.is_empty() {
        None
    } else {
        Some(private_key.try_into().map_err(to_js_err)?)
    };

    let cc_opt: Option<&[u8; 32]> = if chain_code.is_empty() {
        None
    } else {
        Some(chain_code.try_into().map_err(to_js_err)?)
    };

    let (secret, pkg_bytes) =
        frobtlib::ceremony::key_import::key_import_part1(id, max_signers, min_signers, sk_opt, cc_opt)
            .map_err(to_js_err)?;

    let handle = frobtlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_key_import_part3(
    handle_id: i32,
    r1_packages: &[u8],
    r2_packages: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let secret: frobtlib::ceremony::dkg::DkgRound2Secret =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    let (bundle_bytes, pub_key) =
        frobtlib::ceremony::key_import::key_import_part3(
            secret, r1_packages, r2_packages, expected_vk, network, birthday,
        )
        .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "publicKey", &pub_key);
    Ok(obj.into())
}

// === Signing ===

#[wasm_bindgen]
pub fn frobt_sign_commit(key_share: &[u8]) -> Result<JsValue, JsValue> {
    let (nonces, commitments_bytes) = frobtlib::ceremony::sign::sign_commit(key_share)
        .map_err(to_js_err)?;

    let handle = frobtlib::handle::Handle::allocate(nonces).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "commitments", &commitments_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_sign_create_package(message: &[u8], commitments_map: &[u8]) -> Result<Vec<u8>, JsValue> {
    frobtlib::ceremony::sign::sign_create_package(message, commitments_map)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_sign(
    signing_package: &[u8],
    handle_id: i32,
    key_share: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let nonces: frobtlib::ceremony::sign::SignNonces =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    frobtlib::ceremony::sign::sign(signing_package, nonces, key_share)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_sign_aggregate(
    signing_package: &[u8],
    shares_map: &[u8],
    key_share: &[u8],
) -> Result<Vec<u8>, JsValue> {
    frobtlib::ceremony::sign::sign_aggregate(signing_package, shares_map, key_share)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_verify_signature(
    message: &[u8],
    signature: &[u8],
    key_share: &[u8],
) -> Result<(), JsValue> {
    frobtlib::ceremony::sign::verify_signature(message, signature, key_share)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_sign_taproot(
    signing_package: &[u8],
    handle_id: i32,
    key_share: &[u8],
    merkle_root: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let nonces: frobtlib::ceremony::sign::SignNonces =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    let mr = if merkle_root.is_empty() { None } else { Some(merkle_root) };

    frobtlib::ceremony::sign::sign_taproot(signing_package, nonces, key_share, mr)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_sign_aggregate_taproot(
    signing_package: &[u8],
    shares_map: &[u8],
    key_share: &[u8],
    merkle_root: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mr = if merkle_root.is_empty() { None } else { Some(merkle_root) };

    frobtlib::ceremony::sign::sign_aggregate_taproot(signing_package, shares_map, key_share, mr)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_verify_taproot_signature(
    message: &[u8],
    signature: &[u8],
    key_share: &[u8],
    merkle_root: &[u8],
) -> Result<(), JsValue> {
    let mr = if merkle_root.is_empty() { None } else { Some(merkle_root) };

    frobtlib::ceremony::sign::verify_taproot_signature(message, signature, key_share, mr)
        .map_err(to_js_err)
}

// === Reshare (round-based) ===

#[wasm_bindgen]
pub fn frobt_reshare_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_share: &[u8],
    old_ids: &[u8],
) -> Result<JsValue, JsValue> {
    let oks = if old_key_share.is_empty() { None } else { Some(old_key_share) };
    let oid = if old_ids.is_empty() { None } else { Some(old_ids) };

    let (secret, pkg_bytes) =
        frobtlib::ceremony::reshare::reshare_part1(id, max_signers, min_signers, oks, oid)
            .map_err(to_js_err)?;

    let handle = frobtlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frobt_reshare_part3(
    handle_id: i32,
    r1_packages: &[u8],
    r2_packages: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frobtlib::handle::Handle>(handle_id) };
    let secret: frobtlib::ceremony::dkg::DkgRound2Secret =
        frobtlib::handle::Handle::take(handle).map_err(to_js_err)?;

    let (bundle_bytes, pub_key) =
        frobtlib::ceremony::reshare::reshare_part3(
            secret, r1_packages, r2_packages, expected_vk, network, birthday,
        )
        .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "publicKey", &pub_key);
    Ok(obj.into())
}

// === CKD ===

#[wasm_bindgen]
pub fn frobt_ckd_derive(key_share: &[u8], change: u32, index: u32) -> Result<Vec<u8>, JsValue> {
    frobtlib::ceremony::ckd::ckd_derive(key_share, change, index)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_derive_child_pubkey(key_share: &[u8], change: u32, index: u32) -> Result<Vec<u8>, JsValue> {
    frobtlib::ceremony::ckd::derive_child_pubkey(key_share, change, index)
        .map_err(to_js_err)
}

// === Bitcoin Address ===

#[wasm_bindgen]
pub fn frobt_derive_p2tr_address(x_only_pubkey: &[u8], network: u8) -> Result<String, JsValue> {
    frobtlib::bitcoin::address::derive_p2tr_address(x_only_pubkey, network)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_derive_address_from_bundle(key_share: &[u8], change: u32, index: u32) -> Result<String, JsValue> {
    frobtlib::bitcoin::address::derive_address_from_bundle(key_share, change, index)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_derive_root_address(key_share: &[u8]) -> Result<String, JsValue> {
    frobtlib::bitcoin::address::derive_root_address(key_share)
        .map_err(to_js_err)
}

// === Taproot ===

#[wasm_bindgen]
pub fn frobt_compute_taproot_output_key(vk_bytes: &[u8], merkle_root: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mr = if merkle_root.is_empty() { None } else { Some(merkle_root) };
    frobtlib::taproot::compute_taproot_output_key(vk_bytes, mr)
        .map_err(to_js_err)
}

// === Keyshare Inspection ===

#[wasm_bindgen]
pub fn frobt_keyshare_public_key(key_share: &[u8]) -> Result<Vec<u8>, JsValue> {
    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::deserialize(key_share)
        .map_err(to_js_err)?;
    bundle.verifying_key_bytes().map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frobt_keyshare_chain_code(key_share: &[u8]) -> Result<Vec<u8>, JsValue> {
    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::deserialize(key_share)
        .map_err(to_js_err)?;
    Ok(bundle.chain_code.to_vec())
}

#[wasm_bindgen]
pub fn frobt_keyshare_birthday(key_share: &[u8]) -> Result<u64, JsValue> {
    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::deserialize(key_share)
        .map_err(to_js_err)?;
    Ok(bundle.birthday)
}

#[wasm_bindgen]
pub fn frobt_keyshare_network(key_share: &[u8]) -> Result<u8, JsValue> {
    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::deserialize(key_share)
        .map_err(to_js_err)?;
    Ok(bundle.network)
}

// === Session-based Ceremonies ===

async fn frobt_dkg_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, frobtlib::errors::lib_error> {
    use frobtlib::errors::lib_error;

    let id_map = frost_ceremony::session_dkg::build_id_map::<E>(max_signers)?;
    let ident = Ident::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (secret1, r1_combined, cc_share_bytes) = {
        let mut rng = rand::thread_rng();
        let (secret, package) =
            dkg::part1::<E, _>(ident, max_signers, min_signers, &mut rng)
                .map_err(|_| lib_error::LIB_DKG_ERROR)?;
        let mut bytes = package.serialize().map_err(dkg_ser_err)?;

        let cc_share: Scalar = F::random(&mut rng);
        let cc_bytes: [u8; CC_LEN] = {
            let s = F::serialize(&cc_share);
            let sl: &[u8] = s.as_ref();
            sl.try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
        };

        bytes.extend_from_slice(&cc_bytes);
        (secret, bytes, cc_bytes)
    };

    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < CC_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - CC_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; CC_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<E>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        cc_shares_map.insert(sender, cc_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<E>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<E>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let chain_code = aggregate_cc_shares(&cc_share_bytes, &cc_shares_map)?;

    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    bundle.serialize()
}

fn aggregate_cc_shares(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Ident, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], frobtlib::errors::lib_error> {
    let own_arr: &[u8; 32] = own_share;
    let mut sum: Scalar = F::deserialize(own_arr).map_err(dkg_ser_err)?;

    for (_, share_bytes) in other_shares {
        let s: Scalar = F::deserialize(share_bytes).map_err(dkg_ser_err)?;
        sum = sum + s;
    }

    let result_serialized = F::serialize(&sum);
    let sl: &[u8] = result_serialized.as_ref();
    let result: [u8; 32] = sl
        .try_into()
        .map_err(|_| frobtlib::errors::lib_error::LIB_SERIALIZATION_ERROR)?;
    Ok(result)
}

// === Key Import Session ===

async fn frobt_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    spend_key: Vec<u8>,
    chain_code_input: Vec<u8>,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, frobtlib::errors::lib_error> {
    use frobtlib::errors::lib_error;

    let is_seed_holder = my_id == seed_holder_id;
    let id_map = frost_ceremony::session_dkg::build_id_map::<E>(max_signers)?;
    let _ident = Ident::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (constant_term, cc_share_bytes) = if is_seed_holder {
        let sk_bytes: &[u8; 32] = spend_key.as_slice().try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
        let sk_scalar: Scalar = F::deserialize(sk_bytes).map_err(dkg_ser_err)?;
        let ct = frost_ceremony::key_import::derive_constant_term::<E>(sk_scalar, max_signers);

        let cc: [u8; CC_LEN] = if chain_code_input.len() == 32 {
            chain_code_input.as_slice().try_into()
                .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
        } else {
            [0u8; CC_LEN]
        };

        (ct, cc)
    } else {
        (F::one(), [0u8; CC_LEN])
    };

    let (secret1, r1_frost_bytes) =
        frost_ceremony::key_import::key_import_part1::<E>(my_id, max_signers, min_signers, constant_term)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&cc_share_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < CC_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - CC_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; CC_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<E>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        cc_shares_map.insert(sender, cc_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<E>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<E>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    if is_seed_holder {
        let expected_vk: Vec<u8> = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
        ch.broadcast(expected_vk).await;
    } else {
        let (_sender, expected_vk) = ch.recv().await;
        let actual_vk: Vec<u8> = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
        if actual_vk != expected_vk {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    let chain_code = aggregate_import_cc(&cc_share_bytes, &cc_shares_map)?;

    let bundle = frobtlib::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    bundle.serialize()
}

fn aggregate_import_cc(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Ident, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], frobtlib::errors::lib_error> {
    let zero = [0u8; CC_LEN];
    if *own_share != zero {
        return Ok(*own_share);
    }
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    Err(frobtlib::errors::lib_error::LIB_KEY_IMPORT_ERROR)
}

// === FrobtKeyImportSession ===

#[wasm_bindgen]
pub struct FrobtKeyImportSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, frobtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FrobtKeyImportSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        spend_key: &[u8],
        chain_code: &[u8],
        network: u8,
        birthday: u64,
    ) -> Result<FrobtKeyImportSession, JsValue> {
        let ki_setup = KeyImportSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = ki_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let seed_holder_id = ki_setup.seed_holder_id;
        let spend_key_owned = spend_key.to_vec();
        let chain_code_owned = chain_code.to_vec();

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_key_import_run(
                    my_id, max, min, seed_holder_id, spend_key_owned,
                    chain_code_owned, network, birthday, &ch,
                ).await
            }));

        Ok(FrobtKeyImportSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === FrobtDkgSession ===

#[wasm_bindgen]
pub struct FrobtDkgSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, frobtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FrobtDkgSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(setup_bytes: &[u8], my_party_name: &str, network: u8, birthday: u64) -> Result<FrobtDkgSession, JsValue> {
        let (setup, _) = SetupMsg::decode(setup_bytes).map_err(to_js_err)?;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_dkg_run(my_id, max, min, network, birthday, &ch).await
            }));

        Ok(FrobtDkgSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === FrobtSignSession ===

#[wasm_bindgen]
pub struct FrobtSignSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, frobtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FrobtSignSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        key_package: &[u8],
        pub_key_package: &[u8],
    ) -> Result<FrobtSignSession, JsValue> {
        let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let kp = KeyPackage::<E>::deserialize(key_package).map_err(to_js_err)?;
        let pkp = PublicKeyPackage::<E>::deserialize(pub_key_package).map_err(to_js_err)?;

        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_sign::sign_run::<E>(
                    &kp, &pkp, &msg_to_sign, num_signers, &ch,
                ).await
            }));

        Ok(FrobtSignSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let sig = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(sig.as_slice()))
    }
}

// === FrobtReshareSession ===

#[wasm_bindgen]
pub struct FrobtReshareSession {
    protocol: Box<dyn Ceremony<Result<(KeyPackage<E>, PublicKeyPackage<E>), frobtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FrobtReshareSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        old_key_package: &[u8],
    ) -> Result<FrobtReshareSession, JsValue> {
        let reshare_setup = ReshareSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let old_kp = KeyPackage::<E>::deserialize(old_key_package).map_err(to_js_err)?;

        let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
            .map(|&id| Ident::try_from(id).map_err(to_js_err))
            .collect::<Result<_, _>>()?;

        let additive_share = frost_ceremony::reshare::compute_additive_share::<E>(
            &old_kp, &old_ids, setup.max_signers,
        ).map_err(to_js_err)?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;

        let protocol: Box<dyn Ceremony<Result<(KeyPackage<E>, PublicKeyPackage<E>), _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_reshare::reshare_run::<E>(
                    my_id, max, min, additive_share, &expected_vk, &ch,
                ).await
            }));

        Ok(FrobtReshareSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<JsValue, JsValue> {
        let (kp, pkp) = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;

        let kp_bytes = kp.serialize().map_err(to_js_err)?;
        let pkp_bytes = pkp.serialize().map_err(to_js_err)?;

        let obj = js_obj();
        set_bytes(&obj, "keyPackage", &kp_bytes);
        set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
        Ok(obj.into())
    }
}

// === Setup Message Helpers ===

fn decode_parties_wasm(data: &[u8]) -> Result<Vec<PartyEntry>, JsError> {
    if data.len() < 2 {
        return Err(JsError::new("parties data too short"));
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut parties = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return Err(JsError::new("parties data truncated"));
        }
        let frost_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + name_len > data.len() {
            return Err(JsError::new("party name truncated"));
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        parties.push(PartyEntry { frost_id, name });
    }
    Ok(parties)
}

fn decode_u16_list_wasm(data: &[u8]) -> Result<Vec<u16>, JsError> {
    if data.len() < 2 {
        return Err(JsError::new("u16 list data too short"));
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(JsError::new("u16 list truncated"));
        }
        list.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    Ok(list)
}

// === Setup Message Creators ===

#[wasm_bindgen(js_name = "frobtDkgSetupMsgNew")]
pub fn dkg_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    network: u8,
    birthday: u64,
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let setup = SetupMsg { max_signers, min_signers, parties };
    let mut buf = setup.encode();
    buf.push(network);
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}

#[wasm_bindgen(js_name = "frobtSignSetupMsgNew")]
pub fn sign_setup_msg_new(
    msg_to_sign: &[u8],
    parties_data: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let num = parties.len() as u16;
    let setup = SignSetup {
        base: SetupMsg { max_signers: num, min_signers: num, parties },
        message: msg_to_sign.to_vec(),
    };
    Ok(js_sys::Uint8Array::from(setup.encode().as_slice()))
}

#[wasm_bindgen(js_name = "frobtReshareSetupMsgNew")]
pub fn reshare_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    old_identifiers_data: &[u8],
    expected_vk: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let old_identifiers = decode_u16_list_wasm(old_identifiers_data)?;
    let setup = ReshareSetup {
        base: SetupMsg { max_signers, min_signers, parties },
        old_identifiers,
        expected_vk: expected_vk.to_vec(),
    };
    Ok(js_sys::Uint8Array::from(setup.encode().as_slice()))
}

#[wasm_bindgen(js_name = "frobtKeyImportSetupMsgNew")]
pub fn key_import_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    network: u8,
    birthday: u64,
    seed_holder_id: u16,
    seed: &[u8],
    account_index: u32,
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let setup = KeyImportSetup {
        base: SetupMsg { max_signers, min_signers, parties },
        seed_holder_id,
        secret_data: seed.to_vec(),
        account_index,
    };
    let mut buf = setup.encode();
    buf.push(network);
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}

// === Codec / Identifier Utilities ===

#[wasm_bindgen]
pub fn frobt_encode_identifier(id: u16) -> Result<Vec<u8>, JsError> {
    let ident = Ident::try_from(id).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(ident.serialize())
}

#[wasm_bindgen]
pub fn frobt_decode_identifier(id_bytes: &[u8]) -> Result<u16, JsError> {
    let ident = Ident::deserialize(id_bytes).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let serialized = ident.serialize();
    if serialized.len() < 2 {
        return Err(JsError::new("identifier too short"));
    }
    Ok(u16::from_le_bytes([serialized[0], serialized[1]]))
}

#[wasm_bindgen]
pub fn frobt_compute_sighash(
    raw_tx: &[u8],
    prevouts: &[u8],
    input_index: u32,
    sighash_type: u8,
) -> Result<Vec<u8>, JsValue> {
    let hash = frobtlib::bitcoin::sighash::compute_taproot_sighash(
        raw_tx, prevouts, input_index, sighash_type,
    )
    .map_err(to_js_err)?;
    Ok(hash.to_vec())
}

#[wasm_bindgen]
pub fn frobt_attach_witness(
    raw_tx: &[u8],
    input_index: u32,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    frobtlib::bitcoin::witness::attach_taproot_witness(raw_tx, input_index, signature)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn wasm_encode_map(entries: JsValue) -> Result<Vec<u8>, JsValue> {
    let arr = js_sys::Array::from(&entries);
    let len = arr.length();
    let mut buf = Vec::new();
    buf.extend_from_slice(&len.to_le_bytes());
    for i in 0..len {
        let entry = arr.get(i);
        let id_val = js_sys::Reflect::get(&entry, &"id".into())?;
        let value = js_sys::Reflect::get(&entry, &"value".into())?;
        let id_u16 = id_val.as_f64()
            .ok_or_else(|| JsValue::from_str("id must be a number"))? as u16;
        let ident = Ident::try_from(id_u16)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        let id_bytes = ident.serialize();
        let val_bytes = js_sys::Uint8Array::from(value).to_vec();
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&val_bytes);
    }
    Ok(buf)
}
