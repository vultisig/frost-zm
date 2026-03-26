pub mod session;

use wasm_bindgen::prelude::*;

pub(crate) type S = frost_secp256k1::Secp256K1Sha256;
#[allow(dead_code)]
pub(crate) type Identifier = frost_core::Identifier<S>;

pub(crate) fn to_js_err<E: std::fmt::Debug>(e: E) -> wasm_bindgen::JsError {
    wasm_bindgen::JsError::new(&format!("{:?}", e))
}

pub(crate) fn js_obj() -> js_sys::Object {
    js_sys::Object::new()
}

pub(crate) fn set_bytes(obj: &js_sys::Object, key: &str, data: &[u8]) {
    let arr = js_sys::Uint8Array::from(data);
    js_sys::Reflect::set(obj, &wasm_bindgen::JsValue::from_str(key), &arr).unwrap();
}

#[wasm_bindgen]
pub fn froeth_handle_free(handle_id: i32) -> Result<(), JsError> {
    use froethlib::handle::Handle;
    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    Handle::free(handle).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_pack(
    key_package: &[u8],
    pub_key_package: &[u8],
    chain_code: &[u8],
    network: u8,
    birthday: u64,
) -> Result<js_sys::Uint8Array, JsError> {
    if chain_code.len() != 32 {
        return Err(JsError::new("chain_code must be 32 bytes"));
    }
    let cc: [u8; 32] = chain_code.try_into().unwrap();

    let kp = frost_core::keys::KeyPackage::<S>::deserialize(key_package).map_err(to_js_err)?;
    let pkp = frost_core::keys::PublicKeyPackage::<S>::deserialize(pub_key_package)
        .map_err(to_js_err)?;

    let bundle = froethlib::keyshare::bundle::KeyShareBundle::new(kp, pkp, cc, network, birthday);
    let bytes = bundle.serialize().map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_unpack(bundle: &[u8]) -> Result<JsValue, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;

    let kp_bytes = b.key_package.serialize().map_err(to_js_err)?;
    let pkp_bytes = b.pub_key_package.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "keyPackage", &kp_bytes);
    set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
    set_bytes(&obj, "chainCode", &b.chain_code);
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("network"),
        &JsValue::from(b.network),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("birthday"),
        &JsValue::from(b.birthday as f64),
    )
    .unwrap();
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_pub_key_package(bundle: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    let pkp_bytes = b.pub_key_package.serialize().map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(pkp_bytes.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_key_package(bundle: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    let kp_bytes = b.key_package.serialize().map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(kp_bytes.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_chain_code(bundle: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(b.chain_code.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_network(bundle: &[u8]) -> Result<u8, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    Ok(b.network)
}

#[wasm_bindgen]
pub fn froeth_keyshare_bundle_birthday(bundle: &[u8]) -> Result<u64, JsError> {
    let b = froethlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    Ok(b.birthday)
}

#[wasm_bindgen]
pub fn froeth_eth_address(verifying_key: &[u8]) -> Result<String, JsError> {
    froethlib::ethereum::address::eth_address_hex(verifying_key).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn froeth_derive_root_address(bundle: &[u8]) -> Result<String, JsError> {
    froethlib::ethereum::address::derive_root_address(bundle).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn froeth_derive_address(
    bundle: &[u8],
    change: u32,
    index: u32,
) -> Result<String, JsError> {
    froethlib::ethereum::address::derive_address_from_bundle(bundle, change, index)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn froeth_derive_child_pubkey(
    bundle: &[u8],
    change: u32,
    index: u32,
) -> Result<js_sys::Uint8Array, JsError> {
    let pubkey = froethlib::ceremony::ckd::derive_child_pubkey(bundle, change, index)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(pubkey.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_derive_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Result<JsValue, JsError> {
    let (private_key, chain_code, public_key) =
        froethlib::ceremony::key_import::derive_from_seed(seed, account_index)
            .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "privateKey", &private_key);
    set_bytes(&obj, "chainCode", &chain_code);
    set_bytes(&obj, "publicKey", &public_key);
    Ok(obj.into())
}

// === CKD ===

#[wasm_bindgen]
pub fn froeth_ckd_derive(
    bundle: &[u8],
    change: u32,
    index: u32,
) -> Result<js_sys::Uint8Array, JsError> {
    let child = froethlib::ceremony::ckd::ckd_derive(bundle, change, index)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(child.as_slice()))
}

// === Verify ===

#[wasm_bindgen]
pub fn froeth_verify_signature(
    message: &[u8],
    signature: &[u8],
    bundle: &[u8],
) -> Result<(), JsError> {
    froethlib::ceremony::sign::verify_signature(message, signature, bundle)
        .map_err(to_js_err)
}

// === Raw ceremony parts (non-session) ===

#[wasm_bindgen]
pub fn froeth_dkg_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
) -> Result<JsValue, JsError> {
    let (secret, pkg_bytes) =
        froethlib::ceremony::dkg::dkg_part1(identifier, max_signers, min_signers)
            .map_err(to_js_err)?;
    let handle = froethlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let obj = js_obj();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secretHandle"),
        &JsValue::from(unsafe { std::mem::transmute::<froethlib::handle::Handle, i32>(handle) }),
    ).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_dkg_part2(
    secret_handle: i32,
    round1_packages: &[u8],
) -> Result<JsValue, JsError> {
    let handle = unsafe { std::mem::transmute::<i32, froethlib::handle::Handle>(secret_handle) };
    let secret = handle.take::<froethlib::ceremony::dkg::DkgRound1Secret>()
        .map_err(to_js_err)?;
    let (secret2, r2_bytes) =
        froethlib::ceremony::dkg::dkg_part2(secret, round1_packages)
            .map_err(to_js_err)?;
    let handle2 = froethlib::handle::Handle::allocate(secret2).map_err(to_js_err)?;
    let obj = js_obj();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secretHandle"),
        &JsValue::from(unsafe { std::mem::transmute::<froethlib::handle::Handle, i32>(handle2) }),
    ).unwrap();
    set_bytes(&obj, "packages", &r2_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_dkg_part3(
    secret_handle: i32,
    round1_packages: &[u8],
    round2_packages: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsError> {
    let handle = unsafe { std::mem::transmute::<i32, froethlib::handle::Handle>(secret_handle) };
    let secret = handle.take::<froethlib::ceremony::dkg::DkgRound2Secret>()
        .map_err(to_js_err)?;
    let (bundle_bytes, pub_key_bytes) =
        froethlib::ceremony::dkg::dkg_part3(secret, round1_packages, round2_packages, network, birthday)
            .map_err(to_js_err)?;
    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "pubKey", &pub_key_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_sign_commit(bundle: &[u8]) -> Result<JsValue, JsError> {
    let (nonces, commitments_bytes) =
        froethlib::ceremony::sign::sign_commit(bundle).map_err(to_js_err)?;
    let handle = froethlib::handle::Handle::allocate(nonces).map_err(to_js_err)?;
    let obj = js_obj();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("noncesHandle"),
        &JsValue::from(unsafe { std::mem::transmute::<froethlib::handle::Handle, i32>(handle) }),
    ).unwrap();
    set_bytes(&obj, "commitments", &commitments_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_sign_create_package(
    message: &[u8],
    commitments_map: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let pkg = froethlib::ceremony::sign::sign_create_package(message, commitments_map)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(pkg.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_sign(
    signing_package: &[u8],
    nonces_handle: i32,
    bundle: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let handle = unsafe { std::mem::transmute::<i32, froethlib::handle::Handle>(nonces_handle) };
    let nonces = handle.take::<froethlib::ceremony::sign::SignNonces>()
        .map_err(to_js_err)?;
    let share = froethlib::ceremony::sign::sign(signing_package, nonces, bundle)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(share.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_sign_aggregate(
    signing_package: &[u8],
    shares_map: &[u8],
    bundle: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let sig = froethlib::ceremony::sign::sign_aggregate(signing_package, shares_map, bundle)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(sig.as_slice()))
}

#[wasm_bindgen]
pub fn froeth_reshare_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_share: Option<Vec<u8>>,
    old_identifiers: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let old_ks = old_key_share.as_deref();
    let old_ids = old_identifiers.as_deref();
    let (secret, pkg_bytes) =
        froethlib::ceremony::reshare::reshare_part1(identifier, max_signers, min_signers, old_ks, old_ids)
            .map_err(to_js_err)?;
    let handle = froethlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let obj = js_obj();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secretHandle"),
        &JsValue::from(unsafe { std::mem::transmute::<froethlib::handle::Handle, i32>(handle) }),
    ).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_reshare_part3(
    secret_handle: i32,
    round1_packages: &[u8],
    round2_packages: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsError> {
    let handle = unsafe { std::mem::transmute::<i32, froethlib::handle::Handle>(secret_handle) };
    let secret = handle.take::<froethlib::ceremony::dkg::DkgRound2Secret>()
        .map_err(to_js_err)?;
    let (bundle_bytes, pub_key_bytes) =
        froethlib::ceremony::reshare::reshare_part3(secret, round1_packages, round2_packages, expected_vk, network, birthday)
            .map_err(to_js_err)?;
    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "pubKey", &pub_key_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    private_key: Option<Vec<u8>>,
    chain_code: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let sk_opt: Option<&[u8; 32]> = private_key.as_ref().and_then(|s| {
        if s.len() == 32 { s.as_slice().try_into().ok() } else { None }
    });
    let cc_opt: Option<&[u8; 32]> = chain_code.as_ref().and_then(|s| {
        if s.len() == 32 { s.as_slice().try_into().ok() } else { None }
    });
    let (secret, pkg_bytes) =
        froethlib::ceremony::key_import::key_import_part1(identifier, max_signers, min_signers, sk_opt, cc_opt)
            .map_err(to_js_err)?;
    let handle = froethlib::handle::Handle::allocate(secret).map_err(to_js_err)?;
    let obj = js_obj();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secretHandle"),
        &JsValue::from(unsafe { std::mem::transmute::<froethlib::handle::Handle, i32>(handle) }),
    ).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn froeth_key_import_part3(
    secret_handle: i32,
    round1_packages: &[u8],
    round2_packages: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsError> {
    let handle = unsafe { std::mem::transmute::<i32, froethlib::handle::Handle>(secret_handle) };
    let secret = handle.take::<froethlib::ceremony::dkg::DkgRound2Secret>()
        .map_err(to_js_err)?;
    let (bundle_bytes, pub_key_bytes) =
        froethlib::ceremony::key_import::key_import_part3(secret, round1_packages, round2_packages, expected_vk, network, birthday)
            .map_err(to_js_err)?;
    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "pubKey", &pub_key_bytes);
    Ok(obj.into())
}
