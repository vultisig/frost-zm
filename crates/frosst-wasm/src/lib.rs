use wasm_bindgen::prelude::*;

fn to_js_err<E: std::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

fn js_obj() -> js_sys::Object {
    js_sys::Object::new()
}

fn set_bytes(obj: &js_sys::Object, key: &str, data: &[u8]) {
    let arr = js_sys::Uint8Array::from(data);
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &arr).unwrap();
}

// DKG

#[wasm_bindgen]
pub fn frosst_dkg_part1(id: u16, max_signers: u16, min_signers: u16) -> Result<JsValue, JsValue> {
    let (secret, pkg_bytes) = frosstlib::ceremony::dkg::dkg_part1(id, max_signers, min_signers)
        .map_err(to_js_err)?;

    let handle = frosty::Handle::allocate(secret).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frosst_dkg_part2(handle_id: i32, r1_packages: &[u8]) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frosty::Handle>(handle_id) };
    let secret: frosstlib::ceremony::dkg::DkgRound1Secret =
        frosty::Handle::take(handle).map_err(to_js_err)?;

    let (secret2, r2_bytes) = frosstlib::ceremony::dkg::dkg_part2(secret, r1_packages)
        .map_err(to_js_err)?;

    let handle2 = frosty::Handle::allocate(secret2).map_err(to_js_err)?;
    let handle_id2: i32 = unsafe { std::mem::transmute(handle2) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id2)).unwrap();
    set_bytes(&obj, "packages", &r2_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frosst_dkg_part3(
    handle_id: i32,
    r1_packages: &[u8],
    r2_packages: &[u8],
    network: u8,
    birthday: u64,
) -> Result<JsValue, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frosty::Handle>(handle_id) };
    let secret: frosstlib::ceremony::dkg::DkgRound2Secret =
        frosty::Handle::take(handle).map_err(to_js_err)?;

    let (bundle_bytes, pub_key_bytes) =
        frosstlib::ceremony::dkg::dkg_part3(secret, r1_packages, r2_packages, network, birthday)
            .map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "bundle", &bundle_bytes);
    set_bytes(&obj, "publicKey", &pub_key_bytes);
    Ok(obj.into())
}

// Signing

#[wasm_bindgen]
pub fn frosst_sign_commit(key_share: &[u8]) -> Result<JsValue, JsValue> {
    let (nonces, commitments_bytes) = frosstlib::ceremony::sign::sign_commit(key_share)
        .map_err(to_js_err)?;

    let handle = frosty::Handle::allocate(nonces).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    let obj = js_obj();
    js_sys::Reflect::set(&obj, &"handleId".into(), &JsValue::from(handle_id)).unwrap();
    set_bytes(&obj, "commitments", &commitments_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frosst_sign_create_package(message: &[u8], commitments_map: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let pkg = frosstlib::ceremony::sign::sign_create_package(message, commitments_map)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(pkg.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_sign(signing_package: &[u8], nonces_handle_id: i32, key_share: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let handle = unsafe { std::mem::transmute::<i32, frosty::Handle>(nonces_handle_id) };
    let nonces: frosstlib::ceremony::sign::SignNonces =
        frosty::Handle::take(handle).map_err(to_js_err)?;

    let share = frosstlib::ceremony::sign::sign(signing_package, nonces, key_share)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(share.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_sign_aggregate(signing_package: &[u8], shares_map: &[u8], key_share: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let sig = frosstlib::ceremony::sign::sign_aggregate(signing_package, shares_map, key_share)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(sig.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_verify_signature(message: &[u8], signature: &[u8], key_share: &[u8]) -> Result<(), JsValue> {
    frosstlib::ceremony::sign::verify_signature(message, signature, key_share)
        .map_err(to_js_err)
}

// Address

#[wasm_bindgen]
pub fn frosst_derive_address(key_share: &[u8]) -> Result<String, JsValue> {
    frosstlib::solana::address::derive_address(key_share).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn frosst_pubkey_to_address(pubkey: &[u8]) -> Result<String, JsValue> {
    frosstlib::solana::address::pubkey_to_address(pubkey).map_err(to_js_err)
}

// KeyShare bundle helpers

#[wasm_bindgen]
pub fn frosst_keyshare_public_key(bundle: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let b = frosstlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    let vk = b.verifying_key_bytes().map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(vk.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_keyshare_chain_code(bundle: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let b = frosstlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(b.metadata.chain_code.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_keyshare_birthday(bundle: &[u8]) -> Result<u64, JsValue> {
    let b = frosstlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    Ok(b.metadata.birthday)
}

#[wasm_bindgen]
pub fn frosst_keyshare_identifier(bundle: &[u8]) -> Result<u16, JsValue> {
    let b = frosstlib::keyshare::bundle::KeyShareBundle::deserialize(bundle).map_err(to_js_err)?;
    let id = frosty::identifier::identifier_to_u16::<frosstlib::S>(b.key_package.identifier())
        .map_err(to_js_err)?;
    Ok(id)
}

#[wasm_bindgen]
pub fn frosst_private_key_to_public(private_key: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    let sk: &[u8; 32] = private_key.try_into().map_err(to_js_err)?;
    let pk = frosty::ceremony::key_import::private_key_to_public::<frosstlib::S>(sk)
        .map_err(to_js_err)?;
    Ok(js_sys::Uint8Array::from(pk.as_slice()))
}

#[wasm_bindgen]
pub fn frosst_encode_identifier(id: u16) -> Result<js_sys::Uint8Array, JsValue> {
    let ident = frost_core::Identifier::<frosstlib::S>::try_from(id).map_err(to_js_err)?;
    let serialized = ident.serialize();
    let sl: &[u8] = serialized.as_ref();
    Ok(js_sys::Uint8Array::from(sl))
}

#[wasm_bindgen]
pub fn frosst_decode_identifier(id_bytes: &[u8]) -> Result<u16, JsValue> {
    let ident = frost_core::Identifier::<frosstlib::S>::deserialize(id_bytes).map_err(to_js_err)?;
    frosty::identifier::identifier_to_u16::<frosstlib::S>(&ident).map_err(to_js_err)
}
