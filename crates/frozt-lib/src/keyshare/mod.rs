pub mod bundle;

use std::collections::HashMap;
use std::sync::OnceLock;

use frost_core::keys::KeyPackage;
use frost_core::keys::PublicKeyPackage;
use reddsa::frost::redjubjub::JubjubBlake2b512;

use crate::{
    bytes::*,
    errors::*,
};

type J = JubjubBlake2b512;
type Identifier = frost_core::Identifier<J>;

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozt serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

/// Lookup table for identifier bytes → u16. Supports identifiers 1..=256.
static ID_LOOKUP: OnceLock<HashMap<Vec<u8>, u16>> = OnceLock::new();

fn get_id_lookup() -> &'static HashMap<Vec<u8>, u16> {
    ID_LOOKUP.get_or_init(|| {
        let mut map = HashMap::with_capacity(256);
        for i in 1..=256u16 {
            if let Ok(id) = Identifier::try_from(i) {
                map.insert(id.serialize(), i);
            }
        }
        map
    })
}

pub(crate) fn identifier_to_u16(id: &Identifier) -> Result<u16, lib_error> {
    get_id_lookup()
        .get(&id.serialize())
        .copied()
        .ok_or(lib_error::LIB_INVALID_IDENTIFIER)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_encode_identifier(
    id: u16,
    out_bytes: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::try_from(id)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        *out = tss_buffer::from_vec(ident.serialize());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_decode_identifier(
    id_bytes: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let data = id_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::deserialize(data.as_slice()).map_err(ser_err)?;
        *out = identifier_to_u16(&ident)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keypackage_identifier(
    key_package: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;

        let kp = KeyPackage::<J>::deserialize(kp_data.as_slice()).map_err(ser_err)?;
        *out = identifier_to_u16(kp.identifier())?;

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_pubkeypackage_verifying_key(
    pub_key_package: Option<&go_slice>,
    out_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkp = PublicKeyPackage::<J>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;
        let vk = pkp.verifying_key();
        let vk_bytes = vk.serialize().map_err(ser_err)?;

        *out = tss_buffer::from_vec(vk_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keyshare_bundle_pack(
    key_package: Option<&go_slice>,
    pub_key_package: Option<&go_slice>,
    sapling_extras: Option<&go_slice>,
    birthday: u64,
    out_bundle: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_bundle.ok_or(lib_error::LIB_NULL_PTR)?;

        let kp = KeyPackage::<J>::deserialize(kp_data.as_slice()).map_err(ser_err)?;
        let pkp = PublicKeyPackage::<J>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;
        let extras = extras_data.as_slice().to_vec();

        let b = bundle::KeyShareBundle::new(kp, pkp, extras, birthday);
        let bytes = b.serialize()?;

        *out = tss_buffer::from_vec(bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keyshare_bundle_birthday(
    bundle_data: Option<&go_slice>,
    out_birthday: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let data = bundle_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_birthday.ok_or(lib_error::LIB_NULL_PTR)?;

        let b = bundle::KeyShareBundle::deserialize(data.as_slice())?;
        *out = b.birthday;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keyshare_bundle_key_package(
    bundle_data: Option<&go_slice>,
    out_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let data = bundle_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let b = bundle::KeyShareBundle::deserialize(data.as_slice())?;
        let kp_bytes = b.key_package.serialize().map_err(ser_err)?;

        *out = tss_buffer::from_vec(kp_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keyshare_bundle_pub_key_package(
    bundle_data: Option<&go_slice>,
    out_pub_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let data = bundle_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let b = bundle::KeyShareBundle::deserialize(data.as_slice())?;
        let pkp_bytes = b.pub_key_package.serialize().map_err(ser_err)?;

        *out = tss_buffer::from_vec(pkp_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_keyshare_bundle_sapling_extras(
    bundle_data: Option<&go_slice>,
    out_sapling_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let data = bundle_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;

        let b = bundle::KeyShareBundle::deserialize(data.as_slice())?;

        *out = tss_buffer::from_vec(b.sapling_extras);
        Ok(())
    })
}
