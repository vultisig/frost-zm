use std::collections::HashMap;
use std::sync::OnceLock;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use wasm_bindgen::prelude::*;

use crate::{to_js_err, Identifier, J};

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

pub(crate) fn identifier_to_u16(id: &Identifier) -> Result<u16, JsError> {
    get_id_lookup()
        .get(&id.serialize())
        .copied()
        .ok_or_else(|| JsError::new("identifier not found in lookup"))
}

#[wasm_bindgen]
pub fn frozt_encode_identifier(id: u16) -> Result<Vec<u8>, JsError> {
    let ident = Identifier::try_from(id).map_err(to_js_err)?;
    Ok(ident.serialize())
}

#[wasm_bindgen]
pub fn frozt_keypackage_identifier(key_package: &[u8]) -> Result<u16, JsError> {
    let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
    identifier_to_u16(kp.identifier())
}

#[wasm_bindgen]
pub fn frozt_pubkeypackage_verifying_key(pub_key_package: &[u8]) -> Result<Vec<u8>, JsError> {
    let pkp = PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;
    let vk = pkp.verifying_key();
    let vk_bytes = vk.serialize().map_err(to_js_err)?;
    Ok(vk_bytes)
}

const BUNDLE_VERSION: u8 = 1;

fn bundle_read_u64(data: &[u8], pos: &mut usize) -> Result<u64, JsError> {
    if *pos + 8 > data.len() {
        return Err(JsError::new("bundle: unexpected end of data reading u64"));
    }
    let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn bundle_read_u32(data: &[u8], pos: &mut usize) -> Result<u32, JsError> {
    if *pos + 4 > data.len() {
        return Err(JsError::new("bundle: unexpected end of data reading u32"));
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

struct BundleParts {
    birthday: u64,
    sapling_extras: Vec<u8>,
    key_package: Vec<u8>,
    pub_key_package: Vec<u8>,
}

fn bundle_unpack(data: &[u8]) -> Result<BundleParts, JsError> {
    if data.len() < 1 + 8 + 4 {
        return Err(JsError::new("bundle: data too short"));
    }

    let mut pos = 0;

    let version = data[pos];
    pos += 1;
    if version != BUNDLE_VERSION {
        return Err(JsError::new("bundle: unsupported version"));
    }

    let birthday = bundle_read_u64(data, &mut pos)?;

    let extras_len = bundle_read_u32(data, &mut pos)? as usize;
    if pos + extras_len > data.len() {
        return Err(JsError::new("bundle: truncated extras"));
    }
    let sapling_extras = data[pos..pos + extras_len].to_vec();
    pos += extras_len;

    let kp_len = bundle_read_u32(data, &mut pos)? as usize;
    if pos + kp_len > data.len() {
        return Err(JsError::new("bundle: truncated key_package"));
    }
    let key_package = data[pos..pos + kp_len].to_vec();
    pos += kp_len;

    let pkp_len = bundle_read_u32(data, &mut pos)? as usize;
    if pos + pkp_len > data.len() {
        return Err(JsError::new("bundle: truncated pub_key_package"));
    }
    let pub_key_package = data[pos..pos + pkp_len].to_vec();

    Ok(BundleParts {
        birthday,
        sapling_extras,
        key_package,
        pub_key_package,
    })
}

#[wasm_bindgen]
pub fn frozt_keyshare_bundle_pack(
    key_package: &[u8],
    pub_key_package: &[u8],
    sapling_extras: &[u8],
    birthday: u64,
) -> Result<Vec<u8>, JsError> {
    KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
    PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;

    let total = 1 + 8 + 4 + sapling_extras.len() + 4 + key_package.len() + 4 + pub_key_package.len();
    let mut buf = Vec::with_capacity(total);

    buf.push(BUNDLE_VERSION);
    buf.extend_from_slice(&birthday.to_le_bytes());
    buf.extend_from_slice(&(sapling_extras.len() as u32).to_le_bytes());
    buf.extend_from_slice(sapling_extras);
    buf.extend_from_slice(&(key_package.len() as u32).to_le_bytes());
    buf.extend_from_slice(key_package);
    buf.extend_from_slice(&(pub_key_package.len() as u32).to_le_bytes());
    buf.extend_from_slice(pub_key_package);

    Ok(buf)
}

#[wasm_bindgen]
pub fn frozt_keyshare_bundle_birthday(bundle: &[u8]) -> Result<u64, JsError> {
    let parts = bundle_unpack(bundle)?;
    Ok(parts.birthday)
}

#[wasm_bindgen]
pub fn frozt_keyshare_bundle_key_package(bundle: &[u8]) -> Result<Vec<u8>, JsError> {
    let parts = bundle_unpack(bundle)?;
    Ok(parts.key_package)
}

#[wasm_bindgen]
pub fn frozt_keyshare_bundle_pub_key_package(bundle: &[u8]) -> Result<Vec<u8>, JsError> {
    let parts = bundle_unpack(bundle)?;
    Ok(parts.pub_key_package)
}

#[wasm_bindgen]
pub fn frozt_keyshare_bundle_sapling_extras(bundle: &[u8]) -> Result<Vec<u8>, JsError> {
    let parts = bundle_unpack(bundle)?;
    Ok(parts.sapling_extras)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg_native;
    use wasm_bindgen_test::*;

    #[test]
    fn test_identifier_roundtrip() {
        for id in 1..=10u16 {
            let ident = Identifier::try_from(id).unwrap();
            let decoded = identifier_to_u16(&ident).unwrap();
            assert_eq!(id, decoded);
        }
    }

    #[wasm_bindgen_test]
    fn test_identifier_roundtrip_wasm() {
        test_identifier_roundtrip();
    }

    #[test]
    fn test_bundle_round_trip() {
        let results = run_dkg_native(3, 2);
        let extras = vec![0xCDu8; 96];
        let birthday = 3256538u64;

        let (kp, pkp) = &results[0];
        let bundle = frozt_keyshare_bundle_pack(kp, pkp, &extras, birthday).unwrap();

        assert_eq!(frozt_keyshare_bundle_birthday(&bundle).unwrap(), birthday);
        assert_eq!(frozt_keyshare_bundle_key_package(&bundle).unwrap(), *kp);
        assert_eq!(frozt_keyshare_bundle_pub_key_package(&bundle).unwrap(), *pkp);
        assert_eq!(frozt_keyshare_bundle_sapling_extras(&bundle).unwrap(), extras);
    }

    #[wasm_bindgen_test]
    fn test_bundle_round_trip_wasm() {
        test_bundle_round_trip();
    }
}
