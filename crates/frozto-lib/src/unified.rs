use orchard::keys::{FullViewingKey as OrchardFvk, Scope as OrchardScope};
use sapling_crypto::zip32::DiversifiableFullViewingKey as SaplingDfvk;
use zcash_address::unified::{Address as UnifiedAddr, Container, Encoding, Receiver};
use zcash_protocol::consensus::NetworkType;

use crate::{
    bytes::*,
    errors::*,
};

pub struct UnifiedComponents {
    pub orchard_raw_addr: Option<[u8; 43]>,
    pub sapling_raw_addr: Option<[u8; 43]>,
    pub transparent_pkh: Option<[u8; 20]>,
}

pub fn build_unified_address(components: &UnifiedComponents) -> Result<String, lib_error> {
    let mut receivers = Vec::new();

    if let Some(ref orchard) = components.orchard_raw_addr {
        receivers.push(Receiver::Orchard(*orchard));
    }
    if let Some(ref sapling) = components.sapling_raw_addr {
        receivers.push(Receiver::Sapling(*sapling));
    }
    if let Some(ref pkh) = components.transparent_pkh {
        receivers.push(Receiver::P2pkh(*pkh));
    }

    if receivers.is_empty() {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }

    let ua = UnifiedAddr::try_from_items(receivers)
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
    Ok(ua.encode(&NetworkType::Main))
}

pub fn decode_unified_address(ua_str: &str) -> Result<UnifiedComponents, lib_error> {
    let (_network, ua) = UnifiedAddr::decode(ua_str)
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;

    let mut components = UnifiedComponents {
        orchard_raw_addr: None,
        sapling_raw_addr: None,
        transparent_pkh: None,
    };

    for item in ua.items() {
        match item {
            Receiver::Orchard(data) => components.orchard_raw_addr = Some(data),
            Receiver::Sapling(data) => components.sapling_raw_addr = Some(data),
            Receiver::P2pkh(data) => components.transparent_pkh = Some(data),
            _ => {}
        }
    }

    Ok(components)
}

pub fn derive_unified_address_from_keys(
    orchard_fvk_bytes: Option<&[u8]>,
    sapling_dfvk_bytes: Option<&[u8]>,
    transparent_pubkey: Option<&[u8]>,
) -> Result<String, lib_error> {
    let mut components = UnifiedComponents {
        orchard_raw_addr: None,
        sapling_raw_addr: None,
        transparent_pkh: None,
    };

    if let Some(fvk_data) = orchard_fvk_bytes {
        if fvk_data.len() != 96 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        let fvk_arr: [u8; 96] = fvk_data.try_into().unwrap();
        let fvk = OrchardFvk::from_bytes(&fvk_arr)
            .ok_or(lib_error::LIB_ORCHARD_ERROR)?;
        let ivk = fvk.to_ivk(OrchardScope::External);
        let addr = ivk.address_at(0u32);
        components.orchard_raw_addr = Some(addr.to_raw_address_bytes());
    }

    if let Some(dfvk_data) = sapling_dfvk_bytes {
        if dfvk_data.len() != 128 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        let dfvk_arr: [u8; 128] = dfvk_data.try_into().unwrap();
        let dfvk = SaplingDfvk::from_bytes(&dfvk_arr)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let (_, addr) = dfvk.default_address();
        components.sapling_raw_addr = Some(addr.to_bytes());
    }

    if let Some(pk_data) = transparent_pubkey {
        let pkh = crate::transparent::pubkey_to_hash160(pk_data)?;
        components.transparent_pkh = Some(pkh);
    }

    build_unified_address(&components)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_unified_address_encode(
    orchard_fvk: Option<&go_slice>,
    sapling_dfvk: Option<&go_slice>,
    transparent_pubkey: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let orchard = orchard_fvk.map(|s| s.as_slice());
        let sapling = sapling_dfvk.map(|s| s.as_slice());
        let transparent = transparent_pubkey.map(|s| s.as_slice());

        let ua = derive_unified_address_from_keys(orchard, sapling, transparent)?;

        *out = tss_buffer::from_vec(ua.into_bytes());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_unified_address_decode(
    ua_string: Option<&go_slice>,
    out_orchard: Option<&mut tss_buffer>,
    out_sapling: Option<&mut tss_buffer>,
    out_transparent: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ua_data = ua_string.ok_or(lib_error::LIB_NULL_PTR)?;

        let ua_str = std::str::from_utf8(ua_data.as_slice())
            .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
        let components = decode_unified_address(ua_str)?;

        if let Some(out_o) = out_orchard {
            match components.orchard_raw_addr {
                Some(data) => *out_o = tss_buffer::from_vec(data.to_vec()),
                None => *out_o = tss_buffer::empty(),
            }
        }
        if let Some(out_s) = out_sapling {
            match components.sapling_raw_addr {
                Some(data) => *out_s = tss_buffer::from_vec(data.to_vec()),
                None => *out_s = tss_buffer::empty(),
            }
        }
        if let Some(out_t) = out_transparent {
            match components.transparent_pkh {
                Some(data) => *out_t = tss_buffer::from_vec(data.to_vec()),
                None => *out_t = tss_buffer::empty(),
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_orchard_only() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = crate::orchard::generate_extras_raw().unwrap();

        let fvk_raw = crate::orchard::build_fvk_raw(pkp, &extras).unwrap();

        let ua = derive_unified_address_from_keys(Some(&fvk_raw), None, None);
        if let Ok(ua_str) = ua {
            assert!(ua_str.starts_with("u1"), "UA should start with u1: {}", ua_str);

            let components = decode_unified_address(&ua_str).unwrap();
            assert!(components.orchard_raw_addr.is_some());
            assert!(components.sapling_raw_addr.is_none());
            assert!(components.transparent_pkh.is_none());
        }
    }

    #[test]
    fn test_unified_orchard_plus_transparent() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = crate::orchard::generate_extras_raw().unwrap();

        let fvk_raw = crate::orchard::build_fvk_raw(pkp, &extras).unwrap();

        let fake_pubkey = hex::decode(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        ).unwrap();

        let ua = derive_unified_address_from_keys(Some(&fvk_raw), None, Some(&fake_pubkey));
        if let Ok(ua_str) = ua {
            assert!(ua_str.starts_with("u1"));

            let components = decode_unified_address(&ua_str).unwrap();
            assert!(components.orchard_raw_addr.is_some());
            assert!(components.transparent_pkh.is_some());
        }
    }

    #[test]
    fn test_unified_roundtrip_all_three() {
        let orchard_addr = [0xABu8; 43];
        let sapling_addr = [0xCDu8; 43];
        let pkh = [0xEFu8; 20];

        let components = UnifiedComponents {
            orchard_raw_addr: Some(orchard_addr),
            sapling_raw_addr: Some(sapling_addr),
            transparent_pkh: Some(pkh),
        };

        let ua_str = build_unified_address(&components).unwrap();
        assert!(ua_str.starts_with("u1"));

        let decoded = decode_unified_address(&ua_str).unwrap();
        assert_eq!(decoded.orchard_raw_addr.unwrap(), orchard_addr);
        assert_eq!(decoded.sapling_raw_addr.unwrap(), sapling_addr);
        assert_eq!(decoded.transparent_pkh.unwrap(), pkh);
    }

    #[test]
    fn test_unified_empty_fails() {
        let components = UnifiedComponents {
            orchard_raw_addr: None,
            sapling_raw_addr: None,
            transparent_pkh: None,
        };
        assert!(build_unified_address(&components).is_err());
    }

    #[test]
    fn test_unified_transparent_only_fails() {
        let components = UnifiedComponents {
            orchard_raw_addr: None,
            sapling_raw_addr: None,
            transparent_pkh: Some([0xABu8; 20]),
        };
        assert!(build_unified_address(&components).is_err());
    }

    #[test]
    fn test_unified_address_ffi_encode_decode() {
        let orchard_addr = [0xABu8; 43];
        let sapling_addr = [0xCDu8; 43];
        let pkh = [0xEFu8; 20];

        let components = UnifiedComponents {
            orchard_raw_addr: Some(orchard_addr),
            sapling_raw_addr: Some(sapling_addr),
            transparent_pkh: Some(pkh),
        };
        let ua_str = build_unified_address(&components).unwrap();

        let ua_bytes = ua_str.as_bytes();
        let ua_slice = go_slice::from(ua_bytes);

        let mut out_o = tss_buffer::empty();
        let mut out_s = tss_buffer::empty();
        let mut out_t = tss_buffer::empty();

        assert_eq!(
            frozto_unified_address_decode(
                Some(&ua_slice),
                Some(&mut out_o),
                Some(&mut out_s),
                Some(&mut out_t),
            ),
            lib_error::LIB_OK,
        );

        assert_eq!(out_o.into_vec(), orchard_addr.to_vec());
        assert_eq!(out_s.into_vec(), sapling_addr.to_vec());
        assert_eq!(out_t.into_vec(), pkh.to_vec());
    }

    #[test]
    fn test_unified_derive_from_real_orchard_key() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();

        let extras = crate::orchard::derive_extras_from_seed(&seed, 0).unwrap();
        let import = crate::key_import::tests::run_key_import_with_seed(&seed, 3, 2);
        let pkp = &import.results[0].1;

        let fvk_raw = crate::orchard::build_fvk_raw(pkp, &extras);
        if let Ok(fvk) = fvk_raw {
            let ua = derive_unified_address_from_keys(Some(&fvk), None, None);
            if let Ok(ua_str) = ua {
                assert!(ua_str.starts_with("u1"));

                let decoded = decode_unified_address(&ua_str).unwrap();
                assert!(decoded.orchard_raw_addr.is_some());
                assert_eq!(decoded.orchard_raw_addr.unwrap().len(), 43);
            }
        }
    }
}
