use tiny_keccak::{Hasher, Keccak};

use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;

pub fn eth_address(verifying_key_bytes: &[u8]) -> Result<[u8; 20], lib_error> {
    let uncompressed = decompress_to_uncompressed(verifying_key_bytes)?;

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(&uncompressed[1..]);
    keccak.finalize(&mut hash);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

pub fn eth_address_hex(verifying_key_bytes: &[u8]) -> Result<String, lib_error> {
    let addr = eth_address(verifying_key_bytes)?;
    Ok(eip55_checksum(&addr))
}

pub fn derive_root_address(
    key_share_data: &[u8],
) -> Result<String, lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;
    let vk_bytes = bundle.verifying_key_bytes()?;
    eth_address_hex(&vk_bytes)
}

pub fn derive_address_from_bundle(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<String, lib_error> {
    let child_pubkey = crate::ceremony::ckd::derive_child_pubkey(key_share_data, change, index)?;
    eth_address_hex(&child_pubkey)
}

fn decompress_to_uncompressed(compressed: &[u8]) -> Result<Vec<u8>, lib_error> {
    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

    let encoded = k256::EncodedPoint::from_bytes(compressed)
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;

    let affine = k256::AffinePoint::from_encoded_point(&encoded);
    if affine.is_none().into() {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }

    let uncompressed = affine.unwrap().to_encoded_point(false);
    Ok(uncompressed.as_bytes().to_vec())
}

fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(hex_addr.as_bytes());
    keccak.finalize(&mut hash);

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };

        if nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;
    use crate::ceremony::sign;
    use crate::ceremony::sign::tests::run_sign;
    use crate::keyshare::bundle::KeyShareBundle;

    #[test]
    fn test_eth_address_consistency() {
        let bundles = run_dkg(3, 2);

        let addr0 = derive_root_address(&bundles[0]).unwrap();
        let addr1 = derive_root_address(&bundles[1]).unwrap();
        let addr2 = derive_root_address(&bundles[2]).unwrap();

        assert!(addr0.starts_with("0x"));
        assert_eq!(addr0.len(), 42);
        assert_eq!(addr0, addr1);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_eth_child_address() {
        let bundles = run_dkg(3, 2);

        let addr0 = derive_address_from_bundle(&bundles[0], 0, 0).unwrap();
        let addr1 = derive_address_from_bundle(&bundles[1], 0, 0).unwrap();
        assert_eq!(addr0, addr1);

        let addr_diff = derive_address_from_bundle(&bundles[0], 0, 1).unwrap();
        assert_ne!(addr0, addr_diff);
    }

    #[test]
    fn test_eip55_checksum() {
        let addr_bytes: [u8; 20] = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
            .unwrap()
            .try_into()
            .unwrap();
        let checksummed = eip55_checksum(&addr_bytes);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_key_import_eth_address() {
        use crate::ceremony::key_import;

        let seed = [0x42u8; 64];
        let (sk, cc, pub_key) = key_import::derive_from_seed(&seed, 0).unwrap();
        let bundles = key_import::tests::run_key_import(3, 2, &sk, &cc, &pub_key);

        let addr0 = derive_root_address(&bundles[0]).unwrap();
        let addr1 = derive_root_address(&bundles[1]).unwrap();
        assert_eq!(addr0, addr1);
        assert!(addr0.starts_with("0x"));
    }

    #[test]
    fn test_generate_solidity_vectors() {
        let bundles = run_dkg(3, 2);

        let bundle0 = KeyShareBundle::deserialize(&bundles[0]).unwrap();
        let vk_bytes = bundle0.verifying_key_bytes().unwrap();
        let eth_addr = eth_address_hex(&vk_bytes).unwrap();

        let message = b"test message for froeth signing";
        let sig_bytes = run_sign(&bundles, &[0, 1]);
        sign::verify_signature(message.as_ref(), &sig_bytes, &bundles[0]).unwrap();

        eprintln!("=== FROST EVM Test Vectors ===");
        eprintln!("group_pubkey: 0x{}", hex::encode(&vk_bytes));
        eprintln!("eth_address: {}", eth_addr);
        eprintln!("message: 0x{}", hex::encode(message));
        eprintln!("signature R: 0x{}", hex::encode(&sig_bytes[..33]));
        eprintln!("signature z: 0x{}", hex::encode(&sig_bytes[33..]));

        assert_eq!(vk_bytes.len(), 33);
        assert_eq!(sig_bytes.len(), 65);
    }

    #[test]
    fn test_full_lifecycle_dkg_sign_reshare() {
        let bundles_2of3 = run_dkg(3, 2);
        let addr_original = derive_root_address(&bundles_2of3[0]).unwrap();

        let message = b"test message for froeth signing";
        let sig = run_sign(&bundles_2of3, &[0, 1]);
        sign::verify_signature(message, &sig, &bundles_2of3[0]).unwrap();
        sign::verify_signature(message, &run_sign(&bundles_2of3, &[1, 2]), &bundles_2of3[1]).unwrap();
        sign::verify_signature(message, &run_sign(&bundles_2of3, &[0, 2]), &bundles_2of3[2]).unwrap();

        use crate::ceremony::reshare::tests::run_reshare;
        let bundles_2of4 = run_reshare(&bundles_2of3, 4, 2, &[1, 2, 3]);

        let addr_after_reshare = derive_root_address(&bundles_2of4[0]).unwrap();
        assert_eq!(addr_original, addr_after_reshare);

        let sig_new = run_sign(&bundles_2of4, &[0, 1]);
        sign::verify_signature(message, &sig_new, &bundles_2of4[0]).unwrap();
    }

    #[test]
    fn test_key_import_produces_correct_eth_address() {
        use crate::ceremony::key_import;

        let seed = [0x42u8; 64];
        let (sk, cc, pub_key) = key_import::derive_from_seed(&seed, 0).unwrap();
        let bundles = key_import::tests::run_key_import(3, 2, &sk, &cc, &pub_key);

        let addr0 = derive_root_address(&bundles[0]).unwrap();
        let addr1 = derive_root_address(&bundles[1]).unwrap();
        let addr2 = derive_root_address(&bundles[2]).unwrap();
        assert_eq!(addr0, addr1);
        assert_eq!(addr1, addr2);

        let msg = b"test message for froeth signing";
        let sig = run_sign(&bundles, &[0, 2]);
        sign::verify_signature(msg, &sig, &bundles[0]).unwrap();
    }

    #[test]
    fn test_child_key_derivation_addresses() {
        let bundles = run_dkg(3, 2);

        let root_addr = derive_root_address(&bundles[0]).unwrap();
        let child_0_0 = derive_address_from_bundle(&bundles[0], 0, 0).unwrap();
        let child_0_1 = derive_address_from_bundle(&bundles[0], 0, 1).unwrap();

        let child_0_0_from_party2 = derive_address_from_bundle(&bundles[1], 0, 0).unwrap();
        assert_eq!(child_0_0, child_0_0_from_party2);

        assert_ne!(root_addr, child_0_0);
        assert_ne!(child_0_0, child_0_1);
    }
}
