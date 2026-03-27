use tiny_keccak::{Hasher, Keccak};

use frosty::errors::lib_error;
use crate::Bundle;

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
    let bundle = Bundle::deserialize(key_share_data)?;
    let vk_bytes = bundle.verifying_key_bytes()?;
    eth_address_hex(&vk_bytes)
}

pub fn derive_address_from_bundle(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<String, lib_error> {
    let child_pubkey = frosty::ceremony::ckd::derive_child_pubkey::<crate::S, frosty::bundle::ChainCodeMeta>(
        key_share_data, change, index,
    )?;
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
    use crate::tests::run_dkg;

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
}
