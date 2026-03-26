use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use tiny_keccak::{Hasher, Keccak};

use frosty::errors::lib_error;
use crate::monero::address;

pub fn derive_subaddress(
    spend_pub_key: &[u8; 32],
    view_key: &[u8; 32],
    account: u32,
    index: u32,
    network: u8,
) -> Result<String, lib_error> {
    if account == 0 && index == 0 {
        return address::derive_address(spend_pub_key, view_key, network);
    }

    let spend_point = CompressedEdwardsY::from_slice(spend_pub_key)
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?
        .decompress()
        .ok_or(lib_error::LIB_ADDRESS_ERROR)?;

    let view_scalar = Scalar::from_bytes_mod_order(*view_key);

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(b"SubAddr\x00");
    keccak.update(view_key);
    keccak.update(&account.to_le_bytes());
    keccak.update(&index.to_le_bytes());
    keccak.finalize(&mut hash);

    let hash_scalar = Scalar::from_bytes_mod_order(hash);

    let sub_spend = (spend_point + ED25519_BASEPOINT_TABLE * &hash_scalar).compress();
    let sub_spend_point = sub_spend.decompress().ok_or(lib_error::LIB_ADDRESS_ERROR)?;
    let sub_view = (&sub_spend_point * &view_scalar).compress();

    let prefix = match network {
        0 => 42u8,
        _ => return Err(lib_error::LIB_ADDRESS_ERROR),
    };

    let mut data = Vec::with_capacity(69);
    data.push(prefix);
    data.extend_from_slice(sub_spend.as_bytes());
    data.extend_from_slice(sub_view.as_bytes());

    let mut keccak2 = Keccak::v256();
    let mut checksum = [0u8; 32];
    keccak2.update(&data);
    keccak2.finalize(&mut checksum);
    data.extend_from_slice(&checksum[..4]);

    Ok(address::monero_base58_encode(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subaddress_zero_is_main() {
        let spend_pub = [1u8; 32];
        let view_key = [2u8; 32];
        let main = address::derive_address(&spend_pub, &view_key, 0).unwrap();
        let sub = derive_subaddress(&spend_pub, &view_key, 0, 0, 0).unwrap();
        assert_eq!(main, sub);
    }
}
