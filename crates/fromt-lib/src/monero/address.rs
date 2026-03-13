use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use tiny_keccak::{Hasher, Keccak};

use crate::errors::lib_error;

const MAINNET_STANDARD: u8 = 18;

fn network_prefix(network: u8) -> Result<u8, lib_error> {
    match network {
        0 => Ok(MAINNET_STANDARD),
        _ => Err(lib_error::LIB_ADDRESS_ERROR),
    }
}

pub fn derive_address(
    spend_pub_key: &[u8; 32],
    view_key: &[u8; 32],
    network: u8,
) -> Result<String, lib_error> {
    let prefix = network_prefix(network)?;

    let view_scalar = Scalar::from_bytes_mod_order(*view_key);
    let view_pub = (ED25519_BASEPOINT_TABLE * &view_scalar).compress();

    let mut data = Vec::with_capacity(69);
    data.push(prefix);
    data.extend_from_slice(spend_pub_key);
    data.extend_from_slice(view_pub.as_bytes());

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(&data);
    keccak.finalize(&mut hash);
    data.extend_from_slice(&hash[..4]);

    Ok(monero_base58_encode(&data))
}

const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_SIZE: usize = 11;

pub(crate) fn monero_base58_encode(data: &[u8]) -> String {
    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    let remainder = data.len() % FULL_BLOCK_SIZE;

    let total_chars = full_blocks * FULL_ENCODED_SIZE
        + if remainder > 0 {
            ENCODED_BLOCK_SIZES[remainder]
        } else {
            0
        };
    let mut result = String::with_capacity(total_chars);

    for i in 0..full_blocks {
        let block = &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE];
        encode_block(block, FULL_ENCODED_SIZE, &mut result);
    }

    if remainder > 0 {
        let block = &data[full_blocks * FULL_BLOCK_SIZE..];
        encode_block(block, ENCODED_BLOCK_SIZES[remainder], &mut result);
    }

    result
}

fn encode_block(data: &[u8], encoded_size: usize, out: &mut String) {
    let mut num = 0u128;
    for &byte in data {
        num = num * 256 + byte as u128;
    }
    let mut chars = vec![BASE58_ALPHABET[0]; encoded_size];
    for i in (0..encoded_size).rev() {
        let rem = (num % 58) as usize;
        num /= 58;
        chars[i] = BASE58_ALPHABET[rem];
    }
    for &c in &chars {
        out.push(c as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_derivation_produces_output() {
        let spend_pub = [1u8; 32];
        let view_key = [2u8; 32];
        let result = derive_address(&spend_pub, &view_key, 0);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert!(!addr.is_empty());
        assert_eq!(addr.len(), 95);
    }

    #[test]
    fn test_invalid_network() {
        let spend_pub = [1u8; 32];
        let view_key = [2u8; 32];
        assert!(derive_address(&spend_pub, &view_key, 1).is_err());
        assert!(derive_address(&spend_pub, &view_key, 2).is_err());
    }
}
