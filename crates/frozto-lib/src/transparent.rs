use ripemd::Ripemd160;
use sha2::{Sha256, Digest};

use crate::{
    bytes::*,
    errors::*,
};

const T_ADDR_PREFIX: [u8; 2] = [0x1C, 0xB8];

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

pub fn pubkey_to_hash160(compressed_pubkey: &[u8]) -> Result<[u8; 20], lib_error> {
    if compressed_pubkey.len() != 33 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }
    Ok(hash160(compressed_pubkey))
}

pub fn encode_t_address(pubkey_hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&T_ADDR_PREFIX);
    payload.extend_from_slice(pubkey_hash);
    bs58::encode(payload).with_check().into_string()
}

pub fn decode_t_address(addr_str: &str) -> Result<[u8; 20], lib_error> {
    let decoded = bs58::decode(addr_str)
        .with_check(None)
        .into_vec()
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
    if decoded.len() != 22 {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }
    if decoded[0] != T_ADDR_PREFIX[0] || decoded[1] != T_ADDR_PREFIX[1] {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[2..22]);
    Ok(hash)
}

pub fn build_p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_transparent_pubkey_to_address(
    compressed_pubkey: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
    out_pubkey_hash: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pk_data = compressed_pubkey.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_addr = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkh = pubkey_to_hash160(pk_data.as_slice())?;
        let addr = encode_t_address(&pkh);

        *out_addr = tss_buffer::from_vec(addr.into_bytes());
        if let Some(out_h) = out_pubkey_hash {
            *out_h = tss_buffer::from_vec(pkh.to_vec());
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_transparent_decode_address(
    address: Option<&go_slice>,
    out_pubkey_hash: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let addr_data = address.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_pubkey_hash.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr_str = std::str::from_utf8(addr_data.as_slice())
            .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
        let pkh = decode_t_address(addr_str)?;

        *out = tss_buffer::from_vec(pkh.to_vec());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash160() {
        let data = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let h = hash160(&data);
        assert_eq!(hex::encode(h), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn test_encode_decode_t_address() {
        let pkh = hex::decode("ba2722b6bb68e4ff3628fdd36e0a94b0d5fe21b5").unwrap();
        let mut pkh_arr = [0u8; 20];
        pkh_arr.copy_from_slice(&pkh);

        let addr = encode_t_address(&pkh_arr);
        assert!(addr.starts_with("t1"), "t-addr should start with t1: {}", addr);

        let decoded = decode_t_address(&addr).unwrap();
        assert_eq!(decoded, pkh_arr);
    }

    #[test]
    fn test_known_t_address() {
        let hash = decode_t_address("t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs");
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 20);
    }

    #[test]
    fn test_decode_invalid_t_address() {
        assert!(decode_t_address("zs1invalidaddr").is_err());
        assert!(decode_t_address("t3invalid").is_err());
        assert!(decode_t_address("").is_err());
    }

    #[test]
    fn test_p2pkh_script_pubkey() {
        let pkh = [0xABu8; 20];
        let script = build_p2pkh_script_pubkey(&pkh);
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // push 20 bytes
        assert_eq!(&script[3..23], &pkh);
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_pubkey_to_t_address_ffi() {
        let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let pk_slice = go_slice::from(pk.as_slice());
        let mut addr_buf = tss_buffer::empty();
        let mut hash_buf = tss_buffer::empty();

        assert_eq!(
            frozto_transparent_pubkey_to_address(
                Some(&pk_slice),
                Some(&mut addr_buf),
                Some(&mut hash_buf),
            ),
            lib_error::LIB_OK,
        );

        let addr = String::from_utf8(addr_buf.into_vec()).unwrap();
        assert!(addr.starts_with("t1"));

        let hash = hash_buf.into_vec();
        assert_eq!(hash.len(), 20);

        let roundtrip = decode_t_address(&addr).unwrap();
        assert_eq!(roundtrip.as_slice(), hash.as_slice());
    }

    #[test]
    fn test_pubkey_to_hash160_invalid_size() {
        assert!(pubkey_to_hash160(&[0u8; 32]).is_err());
        assert!(pubkey_to_hash160(&[0u8; 65]).is_err());
    }
}
