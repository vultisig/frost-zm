use frosty::errors::lib_error;
use crate::Bundle;

pub fn derive_address(key_share_data: &[u8]) -> Result<String, lib_error> {
    let bundle = Bundle::deserialize(key_share_data)?;
    let vk_bytes = bundle.verifying_key_bytes()?;
    pubkey_to_address(&vk_bytes)
}

pub fn pubkey_to_address(verifying_key_bytes: &[u8]) -> Result<String, lib_error> {
    if verifying_key_bytes.len() != 32 {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }
    Ok(bs58::encode(verifying_key_bytes).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::run_dkg;

    #[test]
    fn test_derive_address_consistency() {
        let bundles = run_dkg(3, 2);

        let addr0 = derive_address(&bundles[0]).unwrap();
        let addr1 = derive_address(&bundles[1]).unwrap();
        let addr2 = derive_address(&bundles[2]).unwrap();

        assert!(addr0.len() >= 32 && addr0.len() <= 44);
        assert_eq!(addr0, addr1);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_deterministic() {
        let bundles = run_dkg(3, 2);
        let addr1 = derive_address(&bundles[0]).unwrap();
        let addr2 = derive_address(&bundles[0]).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_pubkey_to_address_32_bytes() {
        let pubkey = [1u8; 32];
        let addr = pubkey_to_address(&pubkey).unwrap();
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn test_pubkey_to_address_rejects_wrong_size() {
        assert!(pubkey_to_address(&[0u8; 33]).is_err());
        assert!(pubkey_to_address(&[0u8; 20]).is_err());
    }
}
