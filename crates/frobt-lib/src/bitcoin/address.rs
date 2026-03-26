use bitcoin::key::TapTweak;

use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;

pub fn derive_p2tr_address(
    x_only_pubkey: &[u8],
    network: u8,
) -> Result<String, lib_error> {
    if x_only_pubkey.len() != 32 {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }

    let xonly = bitcoin::key::XOnlyPublicKey::from_slice(x_only_pubkey)
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let (tweaked, _parity) = xonly.tap_tweak(&secp, None);

    let btc_network = match network {
        0 => bitcoin::Network::Bitcoin,
        1 => bitcoin::Network::Testnet,
        2 => bitcoin::Network::Signet,
        _ => return Err(lib_error::LIB_ADDRESS_ERROR),
    };

    let address = bitcoin::Address::p2tr_tweaked(tweaked, btc_network);
    Ok(address.to_string())
}

pub fn derive_address_from_bundle(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<String, lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;

    let child_pubkey = crate::ceremony::ckd::derive_child_pubkey(key_share_data, change, index)?;

    let x_only = extract_x_only(&child_pubkey)?;
    derive_p2tr_address(&x_only, bundle.network)
}

pub fn derive_root_address(
    key_share_data: &[u8],
) -> Result<String, lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;
    let vk_bytes = bundle.verifying_key_bytes()?;
    let x_only = extract_x_only(&vk_bytes)?;
    derive_p2tr_address(&x_only, bundle.network)
}

fn extract_x_only(pubkey_bytes: &[u8]) -> Result<Vec<u8>, lib_error> {
    match pubkey_bytes.len() {
        32 => Ok(pubkey_bytes.to_vec()),
        33 => Ok(pubkey_bytes[1..].to_vec()),
        _ => Err(lib_error::LIB_ADDRESS_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;

    #[test]
    fn test_derive_root_address() {
        let bundles = run_dkg(3, 2);

        let addr0 = derive_root_address(&bundles[0]).unwrap();
        let addr1 = derive_root_address(&bundles[1]).unwrap();

        assert!(addr0.starts_with("bc1p") || addr0.starts_with("tb1p"));
        assert_eq!(addr0, addr1);
    }

    #[test]
    fn test_derive_child_address() {
        let bundles = run_dkg(3, 2);

        let addr0 = derive_address_from_bundle(&bundles[0], 0, 0).unwrap();
        let addr1 = derive_address_from_bundle(&bundles[1], 0, 0).unwrap();

        assert_eq!(addr0, addr1);

        let addr_different = derive_address_from_bundle(&bundles[0], 0, 1).unwrap();
        assert_ne!(addr0, addr_different);
    }
}
