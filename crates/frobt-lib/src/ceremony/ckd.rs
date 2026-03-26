use frost_core::{Ciphersuite, Field, Group};
use frost_secp256k1::Secp256K1Sha256;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::ceremony::dkg::ser_err;
use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;

type S = Secp256K1Sha256;
type Scalar = frost_core::Scalar<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;
type G = <S as Ciphersuite>::Group;

type HmacSha512 = Hmac<Sha512>;

fn to_33(data: &[u8]) -> Result<&[u8; 33], lib_error> {
    data.try_into().map_err(|_| lib_error::LIB_CKD_ERROR)
}

fn bip32_child_tweak(
    chain_code: &[u8; 32],
    parent_pubkey_compressed: &[u8],
    index: u32,
) -> Result<(Scalar, [u8; 32]), lib_error> {
    if index >= (1 << 31) {
        return Err(lib_error::LIB_CKD_ERROR);
    }

    let mut mac = HmacSha512::new_from_slice(chain_code)
        .map_err(|_| lib_error::LIB_CKD_ERROR)?;
    mac.update(parent_pubkey_compressed);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let tweak_bytes: [u8; 32] = result[..32]
        .try_into()
        .map_err(|_| lib_error::LIB_CKD_ERROR)?;
    let child_chain_code: [u8; 32] = result[32..]
        .try_into()
        .map_err(|_| lib_error::LIB_CKD_ERROR)?;

    let tweak: Scalar = F::deserialize(&tweak_bytes).map_err(ser_err)?;

    Ok((tweak, child_chain_code))
}

fn serialize_verifying_key_compressed(
    pub_key_package: &frost_core::keys::PublicKeyPackage<S>,
) -> Result<Vec<u8>, lib_error> {
    let vk = pub_key_package.verifying_key();
    let vk_bytes = vk.serialize().map_err(ser_err)?;
    let vk_slice: &[u8] = vk_bytes.as_ref();

    if vk_slice.len() == 33 {
        return Ok(vk_slice.to_vec());
    }

    if vk_slice.len() == 32 {
        let point = <G as Group>::deserialize(to_33(vk_slice)?).map_err(ser_err)?;
        let serialized = <G as Group>::serialize(&point).map_err(ser_err)?;
        let sl: &[u8] = serialized.as_ref();
        return Ok(sl.to_vec());
    }

    Err(lib_error::LIB_CKD_ERROR)
}

pub fn ckd_derive(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<Vec<u8>, lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;

    let parent_compressed = serialize_verifying_key_compressed(&bundle.pub_key_package)?;

    let (tweak1, child_cc) = bip32_child_tweak(
        &bundle.chain_code,
        &parent_compressed,
        change,
    )?;

    let child_point = <G as Group>::generator() * tweak1;
    let parent_point = <G as Group>::deserialize(to_33(&parent_compressed)?).map_err(ser_err)?;
    let child_parent = parent_point + child_point;
    let child_parent_bytes = <G as Group>::serialize(&child_parent).map_err(ser_err)?;
    let child_parent_sl: &[u8] = child_parent_bytes.as_ref();

    let (tweak2, _) = bip32_child_tweak(
        &child_cc,
        child_parent_sl,
        index,
    )?;

    let total_tweak = tweak1 + tweak2;

    let share = bundle.key_package.signing_share().to_scalar();
    let child_share = share + total_tweak;

    let child_share_bytes = F::serialize(&child_share);
    let sl: &[u8] = child_share_bytes.as_ref();
    Ok(sl.to_vec())
}

pub fn derive_child_pubkey(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<Vec<u8>, lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;

    let parent_compressed = serialize_verifying_key_compressed(&bundle.pub_key_package)?;

    let (tweak1, child_cc) = bip32_child_tweak(
        &bundle.chain_code,
        &parent_compressed,
        change,
    )?;

    let parent_point = <G as Group>::deserialize(to_33(&parent_compressed)?).map_err(ser_err)?;
    let child1_point = parent_point + <G as Group>::generator() * tweak1;
    let child1_bytes = <G as Group>::serialize(&child1_point).map_err(ser_err)?;
    let child1_sl: &[u8] = child1_bytes.as_ref();

    let (tweak2, _) = bip32_child_tweak(
        &child_cc,
        child1_sl,
        index,
    )?;

    let child2_point = child1_point + <G as Group>::generator() * tweak2;
    let result = <G as Group>::serialize(&child2_point).map_err(ser_err)?;
    let result_sl: &[u8] = result.as_ref();
    Ok(result_sl.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;

    #[test]
    fn test_ckd_deterministic() {
        let bundles = run_dkg(3, 2);

        let child0 = ckd_derive(&bundles[0], 0, 0).unwrap();
        let child1 = ckd_derive(&bundles[0], 0, 0).unwrap();
        assert_eq!(child0, child1);
    }

    #[test]
    fn test_ckd_different_indices() {
        let bundles = run_dkg(3, 2);

        let child_0_0 = ckd_derive(&bundles[0], 0, 0).unwrap();
        let child_0_1 = ckd_derive(&bundles[0], 0, 1).unwrap();
        let child_1_0 = ckd_derive(&bundles[0], 1, 0).unwrap();

        assert_ne!(child_0_0, child_0_1);
        assert_ne!(child_0_0, child_1_0);
    }

    #[test]
    fn test_derive_child_pubkey() {
        let bundles = run_dkg(3, 2);

        let pub0 = derive_child_pubkey(&bundles[0], 0, 0).unwrap();
        let pub1 = derive_child_pubkey(&bundles[1], 0, 0).unwrap();
        assert_eq!(pub0, pub1);
    }
}
