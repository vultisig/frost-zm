use frost_core::{Ciphersuite, Group};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::bundle::{BundleMetadata, KeyShareBundle};
use crate::ceremony::dkg::{ser_err, deserialize_scalar, serialize_scalar};
use crate::errors::lib_error;

type Scalar<C> = frost_core::Scalar<C>;
type G<C> = <C as Ciphersuite>::Group;

type HmacSha512 = Hmac<Sha512>;

fn bip32_child_tweak<C: Ciphersuite>(
    chain_code: &[u8; 32],
    parent_pubkey_compressed: &[u8],
    index: u32,
) -> Result<(Scalar<C>, [u8; 32]), lib_error> {
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

    let tweak: Scalar<C> = deserialize_scalar::<C>(&tweak_bytes)?;

    Ok((tweak, child_chain_code))
}

fn serialize_verifying_key<C: Ciphersuite>(
    pub_key_package: &frost_core::keys::PublicKeyPackage<C>,
) -> Result<Vec<u8>, lib_error> {
    let vk = pub_key_package.verifying_key();
    let vk_bytes = vk.serialize().map_err(ser_err)?;
    let vk_slice: &[u8] = vk_bytes.as_ref();
    Ok(vk_slice.to_vec())
}

fn deserialize_point<C: Ciphersuite>(data: &[u8]) -> Result<<<C as Ciphersuite>::Group as Group>::Element, lib_error> {
    type GroupSer<C> = <<C as Ciphersuite>::Group as Group>::Serialization;

    let expected_size = std::mem::size_of::<GroupSer<C>>();
    if expected_size != data.len() {
        return Err(lib_error::LIB_CKD_ERROR);
    }

    // SAFETY: We verified GroupSer<C> has the same size as data.
    // All FROST ciphersuites use [u8; 33] (secp256k1) or [u8; 32] (ed25519).
    let buf: &GroupSer<C> = unsafe { &*(data.as_ptr() as *const GroupSer<C>) };
    <G<C> as Group>::deserialize(buf).map_err(ser_err)
}

fn serialize_point<C: Ciphersuite>(point: &<<C as Ciphersuite>::Group as Group>::Element) -> Result<Vec<u8>, lib_error> {
    let bytes = <G<C> as Group>::serialize(point).map_err(ser_err)?;
    let sl: &[u8] = bytes.as_ref();
    Ok(sl.to_vec())
}

pub fn ckd_derive<C: Ciphersuite, M: BundleMetadata>(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<Vec<u8>, lib_error> {
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;

    let parent_compressed = serialize_verifying_key::<C>(&bundle.pub_key_package)?;

    let (tweak1, child_cc) = bip32_child_tweak::<C>(
        bundle.metadata.extra_bytes(),
        &parent_compressed,
        change,
    )?;

    let child_point = <G<C> as Group>::generator() * tweak1;
    let parent_point = deserialize_point::<C>(&parent_compressed)?;
    let child_parent = parent_point + child_point;
    let child_parent_bytes = serialize_point::<C>(&child_parent)?;

    let (tweak2, _) = bip32_child_tweak::<C>(
        &child_cc,
        &child_parent_bytes,
        index,
    )?;

    let total_tweak = tweak1 + tweak2;

    let share = bundle.key_package.signing_share().to_scalar();
    let child_share = share + total_tweak;

    let result = serialize_scalar::<C>(&child_share)?;
    Ok(result.to_vec())
}

pub fn derive_child_pubkey<C: Ciphersuite, M: BundleMetadata>(
    key_share_data: &[u8],
    change: u32,
    index: u32,
) -> Result<Vec<u8>, lib_error> {
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;

    let parent_compressed = serialize_verifying_key::<C>(&bundle.pub_key_package)?;

    let (tweak1, child_cc) = bip32_child_tweak::<C>(
        bundle.metadata.extra_bytes(),
        &parent_compressed,
        change,
    )?;

    let parent_point = deserialize_point::<C>(&parent_compressed)?;
    let child1_point = parent_point + <G<C> as Group>::generator() * tweak1;
    let child1_bytes = serialize_point::<C>(&child1_point)?;

    let (tweak2, _) = bip32_child_tweak::<C>(
        &child_cc,
        &child1_bytes,
        index,
    )?;

    let child2_point = child1_point + <G<C> as Group>::generator() * tweak2;
    serialize_point::<C>(&child2_point)
}
