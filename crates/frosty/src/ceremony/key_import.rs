use frost_core::{Ciphersuite, Field, Group};

use std::collections::BTreeMap;

use crate::bundle::{BundleMetadata, KeyShareBundle};
use crate::ceremony::dkg::{
    decode_r1_map_with_extra, decode_r2_map, ser_err, deserialize_scalar,
    DkgRound1Secret, DkgRound2Secret, EXTRA_LEN,
};
use crate::errors::lib_error;

type F<C> = <<C as Ciphersuite>::Group as Group>::Field;
type Scalar<C> = frost_core::Scalar<C>;
type G<C> = <C as Ciphersuite>::Group;

pub fn derive_from_seed<C: Ciphersuite>(
    seed: &[u8],
    account_index: u32,
    bip32_purpose: u32,
    bip32_coin_type: u32,
) -> Result<([u8; 32], [u8; 32], Vec<u8>), lib_error> {
    if seed.len() != 64 {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }
    if account_index >= (1 << 31) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    use bitcoin::bip32::{ChildNumber, Xpriv};
    use bitcoin::Network;

    let master = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let path = [
        ChildNumber::from_hardened_idx(bip32_purpose).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
        ChildNumber::from_hardened_idx(bip32_coin_type).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
        ChildNumber::from_hardened_idx(account_index).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
    ];

    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;

    let private_key: [u8; 32] = derived.private_key.secret_bytes();
    let chain_code: [u8; 32] = derived.chain_code.to_bytes();

    let scalar: Scalar<C> = deserialize_scalar::<C>(&private_key)?;
    let point = <G<C> as Group>::generator() * scalar;
    let point_bytes = <C as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;
    let sl: &[u8] = point_bytes.as_ref();

    Ok((private_key, chain_code, sl.to_vec()))
}

pub fn private_key_to_public<C: Ciphersuite>(private_key: &[u8; 32]) -> Result<Vec<u8>, lib_error> {
    let scalar: Scalar<C> = deserialize_scalar::<C>(private_key)?;
    let point = <G<C> as Group>::generator() * scalar;
    let point_bytes = <C as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;
    let sl: &[u8] = point_bytes.as_ref();
    Ok(sl.to_vec())
}

pub fn key_import_part1<C: Ciphersuite>(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    private_key: Option<&[u8; 32]>,
    extra_data: Option<&[u8; 32]>,
) -> Result<(DkgRound1Secret<C>, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    let (constant_term, extra_bytes) = match private_key {
        Some(sk_bytes) => {
            let sk_scalar: Scalar<C> = deserialize_scalar::<C>(sk_bytes)?;
            let ct = frost_ceremony::key_import::derive_constant_term::<C>(sk_scalar, max_signers);
            let extra = extra_data.copied().unwrap_or([0u8; 32]);
            (ct, extra)
        }
        None => (F::<C>::one(), [0u8; 32]),
    };

    let (secret, mut pkg_bytes) =
        frost_ceremony::key_import::key_import_part1::<C>(id, max_signers, min_signers, constant_term)?;

    pkg_bytes.extend_from_slice(&extra_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        extra_share: extra_bytes,
    };

    Ok((out_secret, pkg_bytes))
}

pub fn key_import_part3<C: Ciphersuite, M: BundleMetadata>(
    secret: DkgRound2Secret<C>,
    r1_data: &[u8],
    r2_data: &[u8],
    _expected_vk: &[u8],
    build_meta: impl FnOnce([u8; EXTRA_LEN]) -> M,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, extra_shares) = decode_r1_map_with_extra::<C>(r1_data)?;
    let r2_pkgs = decode_r2_map::<C>(r2_data)?;

    let (key_package, pub_key_package) =
        frost_core::keys::dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;

    let extra = aggregate_import_extra(&secret.extra_share, &extra_shares)?;
    let metadata = build_meta(extra);

    let bundle = KeyShareBundle::new(key_package, pub_key_package, metadata);
    let bundle_bytes = bundle.serialize()?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_import_extra<C: Ciphersuite>(
    own_share: &[u8; EXTRA_LEN],
    other_shares: &BTreeMap<frost_core::Identifier<C>, [u8; EXTRA_LEN]>,
) -> Result<[u8; EXTRA_LEN], lib_error> {
    let zero = [0u8; EXTRA_LEN];
    if *own_share != zero {
        return Ok(*own_share);
    }
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    Err(lib_error::LIB_KEY_IMPORT_ERROR)
}
