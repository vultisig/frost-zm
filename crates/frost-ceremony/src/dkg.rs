use std::collections::BTreeMap;

use frost_core::{Ciphersuite, Identifier, keys::dkg};
use frost_ffi::{codec, errors::lib_error};

pub(crate) fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frost-ceremony serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

pub fn encode_r1_map<C: Ciphersuite>(
    packages: &BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
) -> Result<Vec<u8>, lib_error> {
    codec::encode_map(
        packages,
        |id| Ok(id.serialize()),
        |pkg| pkg.serialize().map_err(ser_err),
    )
}

pub fn decode_r1_map<C: Ciphersuite>(
    data: &[u8],
) -> Result<BTreeMap<Identifier<C>, dkg::round1::Package<C>>, lib_error> {
    codec::decode_map(
        data,
        |b| Identifier::<C>::deserialize(b).map_err(ser_err),
        |b| dkg::round1::Package::<C>::deserialize(b).map_err(ser_err),
    )
}

pub fn encode_r2_map<C: Ciphersuite>(
    packages: &BTreeMap<Identifier<C>, dkg::round2::Package<C>>,
) -> Result<Vec<u8>, lib_error> {
    codec::encode_map(
        packages,
        |id| Ok(id.serialize()),
        |pkg| pkg.serialize().map_err(ser_err),
    )
}

pub fn decode_r2_map<C: Ciphersuite>(
    data: &[u8],
) -> Result<BTreeMap<Identifier<C>, dkg::round2::Package<C>>, lib_error> {
    codec::decode_map(
        data,
        |b| Identifier::<C>::deserialize(b).map_err(ser_err),
        |b| dkg::round2::Package::<C>::deserialize(b).map_err(ser_err),
    )
}

pub fn dkg_part1<C: Ciphersuite>(
    id: u16,
    max_signers: u16,
    min_signers: u16,
) -> Result<(dkg::round1::SecretPackage<C>, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_DKG_ERROR);
    }

    let ident = Identifier::<C>::try_from(id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let mut rng = rand::thread_rng();
    let (secret, package) =
        dkg::part1::<C, _>(ident, max_signers, min_signers, &mut rng)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let pkg_bytes = package.serialize().map_err(ser_err)?;

    Ok((secret, pkg_bytes))
}

pub fn dkg_part2<C: Ciphersuite>(
    secret: dkg::round1::SecretPackage<C>,
    round1_packages_data: &[u8],
) -> Result<(dkg::round2::SecretPackage<C>, Vec<u8>), lib_error> {
    let r1_pkgs = decode_r1_map::<C>(round1_packages_data)?;

    let (secret2, r2_pkgs) =
        dkg::part2(secret, &r1_pkgs).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let r2_bytes = encode_r2_map::<C>(&r2_pkgs)?;

    Ok((secret2, r2_bytes))
}

pub fn dkg_part3<C: Ciphersuite>(
    secret: dkg::round2::SecretPackage<C>,
    round1_packages_data: &[u8],
    round2_packages_data: &[u8],
) -> Result<(frost_core::keys::KeyPackage<C>, frost_core::keys::PublicKeyPackage<C>), lib_error> {
    let r1_pkgs = decode_r1_map::<C>(round1_packages_data)?;
    let r2_pkgs = decode_r2_map::<C>(round2_packages_data)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    Ok((key_package, pub_key_package))
}
