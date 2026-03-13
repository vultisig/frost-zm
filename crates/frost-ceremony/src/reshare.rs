use frost_core::{
    Ciphersuite, Field, Group, Identifier, Scalar,
    keys::{dkg, CoefficientCommitment, KeyPackage, PublicKeyPackage, VerifiableSecretSharingCommitment},
};
use frost_ffi::errors::lib_error;

use crate::dkg::{decode_r1_map, decode_r2_map, ser_err};

pub fn decode_old_identifiers<C: Ciphersuite>(
    data: &[u8],
) -> Result<Vec<Identifier<C>>, lib_error> {
    if data.len() % 2 != 0 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = data.len() / 2;
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let raw = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        let id = Identifier::<C>::try_from(raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        ids.push(id);
    }
    Ok(ids)
}

pub fn lagrange_coeff<C: Ciphersuite>(
    my_id: &Identifier<C>,
    all_ids: &[Identifier<C>],
) -> Result<Scalar<C>, lib_error> {
    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;

    let xi = my_id.to_scalar();
    let mut num = F::<C>::one();
    let mut den = F::<C>::one();
    for id in all_ids {
        if id == my_id {
            continue;
        }
        let xj = id.to_scalar();
        num = num * xj;
        den = den * (xj - xi);
    }
    let den_inv = F::<C>::invert(&den).map_err(|_| lib_error::LIB_RESHARE_ERROR)?;
    Ok(num * den_inv)
}

pub fn compute_additive_share<C: Ciphersuite>(
    key_package: &KeyPackage<C>,
    old_ids: &[Identifier<C>],
    max_signers: u16,
) -> Result<Scalar<C>, lib_error> {
    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;

    if old_ids.len() as u16 > max_signers {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    let di = key_package.signing_share().to_scalar();
    let li = lagrange_coeff::<C>(key_package.identifier(), old_ids)?;
    let mut share = di * li;

    let num_new = max_signers - old_ids.len() as u16;
    let min_old_id = old_ids.iter().min().ok_or(lib_error::LIB_RESHARE_ERROR)?;
    if key_package.identifier() == min_old_id {
        for _ in 0..num_new {
            share = share - F::<C>::one();
        }
    }

    Ok(share)
}

pub fn reshare_part1<C: Ciphersuite>(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    additive_share: Scalar<C>,
) -> Result<(dkg::round1::SecretPackage<C>, Vec<u8>), lib_error> {
    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;
    type G<C> = <C as Ciphersuite>::Group;

    let ident = Identifier::<C>::try_from(id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let mut rng = rand::thread_rng();

    let mut coefficients = Vec::with_capacity(min_signers as usize);
    coefficients.push(additive_share);
    for _ in 1..min_signers {
        coefficients.push(F::<C>::random(&mut rng));
    }

    let commitments: Vec<CoefficientCommitment<C>> = coefficients
        .iter()
        .map(|c| CoefficientCommitment::new(G::<C>::generator() * *c))
        .collect();

    let commitment = VerifiableSecretSharingCommitment::new(commitments);

    let proof =
        dkg::compute_proof_of_knowledge::<C, _>(ident, &coefficients, &commitment, &mut rng)
            .map_err(|_| lib_error::LIB_RESHARE_ERROR)?;

    let secret = dkg::round1::SecretPackage::new(
        ident,
        coefficients.clone(),
        commitment.clone(),
        min_signers,
        max_signers,
    );

    for coeff in &mut coefficients {
        *coeff = F::<C>::zero();
    }

    let package = dkg::round1::Package::new(commitment, proof);
    let pkg_bytes = package.serialize().map_err(ser_err)?;

    Ok((secret, pkg_bytes))
}

pub fn reshare_part3<C: Ciphersuite>(
    secret: dkg::round2::SecretPackage<C>,
    round1_packages_data: &[u8],
    round2_packages_data: &[u8],
    expected_verifying_key: &[u8],
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), lib_error> {
    let r1_pkgs = decode_r1_map::<C>(round1_packages_data)?;
    let r2_pkgs = decode_r2_map::<C>(round2_packages_data)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_verifying_key) {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    Ok((key_package, pub_key_package))
}
