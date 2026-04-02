use frost_core::{
    Ciphersuite, Field, Group, Identifier, Scalar,
    keys::{dkg, CoefficientCommitment, KeyPackage, PublicKeyPackage, VerifiableSecretSharingCommitment},
};
use frost_ffi::errors::lib_error;

use crate::blame::frost_err_to_blame;
use crate::dkg::{decode_r1_map, decode_r2_map, ser_err};

pub fn key_import_part1<C: Ciphersuite>(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    constant_term: Scalar<C>,
) -> Result<(dkg::round1::SecretPackage<C>, Vec<u8>), lib_error> {
    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;
    type G<C> = <C as Ciphersuite>::Group;

    let ident = Identifier::<C>::try_from(id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let mut rng = rand::thread_rng();

    let mut coefficients = Vec::with_capacity(min_signers as usize);
    coefficients.push(constant_term);
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
            .map_err(|e| frost_err_to_blame(e, lib_error::LIB_KEY_IMPORT_ERROR))?;

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

pub fn key_import_part3<C: Ciphersuite>(
    secret: dkg::round2::SecretPackage<C>,
    round1_packages_data: &[u8],
    round2_packages_data: &[u8],
    expected_verifying_key: &[u8],
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), lib_error> {
    let r1_pkgs = decode_r1_map::<C>(round1_packages_data)?;
    let r2_pkgs = decode_r2_map::<C>(round2_packages_data)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret, &r1_pkgs, &r2_pkgs)
            .map_err(|e| frost_err_to_blame(e, lib_error::LIB_DKG_ERROR))?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_verifying_key) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    Ok((key_package, pub_key_package))
}

pub fn derive_constant_term<C: Ciphersuite>(
    sk_scalar: Scalar<C>,
    max_signers: u16,
) -> Scalar<C> {
    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;

    let num_others = (max_signers - 1) as u64;
    let mut result = sk_scalar;
    for _ in 0..num_others {
        result = result - F::<C>::one();
    }
    result
}
