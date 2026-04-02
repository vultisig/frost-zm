use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Identifier,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    SigningPackage,
};
use frost_ffi::{codec, errors::lib_error};

use crate::blame::frost_err_to_blame;
use crate::dkg::ser_err;

fn decode_commitments_map<C: Ciphersuite>(
    data: &[u8],
) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, lib_error> {
    codec::decode_map(
        data,
        |b| Identifier::<C>::deserialize(b).map_err(ser_err),
        |b| SigningCommitments::<C>::deserialize(b).map_err(ser_err),
    )
}

fn decode_shares_map<C: Ciphersuite>(
    data: &[u8],
) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, lib_error> {
    codec::decode_map(
        data,
        |b| Identifier::<C>::deserialize(b).map_err(ser_err),
        |b| SignatureShare::<C>::deserialize(b).map_err(ser_err),
    )
}

pub fn sign_commit<C: Ciphersuite>(
    key_package: &KeyPackage<C>,
) -> Result<(SigningNonces<C>, Vec<u8>), lib_error> {
    let mut rng = rand::thread_rng();
    let (nonces, commitments) = frost_core::round1::commit(key_package.signing_share(), &mut rng);

    let commitments_bytes = commitments.serialize().map_err(ser_err)?;

    Ok((nonces, commitments_bytes))
}

pub fn sign_create_package<C: Ciphersuite>(
    message: &[u8],
    commitments_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    let commitments = decode_commitments_map::<C>(commitments_data)?;
    let signing_package = SigningPackage::<C>::new(commitments, message);
    let sp_bytes = signing_package.serialize().map_err(ser_err)?;
    Ok(sp_bytes)
}

pub fn sign<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    nonces: &SigningNonces<C>,
    key_package: &KeyPackage<C>,
) -> Result<Vec<u8>, lib_error> {
    let share =
        frost_core::round2::sign(signing_package, nonces, key_package)
            .map_err(|e| frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

    let share_bytes = share.serialize();

    Ok(share_bytes)
}

pub fn sign_aggregate<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    shares_data: &[u8],
    pub_key_package: &PublicKeyPackage<C>,
) -> Result<Vec<u8>, lib_error> {
    let shares = decode_shares_map::<C>(shares_data)?;

    let signature =
        frost_core::aggregate(signing_package, &shares, pub_key_package)
            .map_err(|e| frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

    let sig_bytes = signature.serialize().map_err(ser_err)?;

    Ok(sig_bytes)
}
