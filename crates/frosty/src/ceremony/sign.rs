use frost_core::SigningPackage;
use frost_core::Ciphersuite;

use crate::bundle::{BundleMetadata, KeyShareBundle};
use crate::ceremony::dkg::ser_err;
use crate::errors::lib_error;

pub struct SignNonces<C: Ciphersuite> {
    pub nonces: frost_core::round1::SigningNonces<C>,
}

pub fn sign_commit<C: Ciphersuite, M: BundleMetadata>(
    key_share_data: &[u8],
) -> Result<(SignNonces<C>, Vec<u8>), lib_error> {
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;

    let (nonces, commitments_bytes) =
        frost_ceremony::sign::sign_commit::<C>(&bundle.key_package)?;

    Ok((SignNonces { nonces }, commitments_bytes))
}

pub fn sign_create_package<C: Ciphersuite>(
    message: &[u8],
    commitments_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    frost_ceremony::sign::sign_create_package::<C>(message, commitments_data)
}

pub fn sign<C: Ciphersuite, M: BundleMetadata>(
    signing_package_data: &[u8],
    nonces: SignNonces<C>,
    key_share_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    let sp = SigningPackage::<C>::deserialize(signing_package_data).map_err(ser_err)?;
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;

    frost_ceremony::sign::sign::<C>(&sp, &nonces.nonces, &bundle.key_package)
}

pub fn sign_aggregate<C: Ciphersuite, M: BundleMetadata>(
    signing_package_data: &[u8],
    shares_data: &[u8],
    key_share_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    let sp = SigningPackage::<C>::deserialize(signing_package_data).map_err(ser_err)?;
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;

    frost_ceremony::sign::sign_aggregate::<C>(&sp, shares_data, &bundle.pub_key_package)
}

pub fn verify_signature<C: Ciphersuite, M: BundleMetadata>(
    message: &[u8],
    signature_data: &[u8],
    key_share_data: &[u8],
) -> Result<(), lib_error> {
    let bundle = KeyShareBundle::<C, M>::deserialize(key_share_data)?;
    let sig = frost_core::Signature::<C>::deserialize(signature_data).map_err(ser_err)?;

    bundle
        .pub_key_package
        .verifying_key()
        .verify(message, &sig)
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)
}
