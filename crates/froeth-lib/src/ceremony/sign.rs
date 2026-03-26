use frost_core::SigningPackage;
use frost_secp256k1::Secp256K1Sha256;

use crate::ceremony::dkg::ser_err;
use crate::errors::lib_error;

type S = Secp256K1Sha256;

pub struct SignNonces {
    pub nonces: frost_core::round1::SigningNonces<S>,
}

pub fn sign_commit(
    key_share_data: &[u8],
) -> Result<(SignNonces, Vec<u8>), lib_error> {
    let bundle = crate::keyshare::bundle::KeyShareBundle::deserialize(key_share_data)?;

    let (nonces, commitments_bytes) =
        frost_ceremony::sign::sign_commit::<S>(&bundle.key_package)?;

    Ok((SignNonces { nonces }, commitments_bytes))
}

pub fn sign_create_package(
    message: &[u8],
    commitments_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    frost_ceremony::sign::sign_create_package::<S>(message, commitments_data)
}

pub fn sign(
    signing_package_data: &[u8],
    nonces: SignNonces,
    key_share_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    let sp = SigningPackage::<S>::deserialize(signing_package_data).map_err(ser_err)?;
    let bundle = crate::keyshare::bundle::KeyShareBundle::deserialize(key_share_data)?;

    frost_ceremony::sign::sign::<S>(&sp, &nonces.nonces, &bundle.key_package)
}

pub fn sign_aggregate(
    signing_package_data: &[u8],
    shares_data: &[u8],
    key_share_data: &[u8],
) -> Result<Vec<u8>, lib_error> {
    let sp = SigningPackage::<S>::deserialize(signing_package_data).map_err(ser_err)?;
    let bundle = crate::keyshare::bundle::KeyShareBundle::deserialize(key_share_data)?;

    frost_ceremony::sign::sign_aggregate::<S>(&sp, shares_data, &bundle.pub_key_package)
}

pub fn verify_signature(
    message: &[u8],
    signature_data: &[u8],
    key_share_data: &[u8],
) -> Result<(), lib_error> {
    let bundle = crate::keyshare::bundle::KeyShareBundle::deserialize(key_share_data)?;
    let sig = frost_core::Signature::<S>::deserialize(signature_data).map_err(ser_err)?;

    bundle
        .pub_key_package
        .verifying_key()
        .verify(message, &sig)
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::{encode_test_map, run_dkg};

    pub fn run_sign(bundles: &[Vec<u8>], signer_indices: &[usize]) -> Vec<u8> {
        let signer_ids: Vec<u16> =
            signer_indices.iter().map(|i| (*i + 1) as u16).collect();

        let mut nonces_list = Vec::new();
        let mut commitments_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for &idx in signer_indices {
            let (nonces, commitments_bytes) =
                sign_commit(&bundles[idx]).unwrap();
            nonces_list.push(nonces);
            commitments_entries
                .push((signer_ids[commitments_entries.len()], commitments_bytes));
        }

        let commitments_map = encode_test_map(&commitments_entries);
        let message = b"test message for froeth signing";
        let sp_bytes = sign_create_package(message.as_ref(), &commitments_map).unwrap();

        let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for (i, &idx) in signer_indices.iter().enumerate() {
            let nonces = nonces_list.remove(0);
            let share_bytes = sign(&sp_bytes, nonces, &bundles[idx]).unwrap();
            share_entries.push((signer_ids[i], share_bytes));
        }

        let shares_map = encode_test_map(&share_entries);
        let sig_bytes =
            sign_aggregate(&sp_bytes, &shares_map, &bundles[signer_indices[0]])
                .unwrap();
        assert!(!sig_bytes.is_empty());
        sig_bytes
    }

    #[test]
    fn test_sign_2x3() {
        let bundles = run_dkg(3, 2);
        run_sign(&bundles, &[0, 1]);
        run_sign(&bundles, &[1, 2]);
        run_sign(&bundles, &[0, 2]);
    }

    #[test]
    fn test_sign_and_verify() {
        let bundles = run_dkg(3, 2);
        let message = b"test message for froeth signing";

        let sig01 = run_sign(&bundles, &[0, 1]);
        verify_signature(message.as_ref(), &sig01, &bundles[0]).unwrap();

        let sig12 = run_sign(&bundles, &[1, 2]);
        verify_signature(message.as_ref(), &sig12, &bundles[1]).unwrap();

        let sig02 = run_sign(&bundles, &[0, 2]);
        verify_signature(message.as_ref(), &sig02, &bundles[0]).unwrap();

        let wrong = b"wrong message";
        assert!(verify_signature(wrong.as_ref(), &sig01, &bundles[0]).is_err());
    }
}
