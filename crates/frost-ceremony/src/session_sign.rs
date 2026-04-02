use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Identifier,
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    SigningPackage,
};
use frost_ffi::errors::lib_error;
use frost_session::relay::FrostChannel;

use crate::blame::frost_err_to_blame;
use crate::dkg::ser_err;

pub async fn sign_run<C: Ciphersuite>(
    key_package: &KeyPackage<C>,
    pub_key_package: &PublicKeyPackage<C>,
    message: &[u8],
    num_signers: usize,
    ch: &FrostChannel,
) -> Result<Vec<u8>, lib_error> {
    let my_ident = *key_package.identifier();

    let (nonces, commitments, commit_bytes) = {
        let mut rng = rand::thread_rng();
        let (n, c) = frost_core::round1::commit::<C, _>(key_package.signing_share(), &mut rng);
        let bytes = c.serialize().map_err(ser_err)?;
        (n, c, bytes)
    };
    ch.broadcast(commit_bytes).await;

    let mut commit_map: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();
    commit_map.insert(my_ident, commitments);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Identifier::<C>::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let c = SigningCommitments::<C>::deserialize(&data).map_err(ser_err)?;
        commit_map.insert(sender, c);
    }

    let signing_package = SigningPackage::<C>::new(commit_map, message);

    let share = frost_core::round2::sign(&signing_package, &nonces, key_package)
        .map_err(|e| frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;
    let share_bytes = share.serialize();
    ch.broadcast(share_bytes).await;

    let mut shares: BTreeMap<Identifier<C>, SignatureShare<C>> = BTreeMap::new();
    shares.insert(my_ident, share);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Identifier::<C>::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let s = SignatureShare::<C>::deserialize(&data).map_err(ser_err)?;
        shares.insert(sender, s);
    }

    let signature = frost_core::aggregate(&signing_package, &shares, pub_key_package)
        .map_err(|e| frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

    let sig_bytes = signature.serialize().map_err(ser_err)?;
    Ok(sig_bytes)
}
