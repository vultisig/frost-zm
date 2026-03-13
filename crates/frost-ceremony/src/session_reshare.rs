use std::collections::BTreeMap;

use frost_core::{Ciphersuite, Identifier, Scalar, keys::dkg};
use frost_ffi::errors::lib_error;
use frost_session::relay::FrostChannel;

use crate::dkg::ser_err;
use crate::reshare::reshare_part1;
use crate::session_dkg::{build_id_map, lookup_u16};

pub async fn reshare_run<C: Ciphersuite>(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    additive_share: Scalar<C>,
    expected_vk: &[u8],
    ch: &FrostChannel,
) -> Result<(frost_core::keys::KeyPackage<C>, frost_core::keys::PublicKeyPackage<C>), lib_error> {
    let id_map = build_id_map::<C>(max_signers)?;

    let (secret1, r1_bytes) = reshare_part1::<C>(
        my_id, max_signers, min_signers, additive_share,
    )?;

    ch.broadcast(r1_bytes).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_map = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Identifier::<C>::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round1::Package::<C>::deserialize(&data).map_err(ser_err)?;
        r1_map.insert(sender, pkg);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = lookup_u16::<C>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Identifier::<C>::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<C>::deserialize(&data).map_err(ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    Ok((key_package, pub_key_package))
}
