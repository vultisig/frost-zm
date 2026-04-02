use std::collections::{BTreeMap, HashMap};

use frost_core::{Ciphersuite, Identifier, keys::dkg};
use frost_ffi::errors::lib_error;
use frost_session::relay::FrostChannel;

use crate::blame::frost_err_to_blame;
use crate::dkg::ser_err;

pub async fn dkg_run<C: Ciphersuite>(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    ch: &FrostChannel,
) -> Result<(frost_core::keys::KeyPackage<C>, frost_core::keys::PublicKeyPackage<C>), lib_error> {
    let id_map = build_id_map::<C>(max_signers)?;
    let ident = Identifier::<C>::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (secret1, r1_bytes) = {
        let mut rng = rand::thread_rng();
        let (secret, package) =
            dkg::part1::<C, _>(ident, max_signers, min_signers, &mut rng)
                .map_err(|e| frost_err_to_blame(e, lib_error::LIB_DKG_ERROR))?;
        let bytes = package.serialize().map_err(ser_err)?;
        (secret, bytes)
    };
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
        dkg::part2(secret1, &r1_map).map_err(|e| frost_err_to_blame(e, lib_error::LIB_DKG_ERROR))?;

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
            .map_err(|e| frost_err_to_blame(e, lib_error::LIB_DKG_ERROR))?;

    Ok((key_package, pub_key_package))
}

pub fn build_id_map<C: Ciphersuite>(
    max_signers: u16,
) -> Result<HashMap<Vec<u8>, u16>, lib_error> {
    let mut map = HashMap::with_capacity(max_signers as usize);
    for i in 1..=max_signers {
        let id = Identifier::<C>::try_from(i)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        map.insert(id.serialize(), i);
    }
    Ok(map)
}

pub fn lookup_u16<C: Ciphersuite>(
    map: &HashMap<Vec<u8>, u16>,
    id: &Identifier<C>,
) -> Result<u16, lib_error> {
    map.get(&id.serialize())
        .copied()
        .ok_or(lib_error::LIB_INVALID_IDENTIFIER)
}
