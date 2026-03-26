use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Field, Group, Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use frost_secp256k1::Secp256K1Sha256;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
    ceremony::dkg::{CC_LEN, aggregate_chain_code_shares, ser_err as dkg_ser_err},
};

use frost_session::{
    message,
    relay::FrostChannel,
    session::{Ceremony, Protocol},
    setup::{SetupMsg, SignSetup, ReshareSetup, KeyImportSetup},
};

type S = Secp256K1Sha256;
type Ident = Identifier<S>;
type Scalar = frost_core::Scalar<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;

struct DkgSessionState {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

async fn frobt_dkg_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, lib_error> {
    let id_map = frost_ceremony::session_dkg::build_id_map::<S>(max_signers)?;
    let ident = Ident::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (secret1, r1_combined, cc_share_bytes) = {
        let mut rng = rand::thread_rng();

        let (secret, package) =
            dkg::part1::<S, _>(ident, max_signers, min_signers, &mut rng)
                .map_err(|_| lib_error::LIB_DKG_ERROR)?;
        let mut bytes = package.serialize().map_err(dkg_ser_err)?;

        let cc_share: Scalar = F::random(&mut rng);
        let cc_bytes: [u8; CC_LEN] = {
            let s = F::serialize(&cc_share);
            let sl: &[u8] = s.as_ref();
            sl.try_into()
                .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
        };

        bytes.extend_from_slice(&cc_bytes);
        (secret, bytes, cc_bytes)
    };
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < CC_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - CC_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; CC_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<S>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        cc_shares_map.insert(sender, cc_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<S>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<S>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let mut cc_share_local = cc_share_bytes;
    let mut chain_code = aggregate_chain_code_shares(&cc_share_local, &cc_shares_map)?;
    cc_share_local.iter_mut().for_each(|b| *b = 0);

    let bundle = crate::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );
    chain_code.iter_mut().for_each(|b| *b = 0);

    bundle.serialize()
}

struct SignSessionState {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

struct ReshareSessionState {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

fn msg_receiver_impl(setup: &SetupMsg, my_id: u16, msg: &[u8], index: u32) -> Option<Vec<u8>> {
    let recipient = message::read_recipient(msg);
    if recipient == 0 {
        let others = setup.other_party_ids(my_id);
        others.get(index as usize).and_then(|&fid| setup.party_name(fid)).map(|n| n.to_vec())
    } else if index == 0 {
        setup.party_name(recipient).map(|n| n.to_vec())
    } else {
        None
    }
}

fn ser_err<T: std::fmt::Debug>(e: T) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frobt session serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

// === DKG Session FFI ===

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_setupmsg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: Option<&go_slice>,
    network: u8,
    birthday: u64,
    out_setup: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pd = parties_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_setup.ok_or(lib_error::LIB_NULL_PTR)?;
        let parties = decode_parties(pd.as_slice())?;
        let setup = SetupMsg { max_signers, min_signers, parties };
        let mut buf = setup.encode();
        buf.push(network);
        buf.extend_from_slice(&birthday.to_le_bytes());
        *out = tss_buffer::from_vec(buf);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_from_setup(
    setup_data: Option<&go_slice>,
    my_party_name: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let sd = setup_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let name = my_party_name.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let data = sd.as_slice();
        let (setup, consumed) = SetupMsg::decode(data)?;
        if consumed + 1 + 8 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let network = data[consumed];
        let birthday = u64::from_le_bytes(
            data[consumed + 1..consumed + 9].try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
        );

        let my_id = setup.frost_id_by_name(name.as_slice())
            .ok_or(lib_error::LIB_INVALID_IDENTIFIER)?;

        let max = setup.max_signers;
        let min = setup.min_signers;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_dkg_run(my_id, max, min, network, birthday, &ch).await
            }));

        let state = DkgSessionState { protocol, setup, my_id };
        *out = Handle::allocate(state)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_feed(
    session: Handle,
    msg: Option<&go_slice>,
    out_finished: Option<&mut i32>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let finished = out_finished.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<DkgSessionState>()?;
        let done = state.protocol.feed(msg_data.as_slice().to_vec());
        *finished = if done { 1 } else { 0 };
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_take_msg(
    session: Handle,
    out_message: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_message.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<DkgSessionState>()?;
        match state.protocol.take_msg() {
            Some(msg) => *out = tss_buffer::from_vec(msg),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_msg_receiver(
    session: Handle,
    msg: Option<&go_slice>,
    index: u32,
    out_receiver: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_receiver.ok_or(lib_error::LIB_NULL_PTR)?;
        let state = session.get::<DkgSessionState>()?;
        match msg_receiver_impl(&state.setup, state.my_id, msg_data.as_slice(), index) {
            Some(name) => *out = tss_buffer::from_vec(name),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_result(
    session: Handle,
    out_bundle: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bundle.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.take::<DkgSessionState>()?;
        let bundle_bytes = state.protocol.result()
            .ok_or(lib_error::LIB_SESSION_NOT_READY)?
            .map_err(|e| e)?;
        *out = tss_buffer::from_vec(bundle_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_dkg_session_free(session: Handle) -> lib_error {
    with_error_handler(|| {
        let _ = session.take::<DkgSessionState>()?;
        Ok(())
    })
}

// === Sign Session FFI ===

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_setupmsg_new(
    msg_to_sign: Option<&go_slice>,
    parties_data: Option<&go_slice>,
    out_setup: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg = msg_to_sign.ok_or(lib_error::LIB_NULL_PTR)?;
        let pd = parties_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_setup.ok_or(lib_error::LIB_NULL_PTR)?;
        let parties = decode_parties(pd.as_slice())?;
        let num = parties.len() as u16;
        let setup = SignSetup {
            base: SetupMsg { max_signers: num, min_signers: num, parties },
            message: msg.as_slice().to_vec(),
        };
        *out = tss_buffer::from_vec(setup.encode());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_from_setup(
    setup_data: Option<&go_slice>,
    my_party_name: Option<&go_slice>,
    key_package: Option<&go_slice>,
    pub_key_package: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let sd = setup_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let name = my_party_name.ok_or(lib_error::LIB_NULL_PTR)?;
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let sign_setup = SignSetup::decode(sd.as_slice())?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(name.as_slice())
            .ok_or(lib_error::LIB_INVALID_IDENTIFIER)?;

        let kp = KeyPackage::<S>::deserialize(kp_data.as_slice()).map_err(ser_err)?;
        let pkp = PublicKeyPackage::<S>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;

        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_sign::sign_run::<S>(
                    &kp, &pkp, &msg_to_sign, num_signers, &ch,
                ).await
            }));

        let state = SignSessionState { protocol, setup, my_id };
        *out = Handle::allocate(state)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_feed(
    session: Handle,
    msg: Option<&go_slice>,
    out_finished: Option<&mut i32>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let finished = out_finished.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<SignSessionState>()?;
        let done = state.protocol.feed(msg_data.as_slice().to_vec());
        *finished = if done { 1 } else { 0 };
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_take_msg(
    session: Handle,
    out_message: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_message.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<SignSessionState>()?;
        match state.protocol.take_msg() {
            Some(msg) => *out = tss_buffer::from_vec(msg),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_msg_receiver(
    session: Handle,
    msg: Option<&go_slice>,
    index: u32,
    out_receiver: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_receiver.ok_or(lib_error::LIB_NULL_PTR)?;
        let state = session.get::<SignSessionState>()?;
        match msg_receiver_impl(&state.setup, state.my_id, msg_data.as_slice(), index) {
            Some(name) => *out = tss_buffer::from_vec(name),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_result(
    session: Handle,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.take::<SignSessionState>()?;
        let sig = state.protocol.result()
            .ok_or(lib_error::LIB_SESSION_NOT_READY)?
            .map_err(|e| e)?;
        *out = tss_buffer::from_vec(sig);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_session_free(session: Handle) -> lib_error {
    with_error_handler(|| {
        let _ = session.take::<SignSessionState>()?;
        Ok(())
    })
}

// === Reshare Session FFI ===

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_setupmsg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: Option<&go_slice>,
    old_identifiers: Option<&go_slice>,
    expected_vk: Option<&go_slice>,
    out_setup: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pd = parties_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let oi = old_identifiers.ok_or(lib_error::LIB_NULL_PTR)?;
        let vk = expected_vk.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_setup.ok_or(lib_error::LIB_NULL_PTR)?;

        let parties = decode_parties(pd.as_slice())?;
        let old_ids = decode_u16_list(oi.as_slice())?;

        let setup = ReshareSetup {
            base: SetupMsg { max_signers, min_signers, parties },
            old_identifiers: old_ids,
            expected_vk: vk.as_slice().to_vec(),
        };
        *out = tss_buffer::from_vec(setup.encode());
        Ok(())
    })
}

async fn frobt_reshare_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    additive_share: Scalar,
    chain_code_bytes: [u8; CC_LEN],
    expected_vk: Vec<u8>,
    ch: &FrostChannel,
) -> Result<(KeyPackage<S>, PublicKeyPackage<S>, [u8; CC_LEN]), lib_error> {
    let id_map = frost_ceremony::session_dkg::build_id_map::<S>(max_signers)?;

    let (secret1, r1_frost_bytes) =
        frost_ceremony::reshare::reshare_part1::<S>(my_id, max_signers, min_signers, additive_share)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&chain_code_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < CC_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - CC_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; CC_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<S>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        cc_shares_map.insert(sender, cc_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<S>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<S>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), &expected_vk) {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    let chain_code = aggregate_reshare_chain_code(&chain_code_bytes, &cc_shares_map)?;

    Ok((key_package, pub_key_package, chain_code))
}

fn aggregate_reshare_chain_code(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Ident, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], lib_error> {
    let zero = [0u8; CC_LEN];
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    if *own_share != zero {
        return Ok(*own_share);
    }
    Err(lib_error::LIB_RESHARE_ERROR)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_from_setup(
    setup_data: Option<&go_slice>,
    my_party_name: Option<&go_slice>,
    old_bundle_data: Option<&go_slice>,
    network: u8,
    birthday: u64,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let sd = setup_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let name = my_party_name.ok_or(lib_error::LIB_NULL_PTR)?;
        let obd = old_bundle_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let reshare_setup = ReshareSetup::decode(sd.as_slice())?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(name.as_slice())
            .ok_or(lib_error::LIB_INVALID_IDENTIFIER)?;

        let old_bundle_bytes = obd.as_slice();
        let (additive_share, chain_code_bytes) = if !old_bundle_bytes.is_empty() {
            let bundle = crate::keyshare::bundle::KeyShareBundle::deserialize(old_bundle_bytes)?;
            let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
                .map(|&id| Ident::try_from(id).map_err(|_| lib_error::LIB_INVALID_IDENTIFIER))
                .collect::<Result<_, _>>()?;
            let additive = frost_ceremony::reshare::compute_additive_share::<S>(
                &bundle.key_package, &old_ids, setup.max_signers,
            )?;
            (additive, bundle.chain_code)
        } else {
            (F::one(), [0u8; CC_LEN])
        };

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;
        let net = network;
        let bday = birthday;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                let (kp, pkp, chain_code) = frobt_reshare_run(
                    my_id, max, min, additive_share, chain_code_bytes,
                    expected_vk, &ch,
                ).await?;

                let bundle = crate::keyshare::bundle::KeyShareBundle::new(
                    kp, pkp, chain_code, net, bday,
                );
                bundle.serialize()
            }));

        let state = ReshareSessionState { protocol, setup, my_id };
        *out = Handle::allocate(state)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_feed(
    session: Handle,
    msg: Option<&go_slice>,
    out_finished: Option<&mut i32>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let finished = out_finished.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<ReshareSessionState>()?;
        let done = state.protocol.feed(msg_data.as_slice().to_vec());
        *finished = if done { 1 } else { 0 };
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_take_msg(
    session: Handle,
    out_message: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_message.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<ReshareSessionState>()?;
        match state.protocol.take_msg() {
            Some(msg) => *out = tss_buffer::from_vec(msg),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_msg_receiver(
    session: Handle,
    msg: Option<&go_slice>,
    index: u32,
    out_receiver: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_receiver.ok_or(lib_error::LIB_NULL_PTR)?;
        let state = session.get::<ReshareSessionState>()?;
        match msg_receiver_impl(&state.setup, state.my_id, msg_data.as_slice(), index) {
            Some(name) => *out = tss_buffer::from_vec(name),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_result(
    session: Handle,
    out_bundle: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bundle.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.take::<ReshareSessionState>()?;
        let bundle_bytes = state.protocol.result()
            .ok_or(lib_error::LIB_SESSION_NOT_READY)?
            .map_err(|e| e)?;
        *out = tss_buffer::from_vec(bundle_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_free(session: Handle) -> lib_error {
    with_error_handler(|| {
        let _ = session.take::<ReshareSessionState>()?;
        Ok(())
    })
}

// === Key Import Session FFI ===

struct KeyImportSessionState {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

async fn frobt_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    secret_data: Vec<u8>,
    account_index: u32,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, lib_error> {
    let id_map = frost_ceremony::session_dkg::build_id_map::<S>(max_signers)?;
    let is_seed_holder = my_id == seed_holder_id;

    let (constant_term, cc_share_bytes) = if is_seed_holder {
        let (private_key, chain_code, _pub_key) =
            crate::ceremony::key_import::derive_from_seed(&secret_data, account_index)?;
        let sk_scalar: Scalar = F::deserialize(&private_key).map_err(dkg_ser_err)?;
        let ct = frost_ceremony::key_import::derive_constant_term::<S>(sk_scalar, max_signers);
        (ct, chain_code)
    } else {
        (F::one(), [0u8; CC_LEN])
    };

    let (secret1, r1_frost_bytes) =
        frost_ceremony::key_import::key_import_part1::<S>(my_id, max_signers, min_signers, constant_term)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&cc_share_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < CC_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - CC_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; CC_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<S>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        cc_shares_map.insert(sender, cc_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<S>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<S>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    if is_seed_holder {
        let expected_vk: Vec<u8> = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
        ch.broadcast(expected_vk).await;
    } else {
        let (_sender, expected_vk) = ch.recv().await;
        let actual_vk = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
        if <[u8]>::ne(actual_vk.as_ref(), &expected_vk) {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    let chain_code = aggregate_import_chain_code(&cc_share_bytes, &cc_shares_map)?;

    let bundle = crate::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    bundle.serialize()
}

fn aggregate_import_chain_code(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Ident, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], lib_error> {
    let zero = [0u8; CC_LEN];
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

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_setupmsg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: Option<&go_slice>,
    network: u8,
    birthday: u64,
    seed_holder_id: u16,
    secret_data: Option<&go_slice>,
    account_index: u32,
    out_setup: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pd = parties_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let sd = secret_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_setup.ok_or(lib_error::LIB_NULL_PTR)?;
        let parties = decode_parties(pd.as_slice())?;
        let setup = KeyImportSetup {
            base: SetupMsg { max_signers, min_signers, parties },
            seed_holder_id,
            secret_data: sd.as_slice().to_vec(),
            account_index,
        };
        let mut buf = setup.encode();
        buf.push(network);
        buf.extend_from_slice(&birthday.to_le_bytes());
        *out = tss_buffer::from_vec(buf);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_from_setup(
    setup_data: Option<&go_slice>,
    my_party_name: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let sd = setup_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let name = my_party_name.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let data = sd.as_slice();
        let ki_setup = KeyImportSetup::decode(data)?;
        let consumed = ki_setup.encode().len();
        if consumed + 1 + 8 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let network = data[consumed];
        let birthday = u64::from_le_bytes(
            data[consumed + 1..consumed + 9].try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
        );

        let setup = ki_setup.base;
        let my_id = setup.frost_id_by_name(name.as_slice())
            .ok_or(lib_error::LIB_INVALID_IDENTIFIER)?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let seed_holder_id = ki_setup.seed_holder_id;
        let secret_data = ki_setup.secret_data;
        let acct_idx = ki_setup.account_index;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_key_import_run(
                    my_id, max, min, seed_holder_id, secret_data,
                    acct_idx, network, birthday, &ch,
                ).await
            }));

        let state = KeyImportSessionState { protocol, setup, my_id };
        *out = Handle::allocate(state)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_feed(
    session: Handle,
    msg: Option<&go_slice>,
    out_finished: Option<&mut i32>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let finished = out_finished.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<KeyImportSessionState>()?;
        let done = state.protocol.feed(msg_data.as_slice().to_vec());
        *finished = if done { 1 } else { 0 };
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_take_msg(
    session: Handle,
    out_message: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_message.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.get::<KeyImportSessionState>()?;
        match state.protocol.take_msg() {
            Some(msg) => *out = tss_buffer::from_vec(msg),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_msg_receiver(
    session: Handle,
    msg: Option<&go_slice>,
    index: u32,
    out_receiver: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg_data = msg.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_receiver.ok_or(lib_error::LIB_NULL_PTR)?;
        let state = session.get::<KeyImportSessionState>()?;
        match msg_receiver_impl(&state.setup, state.my_id, msg_data.as_slice(), index) {
            Some(name) => *out = tss_buffer::from_vec(name),
            None => *out = tss_buffer::empty(),
        }
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_result(
    session: Handle,
    out_bundle: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bundle.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut state = session.take::<KeyImportSessionState>()?;
        let bundle_bytes = state.protocol.result()
            .ok_or(lib_error::LIB_SESSION_NOT_READY)?
            .map_err(|e| e)?;
        *out = tss_buffer::from_vec(bundle_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_session_free(session: Handle) -> lib_error {
    with_error_handler(|| {
        let _ = session.take::<KeyImportSessionState>()?;
        Ok(())
    })
}

// === Helpers ===

fn decode_parties(data: &[u8]) -> Result<Vec<frost_session::setup::PartyEntry>, lib_error> {
    use frost_session::setup::PartyEntry;

    if data.len() < 2 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut parties = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + name_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        parties.push(PartyEntry { frost_id, name });
    }
    Ok(parties)
}

fn decode_u16_list(data: &[u8]) -> Result<Vec<u16>, lib_error> {
    if data.len() < 2 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        list.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_session::setup::PartyEntry;
    use crate::keyshare::bundle::KeyShareBundle;

    const TEST_NETWORK: u8 = 0;
    const TEST_BIRTHDAY: u64 = 0;

    fn make_setup_bytes(n: u16, t: u16) -> Vec<u8> {
        let mut parties = Vec::new();
        for i in 1..=n {
            parties.push(PartyEntry {
                frost_id: i,
                name: format!("party-{}", i).into_bytes(),
            });
        }
        let setup = SetupMsg { max_signers: n, min_signers: t, parties };
        let mut buf = setup.encode();
        buf.push(TEST_NETWORK);
        buf.extend_from_slice(&TEST_BIRTHDAY.to_le_bytes());
        buf
    }

    fn run_n_party_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
        let setup_bytes = make_setup_bytes(n, t);

        let sessions: Vec<_> = (1..=n).map(|i| {
            let my_name = format!("party-{}", i);
            let setup_slice = go_slice::from(setup_bytes.as_slice());
            let name_bytes = my_name.into_bytes();
            let name_slice = go_slice::from(name_bytes.as_slice());

            let mut handle = Handle::null();
            let res = frobt_dkg_session_from_setup(
                Some(&setup_slice), Some(&name_slice), Some(&mut handle),
            );
            assert_eq!(res, lib_error::LIB_OK, "session_from_setup failed for party {}", i);
            (i, handle)
        }).collect();

        let mut finished = vec![false; n as usize];
        let mut results = vec![None; n as usize];

        for _round in 0..50 {
            if finished.iter().all(|f| *f) {
                break;
            }

            let mut outgoing: Vec<(usize, Vec<u8>)> = Vec::new();

            for idx in 0..n as usize {
                let (_id, handle) = &sessions[idx];
                loop {
                    let mut msg_buf = tss_buffer::empty();
                    let res = frobt_dkg_session_take_msg(*handle, Some(&mut msg_buf));
                    assert_eq!(res, lib_error::LIB_OK);
                    let msg_bytes = msg_buf.into_vec();
                    if msg_bytes.is_empty() {
                        break;
                    }
                    outgoing.push((idx, msg_bytes));
                }
            }

            for (sender_idx, msg) in outgoing {
                let sender_id = sessions[sender_idx].0;
                let recipient_raw = message::read_recipient(&msg);
                let payload = message::payload(&msg);

                let targets: Vec<usize> = if recipient_raw == 0 {
                    (0..n as usize).filter(|i| *i != sender_idx).collect()
                } else {
                    (0..n as usize)
                        .filter(|i| sessions[*i].0 == recipient_raw)
                        .collect()
                };

                for target_idx in targets {
                    if finished[target_idx] {
                        continue;
                    }
                    let target_handle = sessions[target_idx].1;
                    let input = frost_session::message::wrap_sender(sender_id, payload);
                    let input_slice = go_slice::from(input.as_slice());
                    let mut done_flag: i32 = 0;
                    let res = frobt_dkg_session_feed(
                        target_handle, Some(&input_slice), Some(&mut done_flag),
                    );
                    assert_eq!(res, lib_error::LIB_OK);
                    if done_flag != 0 {
                        finished[target_idx] = true;
                    }
                }
            }
        }

        assert!(finished.iter().all(|f| *f), "not all parties finished");

        for idx in 0..n as usize {
            let handle = sessions[idx].1;
            let mut bundle_buf = tss_buffer::empty();
            let res = frobt_dkg_session_result(handle, Some(&mut bundle_buf));
            assert_eq!(res, lib_error::LIB_OK);
            results[idx] = Some(bundle_buf.into_vec());
        }

        results.into_iter().map(|r| r.unwrap()).collect()
    }

    fn run_session_loop_generic(
        sessions: &[(u16, Handle)],
        feed_fn: extern "C" fn(Handle, Option<&go_slice>, Option<&mut i32>) -> lib_error,
        take_fn: extern "C" fn(Handle, Option<&mut tss_buffer>) -> lib_error,
    ) -> Vec<bool> {
        let n = sessions.len();
        let mut finished = vec![false; n];

        for _round in 0..50 {
            if finished.iter().all(|f| *f) {
                break;
            }

            let mut outgoing: Vec<(usize, Vec<u8>)> = Vec::new();
            for idx in 0..n {
                let (_id, handle) = &sessions[idx];
                loop {
                    let mut msg_buf = tss_buffer::empty();
                    let res = take_fn(*handle, Some(&mut msg_buf));
                    assert_eq!(res, lib_error::LIB_OK);
                    let msg_bytes = msg_buf.into_vec();
                    if msg_bytes.is_empty() {
                        break;
                    }
                    outgoing.push((idx, msg_bytes));
                }
            }

            for (sender_idx, msg_bytes) in outgoing {
                let sender_id = sessions[sender_idx].0;
                let recipient_raw = message::read_recipient(&msg_bytes);
                let payload = message::payload(&msg_bytes);

                let targets: Vec<usize> = if recipient_raw == 0 {
                    (0..n).filter(|i| *i != sender_idx).collect()
                } else {
                    (0..n).filter(|i| sessions[*i].0 == recipient_raw as u16).collect()
                };

                for target_idx in targets {
                    if finished[target_idx] {
                        continue;
                    }
                    let target_handle = sessions[target_idx].1;
                    let input = frost_session::message::wrap_sender(sender_id, payload);
                    let input_slice = go_slice::from(input.as_slice());
                    let mut done_flag: i32 = 0;
                    let res = feed_fn(target_handle, Some(&input_slice), Some(&mut done_flag));
                    assert_eq!(res, lib_error::LIB_OK);
                    if done_flag != 0 {
                        finished[target_idx] = true;
                    }
                }
            }
        }

        finished
    }

    #[test]
    fn test_session_dkg_2x3() {
        let bundles = run_n_party_dkg(3, 2);
        assert_eq!(bundles.len(), 3);

        let b0 = KeyShareBundle::deserialize(&bundles[0]).unwrap();
        let b1 = KeyShareBundle::deserialize(&bundles[1]).unwrap();
        let b2 = KeyShareBundle::deserialize(&bundles[2]).unwrap();

        assert_eq!(b0.pub_key_package.verifying_key(), b1.pub_key_package.verifying_key());
        assert_eq!(b1.pub_key_package.verifying_key(), b2.pub_key_package.verifying_key());

        assert_eq!(b0.chain_code, b1.chain_code);
        assert_eq!(b1.chain_code, b2.chain_code);

        assert_eq!(b0.network, TEST_NETWORK);
        assert_eq!(b1.network, TEST_NETWORK);

        assert_eq!(b0.birthday, TEST_BIRTHDAY);
        assert_eq!(b1.birthday, TEST_BIRTHDAY);
    }

    #[test]
    fn test_session_dkg_2x2() {
        let bundles = run_n_party_dkg(2, 2);
        assert_eq!(bundles.len(), 2);

        let b0 = KeyShareBundle::deserialize(&bundles[0]).unwrap();
        let b1 = KeyShareBundle::deserialize(&bundles[1]).unwrap();
        assert_eq!(b0.pub_key_package.verifying_key(), b1.pub_key_package.verifying_key());
        assert_eq!(b0.chain_code, b1.chain_code);
        assert_eq!(b0.network, TEST_NETWORK);
        assert_eq!(b0.birthday, TEST_BIRTHDAY);
    }

    #[test]
    fn test_session_sign_2x3() {
        let bundles = run_n_party_dkg(3, 2);

        let parsed: Vec<_> = bundles.iter()
            .map(|b| KeyShareBundle::deserialize(b).unwrap())
            .collect();

        let signer_indices = [0usize, 1];
        let msg_to_sign = b"test message for frobt signing";

        let mut sign_parties = Vec::new();
        for &idx in &signer_indices {
            sign_parties.push(PartyEntry {
                frost_id: (idx + 1) as u16,
                name: format!("party-{}", idx + 1).into_bytes(),
            });
        }

        let sign_setup = SignSetup {
            base: SetupMsg {
                max_signers: signer_indices.len() as u16,
                min_signers: signer_indices.len() as u16,
                parties: sign_parties,
            },
            message: msg_to_sign.to_vec(),
        };
        let sign_setup_bytes = sign_setup.encode();

        let mut sessions: Vec<(u16, Handle)> = Vec::new();
        for &idx in &signer_indices {
            let id = (idx + 1) as u16;
            let my_name = format!("party-{}", id).into_bytes();
            let kp_bytes = parsed[idx].key_package.serialize().unwrap();
            let pkp_bytes = parsed[idx].pub_key_package.serialize().unwrap();

            let setup_slice = go_slice::from(sign_setup_bytes.as_slice());
            let name_slice = go_slice::from(my_name.as_slice());
            let kp_slice = go_slice::from(kp_bytes.as_slice());
            let pkp_slice = go_slice::from(pkp_bytes.as_slice());

            let mut handle = Handle::null();
            let res = frobt_sign_session_from_setup(
                Some(&setup_slice), Some(&name_slice),
                Some(&kp_slice), Some(&pkp_slice),
                Some(&mut handle),
            );
            assert_eq!(res, lib_error::LIB_OK);
            sessions.push((id, handle));
        }

        let n = sessions.len();
        let mut finished = vec![false; n];

        for _round in 0..20 {
            if finished.iter().all(|f| *f) {
                break;
            }

            let mut outgoing: Vec<(usize, Vec<u8>)> = Vec::new();
            for idx in 0..n {
                loop {
                    let mut msg_buf = tss_buffer::empty();
                    frobt_sign_session_take_msg(sessions[idx].1, Some(&mut msg_buf));
                    let msg_bytes = msg_buf.into_vec();
                    if msg_bytes.is_empty() {
                        break;
                    }
                    outgoing.push((idx, msg_bytes));
                }
            }

            for (sender_idx, msg) in outgoing {
                let sender_id = sessions[sender_idx].0;
                let recipient_raw = message::read_recipient(&msg);
                let payload_data = message::payload(&msg);

                let targets: Vec<usize> = if recipient_raw == 0 {
                    (0..n).filter(|i| *i != sender_idx).collect()
                } else {
                    (0..n).filter(|i| sessions[*i].0 == recipient_raw).collect()
                };

                for target_idx in targets {
                    if finished[target_idx] {
                        continue;
                    }
                    let input = frost_session::message::wrap_sender(sender_id, payload_data);
                    let input_slice = go_slice::from(input.as_slice());
                    let mut done_flag: i32 = 0;
                    frobt_sign_session_feed(
                        sessions[target_idx].1, Some(&input_slice), Some(&mut done_flag),
                    );
                    if done_flag != 0 {
                        finished[target_idx] = true;
                    }
                }
            }
        }

        assert!(finished.iter().all(|f| *f), "not all signers finished");

        for idx in 0..n {
            let mut sig_buf = tss_buffer::empty();
            let res = frobt_sign_session_result(sessions[idx].1, Some(&mut sig_buf));
            assert_eq!(res, lib_error::LIB_OK);
            let sig_bytes = sig_buf.into_vec();
            assert!(!sig_bytes.is_empty(), "signature is empty for signer {}", idx);
        }
    }

    #[test]
    fn test_session_key_import_2x3() {
        let seed = [0u8; 64];
        let (_private_key, chain_code, _pub_key) =
            crate::ceremony::key_import::derive_from_seed(&seed, 0).unwrap();

        let mut parties = Vec::new();
        for i in 1..=3u16 {
            parties.push(PartyEntry {
                frost_id: i,
                name: format!("party-{}", i).into_bytes(),
            });
        }

        let setup_per_party: Vec<Vec<u8>> = (1..=3u16).map(|i| {
            let secret_data = if i == 1 { seed.to_vec() } else { vec![] };
            let setup = KeyImportSetup {
                base: SetupMsg { max_signers: 3, min_signers: 2, parties: parties.clone() },
                seed_holder_id: 1,
                secret_data,
                account_index: 0,
            };
            let mut buf = setup.encode();
            buf.push(TEST_NETWORK);
            buf.extend_from_slice(&TEST_BIRTHDAY.to_le_bytes());
            buf
        }).collect();

        let sessions: Vec<_> = (0..3).map(|i| {
            let party_id = (i + 1) as u16;
            let my_name = format!("party-{}", party_id);
            let setup_slice = go_slice::from(setup_per_party[i].as_slice());
            let name_bytes = my_name.into_bytes();
            let name_slice = go_slice::from(name_bytes.as_slice());

            let mut handle = Handle::null();
            let res = frobt_key_import_session_from_setup(
                Some(&setup_slice), Some(&name_slice), Some(&mut handle),
            );
            assert_eq!(res, lib_error::LIB_OK, "key_import session_from_setup failed for party {}", party_id);
            (party_id, handle)
        }).collect();

        let finished = run_session_loop_generic(&sessions, frobt_key_import_session_feed, frobt_key_import_session_take_msg);
        assert!(finished.iter().all(|f| *f), "not all parties finished key import");

        let mut bundles = Vec::new();
        for (_id, handle) in &sessions {
            let mut bundle_buf = tss_buffer::empty();
            let res = frobt_key_import_session_result(*handle, Some(&mut bundle_buf));
            assert_eq!(res, lib_error::LIB_OK);
            bundles.push(bundle_buf.into_vec());
        }

        let b0 = KeyShareBundle::deserialize(&bundles[0]).unwrap();
        let b1 = KeyShareBundle::deserialize(&bundles[1]).unwrap();
        let b2 = KeyShareBundle::deserialize(&bundles[2]).unwrap();

        assert_eq!(b0.pub_key_package.verifying_key(), b1.pub_key_package.verifying_key());
        assert_eq!(b1.pub_key_package.verifying_key(), b2.pub_key_package.verifying_key());

        assert_eq!(b0.chain_code, b1.chain_code);
        assert_eq!(b1.chain_code, b2.chain_code);
        assert_eq!(b0.chain_code, chain_code);

        assert_eq!(b0.network, TEST_NETWORK);
        assert_eq!(b0.birthday, TEST_BIRTHDAY);
    }
}
