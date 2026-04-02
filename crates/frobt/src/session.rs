use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Field, Group, Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use frost_secp256k1::Secp256K1Sha256;

use crate::bytes::*;
use crate::errors::*;
use crate::handle::Handle;
use frosty::bundle::{BundleMetadata, ChainCodeMeta};
use frosty::ceremony::dkg::{
    EXTRA_LEN, aggregate_extra_shares, ser_err as dkg_ser_err, deserialize_scalar,
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

struct SignSessionState {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

struct ReshareSessionState {
    protocol: Box<dyn Ceremony<Result<(KeyPackage<S>, PublicKeyPackage<S>), lib_error>> + Send>,
    setup: SetupMsg,
    my_id: u16,
}

struct KeyImportSessionState {
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

// === DKG async run ===

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
        let cc_bytes: [u8; EXTRA_LEN] = frosty::ceremony::dkg::serialize_scalar::<S>(&cc_share)?;

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

        if data.len() < EXTRA_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - EXTRA_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; EXTRA_LEN] = data[frost_len..]
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

    let chain_code = aggregate_extra_shares::<S>(&cc_share_bytes, &cc_shares_map)?;
    let metadata = ChainCodeMeta::from_dkg(chain_code, network, birthday);

    let bundle = frosty::bundle::KeyShareBundle::new(key_package, pub_key_package, metadata);
    bundle.serialize()
}

// === Key Import async run ===

async fn frobt_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    private_key: Vec<u8>,
    chain_code: Vec<u8>,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, lib_error> {
    let is_seed_holder = my_id == seed_holder_id;
    let id_map = frost_ceremony::session_dkg::build_id_map::<S>(max_signers)?;

    let (constant_term, cc_bytes) = if is_seed_holder {
        let sk_bytes: &[u8; 32] = private_key.as_slice().try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
        let sk_scalar: Scalar = deserialize_scalar::<S>(sk_bytes)?;
        let ct = frost_ceremony::key_import::derive_constant_term::<S>(sk_scalar, max_signers);
        let cc: [u8; 32] = chain_code.as_slice().try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
        (ct, cc)
    } else {
        (F::one(), [0u8; 32])
    };

    let (secret1, r1_frost_bytes) =
        frost_ceremony::key_import::key_import_part1::<S>(my_id, max_signers, min_signers, constant_term)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&cc_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < EXTRA_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - EXTRA_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; EXTRA_LEN] = data[frost_len..]
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

    let zero = [0u8; EXTRA_LEN];
    let resolved_cc = if cc_bytes != zero {
        cc_bytes
    } else {
        let mut found = None;
        for share in cc_shares_map.values() {
            if *share != zero {
                found = Some(*share);
                break;
            }
        }
        found.ok_or(lib_error::LIB_KEY_IMPORT_ERROR)?
    };

    let metadata = ChainCodeMeta::from_dkg(resolved_cc, network, birthday);
    let bundle = frosty::bundle::KeyShareBundle::new(key_package, pub_key_package, metadata);
    bundle.serialize()
}

// === Reshare async run ===

async fn frobt_reshare_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    additive_share: Scalar,
    cc_bytes: [u8; EXTRA_LEN],
    expected_vk: Vec<u8>,
    ch: &FrostChannel,
) -> Result<(KeyPackage<S>, PublicKeyPackage<S>), lib_error> {
    let id_map = frost_ceremony::session_dkg::build_id_map::<S>(max_signers)?;

    let (secret1, r1_frost_bytes) =
        frost_ceremony::reshare::reshare_part1::<S>(my_id, max_signers, min_signers, additive_share)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&cc_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut cc_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < EXTRA_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - EXTRA_LEN;
        let frost_data = &data[..frost_len];
        let cc_data: [u8; EXTRA_LEN] = data[frost_len..]
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

    Ok((key_package, pub_key_package))
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

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_reshare_session_from_setup(
    setup_data: Option<&go_slice>,
    my_party_name: Option<&go_slice>,
    old_key_package: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let sd = setup_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let name = my_party_name.ok_or(lib_error::LIB_NULL_PTR)?;
        let okp = old_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let reshare_setup = ReshareSetup::decode(sd.as_slice())?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(name.as_slice())
            .ok_or(lib_error::LIB_INVALID_IDENTIFIER)?;

        let okp_data = okp.as_slice();
        let (additive_share, cc_bytes) = if !okp_data.is_empty() {
            let bundle = frosty::bundle::KeyShareBundle::<S, ChainCodeMeta>::deserialize(okp_data)?;

            let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
                .map(|&id| Ident::try_from(id).map_err(|_| lib_error::LIB_INVALID_IDENTIFIER))
                .collect::<Result<_, _>>()?;

            let share = frost_ceremony::reshare::compute_additive_share::<S>(
                &bundle.key_package, &old_ids, setup.max_signers,
            )?;
            let cc = *bundle.metadata.extra_bytes();
            (share, cc)
        } else {
            (F::one(), [0u8; EXTRA_LEN])
        };

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;

        let protocol: Box<dyn Ceremony<Result<(KeyPackage<S>, PublicKeyPackage<S>), lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_reshare_run(
                    my_id, max, min, additive_share, cc_bytes, expected_vk, &ch,
                ).await
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
    out_key_package: Option<&mut tss_buffer>,
    out_pub_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_kp = out_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pkp = out_pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut state = session.take::<ReshareSessionState>()?;
        let (kp, pkp) = state.protocol.result()
            .ok_or(lib_error::LIB_SESSION_NOT_READY)?
            .map_err(|e| e)?;

        let kp_bytes = kp.serialize().map_err(ser_err)?;
        let pkp_bytes = pkp.serialize().map_err(ser_err)?;

        *out_kp = tss_buffer::from_vec(kp_bytes);
        *out_pkp = tss_buffer::from_vec(pkp_bytes);
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

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_key_import_setupmsg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: Option<&go_slice>,
    network: u8,
    birthday: u64,
    seed_holder_id: u16,
    private_key: Option<&go_slice>,
    chain_code: Option<&go_slice>,
    out_setup: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pd = parties_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let sk_data = private_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let cc_data = chain_code.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_setup.ok_or(lib_error::LIB_NULL_PTR)?;
        let parties = decode_parties(pd.as_slice())?;

        let mut secret = sk_data.as_slice().to_vec();
        secret.extend_from_slice(cc_data.as_slice());

        let setup = KeyImportSetup {
            base: SetupMsg { max_signers, min_signers, parties },
            seed_holder_id,
            secret_data: secret,
            account_index: 0,
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

        let secret_blob = ki_setup.secret_data;
        let (sk_vec, cc_vec) = if secret_blob.len() >= 64 {
            (secret_blob[..32].to_vec(), secret_blob[32..64].to_vec())
        } else {
            (secret_blob, vec![])
        };

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, lib_error>> + Send> =
            Box::new(Protocol::start(move |ch| async move {
                frobt_key_import_run(
                    my_id, max, min, seed_holder_id, sk_vec, cc_vec,
                    network, birthday, &ch,
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
