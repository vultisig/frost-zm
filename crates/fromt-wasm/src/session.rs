use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Field, Group, Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use frost_ed25519::Ed25519Sha512;
use wasm_bindgen::prelude::*;

use frost_session::{
    message,
    relay::FrostChannel,
    session::{Ceremony, Protocol},
    setup::{KeyImportSetup, KeyImageSetup, PartyEntry, SetupMsg, SignSetup, ReshareSetup},
};

use crate::to_js_err;

type E = Ed25519Sha512;
type Ident = Identifier<E>;
type Scalar = frost_core::Scalar<E>;
type F = <<E as Ciphersuite>::Group as Group>::Field;

const VK_SHARE_LEN: usize = 32;

fn js_obj() -> js_sys::Object {
    js_sys::Object::new()
}

fn set_bytes(obj: &js_sys::Object, key: &str, data: &[u8]) {
    let arr = js_sys::Uint8Array::from(data);
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &arr).unwrap();
}

fn dkg_ser_err<Err: std::fmt::Debug>(e: Err) -> fromtlib::errors::lib_error {
    let _ = e;
    fromtlib::errors::lib_error::LIB_SERIALIZATION_ERROR
}

async fn fromt_dkg_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, fromtlib::errors::lib_error> {
    use fromtlib::errors::lib_error;

    let id_map = frost_ceremony::session_dkg::build_id_map::<E>(max_signers)?;
    let ident = Ident::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (secret1, r1_combined, vk_share_bytes) = {
        let mut rng = rand::thread_rng();
        let (secret, package) =
            dkg::part1::<E, _>(ident, max_signers, min_signers, &mut rng)
                .map_err(|_| lib_error::LIB_DKG_ERROR)?;
        let mut bytes = package.serialize().map_err(dkg_ser_err)?;

        let vk_share: Scalar = F::random(&mut rng);
        let serialized = F::serialize(&vk_share);
        let vk_bytes: [u8; VK_SHARE_LEN] = AsRef::<[u8]>::as_ref(&serialized)
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        bytes.extend_from_slice(&vk_bytes);
        (secret, bytes, vk_bytes)
    };

    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut vk_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < VK_SHARE_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - VK_SHARE_LEN;
        let frost_data = &data[..frost_len];
        let vk_data: [u8; VK_SHARE_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<E>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        vk_shares_map.insert(sender, vk_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<E>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<E>::deserialize(&data).map_err(dkg_ser_err)?;
        r2_received.insert(sender, pkg);
    }

    let (key_package, pub_key_package) =
        dkg::part3(&secret2, &r1_frost_map, &r2_received)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let mut vk_share_local = vk_share_bytes;
    let mut vk_sum = frosty::ceremony::dkg::aggregate_extra_shares::<E>(&vk_share_local, &vk_shares_map)?;
    vk_share_local.iter_mut().for_each(|b| *b = 0);

    let bundle = fromtlib::keyshare::bundle::new_bundle(
        key_package,
        pub_key_package,
        vk_sum,
        network,
        birthday,
    );
    vk_sum.iter_mut().for_each(|b| *b = 0);

    bundle.serialize()
}

// === Key Import Session ===

async fn fromt_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    spend_key: Vec<u8>,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, fromtlib::errors::lib_error> {
    use fromtlib::errors::lib_error;
    use tiny_keccak::{Hasher, Keccak};

    let is_seed_holder = my_id == seed_holder_id;
    let id_map = frost_ceremony::session_dkg::build_id_map::<E>(max_signers)?;
    let _ident = Ident::try_from(my_id)
        .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

    let (constant_term, vk_share_bytes) = if is_seed_holder {
        let sk_bytes: &[u8; 32] = spend_key.as_slice().try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
        let sk_scalar: Scalar = F::deserialize(sk_bytes).map_err(dkg_ser_err)?;
        let ct = frost_ceremony::key_import::derive_constant_term::<E>(sk_scalar, max_signers);

        let mut keccak = Keccak::v256();
        let mut hash = [0u8; 32];
        keccak.update(sk_bytes);
        keccak.finalize(&mut hash);
        let vk_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(hash);
        let vk_bytes: [u8; VK_SHARE_LEN] = vk_scalar.to_bytes();

        (ct, vk_bytes)
    } else {
        (F::one(), [0u8; VK_SHARE_LEN])
    };

    let (secret1, r1_frost_bytes) =
        frost_ceremony::key_import::key_import_part1::<E>(my_id, max_signers, min_signers, constant_term)?;

    let mut r1_combined = r1_frost_bytes;
    r1_combined.extend_from_slice(&vk_share_bytes);
    ch.broadcast(r1_combined).await;

    let num_others = (max_signers - 1) as usize;
    let mut r1_frost_map = BTreeMap::new();
    let mut vk_shares_map = BTreeMap::new();

    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        if data.len() < VK_SHARE_LEN {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let frost_len = data.len() - VK_SHARE_LEN;
        let frost_data = &data[..frost_len];
        let vk_data: [u8; VK_SHARE_LEN] = data[frost_len..]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let pkg = dkg::round1::Package::<E>::deserialize(frost_data).map_err(dkg_ser_err)?;
        r1_frost_map.insert(sender, pkg);
        vk_shares_map.insert(sender, vk_data);
    }

    let (secret2, r2_map) =
        dkg::part2(secret1, &r1_frost_map).map_err(|_| lib_error::LIB_DKG_ERROR)?;

    for (recipient, pkg) in &r2_map {
        let recipient_u16 = frost_ceremony::session_dkg::lookup_u16::<E>(&id_map, recipient)?;
        let pkg_bytes = pkg.serialize().map_err(dkg_ser_err)?;
        ch.send_to(recipient_u16, pkg_bytes).await;
    }

    let mut r2_received = BTreeMap::new();
    for _ in 0..num_others {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let pkg = dkg::round2::Package::<E>::deserialize(&data).map_err(dkg_ser_err)?;
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
        let actual_vk: Vec<u8> = pub_key_package.verifying_key().serialize().map_err(dkg_ser_err)?;
        if actual_vk != expected_vk {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    let mut vk_share_local = vk_share_bytes;
    let mut vk_sum = frosty::ceremony::dkg::aggregate_extra_shares::<E>(&vk_share_local, &vk_shares_map)?;
    vk_share_local.iter_mut().for_each(|b| *b = 0);

    let bundle = fromtlib::keyshare::bundle::new_bundle(
        key_package,
        pub_key_package,
        vk_sum,
        network,
        birthday,
    );
    vk_sum.iter_mut().for_each(|b| *b = 0);

    bundle.serialize()
}

#[wasm_bindgen]
pub struct FromtKeyImportSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, fromtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FromtKeyImportSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        spend_key: &[u8],
        network: u8,
        birthday: u64,
    ) -> Result<FromtKeyImportSession, JsValue> {
        let ki_setup = KeyImportSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = ki_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let seed_holder_id = ki_setup.seed_holder_id;
        let spend_key_owned = spend_key.to_vec();

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                fromt_key_import_run(
                    my_id, max, min, seed_holder_id, spend_key_owned,
                    network, birthday, &ch,
                ).await
            }));

        Ok(FromtKeyImportSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === DKG Session ===

#[wasm_bindgen]
pub struct FromtDkgSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, fromtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FromtDkgSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(setup_bytes: &[u8], my_party_name: &str, network: u8, birthday: u64) -> Result<FromtDkgSession, JsValue> {
        let (setup, _) = SetupMsg::decode(setup_bytes).map_err(to_js_err)?;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                fromt_dkg_run(my_id, max, min, network, birthday, &ch).await
            }));

        Ok(FromtDkgSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === Sign Session ===

#[wasm_bindgen]
pub struct FromtSignSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, fromtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FromtSignSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        key_package: &[u8],
        pub_key_package: &[u8],
    ) -> Result<FromtSignSession, JsValue> {
        let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let kp = KeyPackage::<E>::deserialize(key_package).map_err(to_js_err)?;
        let pkp = PublicKeyPackage::<E>::deserialize(pub_key_package).map_err(to_js_err)?;

        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_sign::sign_run::<E>(
                    &kp, &pkp, &msg_to_sign, num_signers, &ch,
                ).await
            }));

        Ok(FromtSignSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let sig = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(sig.as_slice()))
    }
}

// === Reshare Session ===

#[wasm_bindgen]
pub struct FromtReshareSession {
    protocol: Box<dyn Ceremony<Result<(KeyPackage<E>, PublicKeyPackage<E>), fromtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FromtReshareSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        old_key_package: &[u8],
    ) -> Result<FromtReshareSession, JsValue> {
        let reshare_setup = ReshareSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let old_kp = KeyPackage::<E>::deserialize(old_key_package).map_err(to_js_err)?;

        let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
            .map(|&id| Ident::try_from(id).map_err(to_js_err))
            .collect::<Result<_, _>>()?;

        let additive_share = frost_ceremony::reshare::compute_additive_share::<E>(
            &old_kp, &old_ids, setup.max_signers,
        ).map_err(to_js_err)?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;

        let protocol: Box<dyn Ceremony<Result<(KeyPackage<E>, PublicKeyPackage<E>), _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_reshare::reshare_run::<E>(
                    my_id, max, min, additive_share, &expected_vk, &ch,
                ).await
            }));

        Ok(FromtReshareSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<JsValue, JsValue> {
        let (kp, pkp) = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;

        let kp_bytes = kp.serialize().map_err(to_js_err)?;
        let pkp_bytes = pkp.serialize().map_err(to_js_err)?;

        let obj = js_obj();
        set_bytes(&obj, "keyPackage", &kp_bytes);
        set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
        Ok(obj.into())
    }
}

// === Key Image Session ===

async fn key_image_session_run(
    key_share_data: Vec<u8>,
    outputs_data: Vec<u8>,
    signer_ids: Vec<u16>,
    ch: &FrostChannel,
) -> Result<Vec<u8>, fromtlib::errors::lib_error> {
    use fromtlib::ceremony::key_image;

    let num_signers = signer_ids.len();

    let (state, partials) = key_image::key_image_part1(&key_share_data, &outputs_data, &signer_ids)?;
    ch.broadcast(partials).await;

    let mut r1_packages = Vec::new();
    for _ in 0..(num_signers - 1) {
        let (sender_id, data) = ch.recv().await;
        r1_packages.push((sender_id, data));
    }

    key_image::key_image_part2(state, &r1_packages)
}

#[wasm_bindgen]
pub struct FromtKeyImageSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, fromtlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FromtKeyImageSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(setup_bytes: &[u8], my_party_name: &str, key_share: &[u8]) -> Result<FromtKeyImageSession, JsValue> {
        let ki_setup = KeyImageSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = ki_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsValue::from_str("party name not found in setup"))?;

        let key_share_data = key_share.to_vec();
        let outputs_data = ki_setup.outputs_data;
        let signer_ids: Vec<u16> = setup.parties.iter().map(|p| p.frost_id).collect();

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                key_image_session_run(key_share_data, outputs_data, signer_ids, &ch).await
            }));

        Ok(FromtKeyImageSession { protocol, setup, my_id })
    }

    pub fn feed(&mut self, msg: &[u8]) -> bool {
        self.protocol.feed(msg.to_vec())
    }

    #[wasm_bindgen(js_name = "takeMsg")]
    pub fn take_msg(&mut self) -> Option<js_sys::Uint8Array> {
        self.protocol.take_msg().map(|m| js_sys::Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(js_name = "msgReceiver")]
    pub fn msg_receiver(&self, msg: &[u8], index: u32) -> Option<String> {
        let recipient = message::read_recipient(msg);
        if recipient == 0 {
            let others = self.setup.other_party_ids(self.my_id);
            others.get(index as usize)
                .and_then(|&fid| self.setup.party_name(fid))
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else if index == 0 {
            self.setup.party_name(recipient)
                .map(|n| String::from_utf8_lossy(n).into_owned())
        } else {
            None
        }
    }

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let key_images = self.protocol.result()
            .ok_or_else(|| JsValue::from_str("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(key_images.as_slice()))
    }
}

// === Setup Message Helpers ===

fn decode_parties_wasm(data: &[u8]) -> Result<Vec<PartyEntry>, JsError> {
    if data.len() < 2 {
        return Err(JsError::new("parties data too short"));
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut parties = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return Err(JsError::new("parties data truncated"));
        }
        let frost_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + name_len > data.len() {
            return Err(JsError::new("party name truncated"));
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        parties.push(PartyEntry { frost_id, name });
    }
    Ok(parties)
}

fn decode_u16_list_wasm(data: &[u8]) -> Result<Vec<u16>, JsError> {
    if data.len() < 2 {
        return Err(JsError::new("u16 list data too short"));
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(JsError::new("u16 list truncated"));
        }
        list.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    Ok(list)
}

// === Setup Message Creators ===

#[wasm_bindgen(js_name = "fromtDkgSetupMsgNew")]
pub fn dkg_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    network: u8,
    birthday: u64,
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let setup = SetupMsg { max_signers, min_signers, parties };
    let mut buf = setup.encode();
    buf.push(network);
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}

#[wasm_bindgen(js_name = "fromtSignSetupMsgNew")]
pub fn sign_setup_msg_new(
    msg_to_sign: &[u8],
    parties_data: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let num = parties.len() as u16;
    let setup = SignSetup {
        base: SetupMsg { max_signers: num, min_signers: num, parties },
        message: msg_to_sign.to_vec(),
    };
    Ok(js_sys::Uint8Array::from(setup.encode().as_slice()))
}

#[wasm_bindgen(js_name = "fromtReshareSetupMsgNew")]
pub fn reshare_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    old_identifiers_data: &[u8],
    expected_vk: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let old_identifiers = decode_u16_list_wasm(old_identifiers_data)?;
    let setup = ReshareSetup {
        base: SetupMsg { max_signers, min_signers, parties },
        old_identifiers,
        expected_vk: expected_vk.to_vec(),
    };
    Ok(js_sys::Uint8Array::from(setup.encode().as_slice()))
}

#[wasm_bindgen(js_name = "fromtKeyImportSetupMsgNew")]
pub fn key_import_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    network: u8,
    birthday: u64,
    seed_holder_id: u16,
    seed: &[u8],
    account_index: u32,
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let setup = KeyImportSetup {
        base: SetupMsg { max_signers, min_signers, parties },
        seed_holder_id,
        secret_data: seed.to_vec(),
        account_index,
    };
    let mut buf = setup.encode();
    buf.push(network);
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}

#[wasm_bindgen(js_name = "fromtKeyImageSetupMsgNew")]
pub fn key_image_setup_msg_new(
    parties_data: &[u8],
    outputs: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let num = parties.len() as u16;
    let setup = KeyImageSetup {
        base: SetupMsg { max_signers: num, min_signers: num, parties },
        outputs_data: outputs.to_vec(),
    };
    Ok(js_sys::Uint8Array::from(setup.encode().as_slice()))
}

// === Codec / Identifier Utilities ===

#[wasm_bindgen]
pub fn fromt_encode_identifier(id: u16) -> Result<Vec<u8>, JsError> {
    let ident = Ident::try_from(id).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(ident.serialize())
}

#[wasm_bindgen]
pub fn fromt_decode_identifier(id_bytes: &[u8]) -> Result<u16, JsError> {
    let ident = Ident::deserialize(id_bytes).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let serialized = ident.serialize();
    if serialized.len() < 2 {
        return Err(JsError::new("identifier too short"));
    }
    Ok(u16::from_le_bytes([serialized[0], serialized[1]]))
}

#[wasm_bindgen(js_name = "fromt_encode_map")]
pub fn wasm_encode_map(entries: JsValue) -> Result<Vec<u8>, JsError> {
    let arr = js_sys::Array::from(&entries);
    let len = arr.length();
    let mut buf = Vec::new();
    buf.extend_from_slice(&len.to_le_bytes());
    for i in 0..len {
        let entry = arr.get(i);
        let id_val = js_sys::Reflect::get(&entry, &"id".into())
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        let value = js_sys::Reflect::get(&entry, &"value".into())
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        let id_u16 = id_val.as_f64()
            .ok_or_else(|| JsError::new("id must be a number"))? as u16;
        let ident = Ident::try_from(id_u16)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        let id_bytes = ident.serialize();
        let val_bytes = js_sys::Uint8Array::from(value).to_vec();
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&val_bytes);
    }
    Ok(buf)
}
