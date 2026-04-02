use std::collections::BTreeMap;

use frost_core::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    SigningPackage,
};
use frost_rerandomized::{Randomizer, RandomizedParams};
use wasm_bindgen::prelude::*;

use frost_session::{
    message,
    relay::FrostChannel,
    session::{Ceremony, Protocol},
    setup::{KeyImportSetup, PartyEntry, SetupMsg, SignSetup, ReshareSetup},
};

use crate::{to_js_err, js_obj, set_bytes, J};

type Ident = Identifier<J>;

fn ser_err<E: std::fmt::Debug>(e: E) -> froztlib::errors::lib_error {
    let _ = e;
    froztlib::errors::lib_error::LIB_SERIALIZATION_ERROR
}

async fn frozt_sign_run(
    key_package: KeyPackage<J>,
    pub_key_package: PublicKeyPackage<J>,
    msg_to_sign: Vec<u8>,
    is_coordinator: bool,
    num_signers: usize,
    alpha: Option<Vec<u8>>,
    ch: FrostChannel,
) -> Result<Vec<u8>, froztlib::errors::lib_error> {
    use froztlib::errors::lib_error;

    let my_ident = *key_package.identifier();

    let (nonces, commitments, commit_bytes) = {
        let mut rng = rand::thread_rng();
        let (n, c) = frost_core::round1::commit::<J, _>(key_package.signing_share(), &mut rng);
        let bytes = c.serialize().map_err(ser_err)?;
        (n, c, bytes)
    };
    ch.broadcast(commit_bytes).await;

    let mut commit_map: BTreeMap<Ident, SigningCommitments<J>> = BTreeMap::new();
    commit_map.insert(my_ident, commitments);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let c = SigningCommitments::<J>::deserialize(&data).map_err(ser_err)?;
        commit_map.insert(sender, c);
    }

    let signing_package = SigningPackage::<J>::new(commit_map, &msg_to_sign);

    let (_sp_bytes, randomizer) = if is_coordinator {
        let randomizer = if let Some(ref alpha_bytes) = alpha {
            Randomizer::<J>::deserialize(alpha_bytes)
                .map_err(|_| lib_error::LIB_SIGNING_ERROR)?
        } else {
            let rp = RandomizedParams::<J>::new(
                pub_key_package.verifying_key(),
                &signing_package,
                rand::thread_rng(),
            ).map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
            *rp.randomizer()
        };

        let sp_ser = signing_package.serialize().map_err(ser_err)?;
        let rand_ser = randomizer.serialize();

        let mut combined = Vec::with_capacity(4 + sp_ser.len() + rand_ser.len());
        combined.extend_from_slice(&(sp_ser.len() as u32).to_le_bytes());
        combined.extend_from_slice(&sp_ser);
        combined.extend_from_slice(&rand_ser);
        ch.broadcast(combined).await;

        (sp_ser, randomizer)
    } else {
        let (_sender, combined) = ch.recv().await;
        if combined.len() < 4 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let sp_len = u32::from_le_bytes(combined[..4].try_into().unwrap()) as usize;
        if combined.len() < 4 + sp_len {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let sp_ser = combined[4..4 + sp_len].to_vec();
        let rand_ser = &combined[4 + sp_len..];
        let randomizer = Randomizer::<J>::deserialize(rand_ser)
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
        (sp_ser, randomizer)
    };

    let share = frost_rerandomized::sign(&signing_package, &nonces, &key_package, randomizer)
        .map_err(|e| frost_ceremony::blame::frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;
    let share_bytes = share.serialize();
    ch.broadcast(share_bytes).await;

    let mut shares: BTreeMap<Ident, SignatureShare<J>> = BTreeMap::new();
    shares.insert(my_ident, share);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let s = SignatureShare::<J>::deserialize(&data).map_err(ser_err)?;
        shares.insert(sender, s);
    }

    let randomized_params =
        RandomizedParams::<J>::from_randomizer(pub_key_package.verifying_key(), randomizer);
    let signature = frost_rerandomized::aggregate(
        &signing_package, &shares, &pub_key_package, &randomized_params,
    ).map_err(|e| frost_ceremony::blame::frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

    let sig_bytes = signature.serialize().map_err(ser_err)?;
    Ok(sig_bytes)
}

async fn frozt_dkg_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    birthday: u64,
    is_coordinator: bool,
    ch: &FrostChannel,
) -> Result<Vec<u8>, froztlib::errors::lib_error> {
    use froztlib::errors::lib_error;

    let (key_package, pub_key_package) =
        frost_ceremony::session_dkg::dkg_run::<J>(my_id, max_signers, min_signers, ch).await?;

    let metadata_blob = if is_coordinator {
        let (_extras, blob) = froztlib::ceremony_metadata::metadata_create(birthday)?;
        ch.broadcast(blob.clone()).await;
        blob
    } else {
        let (_sender, blob) = ch.recv().await;
        blob
    };

    let my_hash = froztlib::ceremony_metadata::metadata_hash(&metadata_blob)?;
    ch.broadcast(my_hash.to_vec()).await;

    let num_others = (max_signers - 1) as usize;
    for _ in 0..num_others {
        let (_sender, hash_bytes) = ch.recv().await;
        if hash_bytes.len() != 32 || hash_bytes.as_slice() != my_hash.as_slice() {
            return Err(lib_error::LIB_DKG_ERROR);
        }
    }

    let (extras, agreed_birthday) = froztlib::ceremony_metadata::metadata_parse(&metadata_blob)?;

    let kp_bytes = key_package.serialize().map_err(ser_err)?;
    let pkp_bytes = pub_key_package.serialize().map_err(ser_err)?;

    crate::keyshare::frozt_keyshare_bundle_pack(&kp_bytes, &pkp_bytes, &extras, agreed_birthday)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)
}

// === DKG Session ===

#[wasm_bindgen]
pub struct FroztDkgSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froztlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroztDkgSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(setup_bytes: &[u8], my_party_name: &str, birthday: u64) -> Result<FroztDkgSession, JsError> {
        let (setup, _) = SetupMsg::decode(setup_bytes).map_err(to_js_err)?;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let is_coordinator = setup.coordinator_id() == my_id;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frozt_dkg_run(my_id, max, min, birthday, is_coordinator, &ch).await
            }));

        Ok(FroztDkgSession { protocol, setup, my_id })
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

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsError> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsError::new("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === Key Import Session ===

async fn frozt_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    seed: Vec<u8>,
    account_index: u32,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, froztlib::errors::lib_error> {
    use froztlib::errors::lib_error;
    use frost_core::{Ciphersuite, Field, Group};
    type F = <<J as Ciphersuite>::Group as Group>::Field;

    let is_seed_holder = my_id == seed_holder_id;

    let constant_term = if is_seed_holder {
        let sk = froztlib::key_import::derive_spending_key(&seed, account_index)?;
        let sk_scalar = F::deserialize(&sk).map_err(ser_err)?;
        frost_ceremony::key_import::derive_constant_term::<J>(sk_scalar, max_signers)
    } else {
        F::one()
    };

    let (key_package, pub_key_package) =
        frost_ceremony::session_key_import::key_import_run::<J>(
            my_id, max_signers, min_signers, constant_term, ch,
        ).await?;

    let metadata_blob = if is_seed_holder {
        let extras = froztlib::sapling::derive_extras_from_seed(&seed, account_index)?;
        let blob = froztlib::ceremony_metadata::metadata_create_with_extras(&extras, birthday)?;
        ch.broadcast(blob.clone()).await;
        blob
    } else {
        let (_sender, blob) = ch.recv().await;
        blob
    };

    let my_hash = froztlib::ceremony_metadata::metadata_hash(&metadata_blob)?;
    ch.broadcast(my_hash.to_vec()).await;

    let num_others = (max_signers - 1) as usize;
    for _ in 0..num_others {
        let (_sender, hash_bytes) = ch.recv().await;
        if hash_bytes.len() != 32 || hash_bytes.as_slice() != my_hash.as_slice() {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    if is_seed_holder {
        let sk = froztlib::key_import::derive_spending_key(&seed, account_index)?;
        let expected_vk = froztlib::key_import::spending_key_to_vk(&sk)?;
        ch.broadcast(expected_vk).await;
    } else {
        let (_sender, expected_vk) = ch.recv().await;
        let actual_vk = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
        if <[u8]>::ne(actual_vk.as_ref(), &expected_vk) {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    let (extras, agreed_birthday) = froztlib::ceremony_metadata::metadata_parse(&metadata_blob)?;

    let kp_bytes = key_package.serialize().map_err(ser_err)?;
    let pkp_bytes = pub_key_package.serialize().map_err(ser_err)?;

    crate::keyshare::frozt_keyshare_bundle_pack(&kp_bytes, &pkp_bytes, &extras, agreed_birthday)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)
}

#[wasm_bindgen]
pub struct FroztKeyImportSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froztlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroztKeyImportSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        seed: &[u8],
        account_index: u32,
        birthday: u64,
    ) -> Result<FroztKeyImportSession, JsError> {
        let ki_setup = KeyImportSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = ki_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let seed_holder_id = ki_setup.seed_holder_id;
        let seed_owned = seed.to_vec();

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frozt_key_import_run(
                    my_id, max, min, seed_holder_id, seed_owned, account_index,
                    birthday, &ch,
                ).await
            }));

        Ok(FroztKeyImportSession { protocol, setup, my_id })
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

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsError> {
        let bundle = self.protocol.result()
            .ok_or_else(|| JsError::new("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(bundle.as_slice()))
    }
}

// === Sign Session ===

#[wasm_bindgen]
pub struct FroztSignSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froztlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroztSignSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        key_package: &[u8],
        pub_key_package: &[u8],
    ) -> Result<FroztSignSession, JsError> {
        let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
        let pkp = PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;

        let is_coordinator = setup.coordinator_id() == my_id;
        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| {
                frozt_sign_run(kp, pkp, msg_to_sign, is_coordinator, num_signers, None, ch)
            }));

        Ok(FroztSignSession { protocol, setup, my_id })
    }

    #[wasm_bindgen(js_name = "fromSetupWithAlpha")]
    pub fn from_setup_with_alpha(
        setup_bytes: &[u8],
        my_party_name: &str,
        key_package: &[u8],
        pub_key_package: &[u8],
        alpha: &[u8],
    ) -> Result<FroztSignSession, JsError> {
        let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
        let pkp = PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;

        let is_coordinator = setup.coordinator_id() == my_id;
        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;
        let alpha_owned = alpha.to_vec();

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| {
                frozt_sign_run(kp, pkp, msg_to_sign, is_coordinator, num_signers, Some(alpha_owned), ch)
            }));

        Ok(FroztSignSession { protocol, setup, my_id })
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

    pub fn result(&mut self) -> Result<js_sys::Uint8Array, JsError> {
        let sig = self.protocol.result()
            .ok_or_else(|| JsError::new("session not ready"))?
            .map_err(to_js_err)?;
        Ok(js_sys::Uint8Array::from(sig.as_slice()))
    }
}

// === Reshare Session ===

#[wasm_bindgen]
pub struct FroztReshareSession {
    protocol: Box<dyn Ceremony<Result<(KeyPackage<J>, PublicKeyPackage<J>), froztlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroztReshareSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        old_key_package: &[u8],
    ) -> Result<FroztReshareSession, JsError> {
        let reshare_setup = ReshareSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let old_kp = KeyPackage::<J>::deserialize(old_key_package).map_err(to_js_err)?;

        let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
            .map(|&id| Ident::try_from(id).map_err(|e| to_js_err(e)))
            .collect::<Result<_, _>>()?;

        let additive_share = frost_ceremony::reshare::compute_additive_share::<J>(
            &old_kp, &old_ids, setup.max_signers,
        ).map_err(to_js_err)?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;

        let protocol: Box<dyn Ceremony<Result<(KeyPackage<J>, PublicKeyPackage<J>), _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_reshare::reshare_run::<J>(
                    my_id, max, min, additive_share, &expected_vk, &ch,
                ).await
            }));

        Ok(FroztReshareSession { protocol, setup, my_id })
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

    pub fn result(&mut self) -> Result<JsValue, JsError> {
        let (kp, pkp) = self.protocol.result()
            .ok_or_else(|| JsError::new("session not ready"))?
            .map_err(to_js_err)?;

        let kp_bytes = kp.serialize().map_err(to_js_err)?;
        let pkp_bytes = pkp.serialize().map_err(to_js_err)?;

        let obj = js_obj();
        set_bytes(&obj, "keyPackage", &kp_bytes);
        set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
        Ok(obj.into())
    }
}

// === Setup Message Creation ===

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

#[wasm_bindgen(js_name = "froztDkgSetupMsgNew")]
pub fn dkg_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
    birthday: u64,
) -> Result<js_sys::Uint8Array, JsError> {
    let parties = decode_parties_wasm(parties_data)?;
    let setup = SetupMsg { max_signers, min_signers, parties };
    let mut buf = setup.encode();
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}

#[wasm_bindgen(js_name = "froztSignSetupMsgNew")]
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

#[wasm_bindgen(js_name = "froztReshareSetupMsgNew")]
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

#[wasm_bindgen(js_name = "froztKeyImportSetupMsgNew")]
pub fn key_import_setup_msg_new(
    max_signers: u16,
    min_signers: u16,
    parties_data: &[u8],
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
    buf.extend_from_slice(&birthday.to_le_bytes());
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}
