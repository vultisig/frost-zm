use std::collections::BTreeMap;

use frost_core::{
    Ciphersuite, Field, Group, Identifier,
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    SigningPackage,
};
use wasm_bindgen::prelude::*;

use frost_session::{
    message,
    relay::FrostChannel,
    session::{Ceremony, Protocol},
    setup::{KeyImportSetup, PartyEntry, SetupMsg, SignSetup, ReshareSetup},
};

use crate::{to_js_err, js_obj, set_bytes, S};

type Ident = Identifier<S>;
type Scalar = frost_core::Scalar<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;

const CC_LEN: usize = 32;

fn ser_err<E: std::fmt::Debug>(e: E) -> froethlib::errors::lib_error {
    let _ = e;
    froethlib::errors::lib_error::LIB_SERIALIZATION_ERROR
}

// === Sign ===

async fn froeth_sign_run(
    key_package: KeyPackage<S>,
    pub_key_package: PublicKeyPackage<S>,
    msg_to_sign: Vec<u8>,
    num_signers: usize,
    ch: FrostChannel,
) -> Result<Vec<u8>, froethlib::errors::lib_error> {
    use froethlib::errors::lib_error;

    let my_ident = *key_package.identifier();

    let (nonces, commitments, commit_bytes) = {
        let mut rng = rand::thread_rng();
        let (n, c) = frost_core::round1::commit::<S, _>(key_package.signing_share(), &mut rng);
        let bytes = c.serialize().map_err(ser_err)?;
        (n, c, bytes)
    };
    ch.broadcast(commit_bytes).await;

    let mut commit_map: BTreeMap<Ident, SigningCommitments<S>> = BTreeMap::new();
    commit_map.insert(my_ident, commitments);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let c = SigningCommitments::<S>::deserialize(&data).map_err(ser_err)?;
        commit_map.insert(sender, c);
    }

    let signing_package = SigningPackage::<S>::new(commit_map, &msg_to_sign);

    let share = frost_core::round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
    let share_bytes = share.serialize();
    ch.broadcast(share_bytes).await;

    let mut shares: BTreeMap<Ident, SignatureShare<S>> = BTreeMap::new();
    shares.insert(my_ident, share);

    for _ in 0..(num_signers - 1) {
        let (sender_raw, data) = ch.recv().await;
        let sender = Ident::try_from(sender_raw)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        let s = SignatureShare::<S>::deserialize(&data).map_err(ser_err)?;
        shares.insert(sender, s);
    }

    let signature = frost_core::aggregate(&signing_package, &shares, &pub_key_package)
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

    let sig_bytes = signature.serialize().map_err(ser_err)?;
    Ok(sig_bytes)
}

// === DKG ===

async fn froeth_dkg_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, froethlib::errors::lib_error> {
    use froethlib::errors::lib_error;

    let (key_package, pub_key_package) =
        frost_ceremony::session_dkg::dkg_run::<S>(my_id, max_signers, min_signers, ch).await?;

    let mut rng = rand::thread_rng();
    let cc_share: Scalar = F::random(&mut rng);
    let cc_share_bytes: [u8; CC_LEN] = {
        let s = F::serialize(&cc_share);
        let sl: &[u8] = s.as_ref();
        sl.try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
    };
    ch.broadcast(cc_share_bytes.to_vec()).await;

    let num_others = (max_signers - 1) as usize;
    let mut cc_shares: Vec<[u8; CC_LEN]> = Vec::with_capacity(num_others);
    for _ in 0..num_others {
        let (_sender, data) = ch.recv().await;
        let share: [u8; CC_LEN] = data
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        cc_shares.push(share);
    }

    let chain_code = aggregate_cc_shares(&cc_share_bytes, &cc_shares)?;

    let bundle = froethlib::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    bundle.serialize()
}

fn aggregate_cc_shares(
    own: &[u8; CC_LEN],
    others: &[[u8; CC_LEN]],
) -> Result<[u8; CC_LEN], froethlib::errors::lib_error> {
    let mut sum: Scalar = F::deserialize(own).map_err(ser_err)?;
    for share_bytes in others {
        let s: Scalar = F::deserialize(share_bytes).map_err(ser_err)?;
        sum = sum + s;
    }
    let result_serialized = F::serialize(&sum);
    let sl: &[u8] = result_serialized.as_ref();
    let result: [u8; CC_LEN] = sl
        .try_into()
        .map_err(|_| froethlib::errors::lib_error::LIB_SERIALIZATION_ERROR)?;
    Ok(result)
}

// === Key Import ===

async fn froeth_key_import_run(
    my_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed_holder_id: u16,
    seed: Vec<u8>,
    account_index: u32,
    network: u8,
    birthday: u64,
    ch: &FrostChannel,
) -> Result<Vec<u8>, froethlib::errors::lib_error> {
    use froethlib::errors::lib_error;

    let is_seed_holder = my_id == seed_holder_id;

    let (constant_term, cc_bytes) = if is_seed_holder {
        let (sk, cc, _pub_key) =
            froethlib::ceremony::key_import::derive_from_seed(&seed, account_index)?;
        let sk_scalar: Scalar = F::deserialize(&sk).map_err(ser_err)?;
        let ct = frost_ceremony::key_import::derive_constant_term::<S>(sk_scalar, max_signers);
        (ct, cc)
    } else {
        (F::one(), [0u8; 32])
    };

    let (key_package, pub_key_package) =
        frost_ceremony::session_key_import::key_import_run::<S>(
            my_id, max_signers, min_signers, constant_term, ch,
        ).await?;

    ch.broadcast(cc_bytes.to_vec()).await;

    let num_others = (max_signers - 1) as usize;
    let mut received_cc: Vec<[u8; CC_LEN]> = Vec::with_capacity(num_others);
    for _ in 0..num_others {
        let (_sender, data) = ch.recv().await;
        let share: [u8; CC_LEN] = data
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        received_cc.push(share);
    }

    let chain_code = if is_seed_holder {
        cc_bytes
    } else {
        let mut found = None;
        for cc in &received_cc {
            if *cc != [0u8; CC_LEN] {
                found = Some(*cc);
                break;
            }
        }
        found.ok_or(lib_error::LIB_KEY_IMPORT_ERROR)?
    };

    if is_seed_holder {
        let (_sk, _cc, pub_key) =
            froethlib::ceremony::key_import::derive_from_seed(&seed, account_index)?;
        ch.broadcast(pub_key).await;
    } else {
        let (_sender, expected_vk) = ch.recv().await;
        let actual_vk = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
        if <[u8]>::ne(actual_vk.as_ref(), &expected_vk) {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }
    }

    let bundle = froethlib::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    bundle.serialize()
}

// === DKG Session ===

#[wasm_bindgen]
pub struct FroethDkgSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froethlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroethDkgSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        network: u8,
        birthday: u64,
    ) -> Result<FroethDkgSession, JsError> {
        let (setup, _) = SetupMsg::decode(setup_bytes).map_err(to_js_err)?;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let max = setup.max_signers;
        let min = setup.min_signers;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| async move {
                froeth_dkg_run(my_id, max, min, network, birthday, &ch).await
            }));

        Ok(FroethDkgSession { protocol, setup, my_id })
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

#[wasm_bindgen]
pub struct FroethKeyImportSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froethlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroethKeyImportSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        seed: &[u8],
        account_index: u32,
        birthday: u64,
    ) -> Result<FroethKeyImportSession, JsError> {
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
                froeth_key_import_run(
                    my_id, max, min, seed_holder_id, seed_owned, account_index,
                    0, birthday, &ch,
                ).await
            }));

        Ok(FroethKeyImportSession { protocol, setup, my_id })
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
pub struct FroethSignSession {
    protocol: Box<dyn Ceremony<Result<Vec<u8>, froethlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroethSignSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        key_package: &[u8],
        pub_key_package: &[u8],
    ) -> Result<FroethSignSession, JsError> {
        let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = sign_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let kp = KeyPackage::<S>::deserialize(key_package).map_err(to_js_err)?;
        let pkp = PublicKeyPackage::<S>::deserialize(pub_key_package).map_err(to_js_err)?;

        let num_signers = setup.parties.len();
        let msg_to_sign = sign_setup.message;

        let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
            Box::new(Protocol::start(move |ch| {
                froeth_sign_run(kp, pkp, msg_to_sign, num_signers, ch)
            }));

        Ok(FroethSignSession { protocol, setup, my_id })
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
pub struct FroethReshareSession {
    protocol: Box<dyn Ceremony<Result<(KeyPackage<S>, PublicKeyPackage<S>), froethlib::errors::lib_error>>>,
    setup: SetupMsg,
    my_id: u16,
}

#[wasm_bindgen]
impl FroethReshareSession {
    #[wasm_bindgen(js_name = "fromSetup")]
    pub fn from_setup(
        setup_bytes: &[u8],
        my_party_name: &str,
        old_key_package: &[u8],
    ) -> Result<FroethReshareSession, JsError> {
        let reshare_setup = ReshareSetup::decode(setup_bytes).map_err(to_js_err)?;
        let setup = reshare_setup.base;
        let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
            .ok_or_else(|| JsError::new("party name not found in setup"))?;

        let old_kp = KeyPackage::<S>::deserialize(old_key_package).map_err(to_js_err)?;

        let old_ids: Vec<Ident> = reshare_setup.old_identifiers.iter()
            .map(|&id| Ident::try_from(id).map_err(|e| to_js_err(e)))
            .collect::<Result<_, _>>()?;

        let additive_share = frost_ceremony::reshare::compute_additive_share::<S>(
            &old_kp, &old_ids, setup.max_signers,
        ).map_err(to_js_err)?;

        let max = setup.max_signers;
        let min = setup.min_signers;
        let expected_vk = reshare_setup.expected_vk;

        let protocol: Box<dyn Ceremony<Result<(KeyPackage<S>, PublicKeyPackage<S>), _>>> =
            Box::new(Protocol::start(move |ch| async move {
                frost_ceremony::session_reshare::reshare_run::<S>(
                    my_id, max, min, additive_share, &expected_vk, &ch,
                ).await
            }));

        Ok(FroethReshareSession { protocol, setup, my_id })
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

#[wasm_bindgen(js_name = "froethDkgSetupMsgNew")]
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

#[wasm_bindgen(js_name = "froethSignSetupMsgNew")]
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

#[wasm_bindgen(js_name = "froethReshareSetupMsgNew")]
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

#[wasm_bindgen(js_name = "froethKeyImportSetupMsgNew")]
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
