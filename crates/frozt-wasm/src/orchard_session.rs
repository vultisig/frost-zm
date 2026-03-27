use std::collections::BTreeMap;

use frost_core::{
	keys::{KeyPackage, PublicKeyPackage},
	round1::SigningCommitments,
	round2::SignatureShare,
	SigningPackage,
};
use frost_rerandomized::{Randomizer, RandomizedParams};
use reddsa::frost::redpallas::PallasBlake2b512;
use wasm_bindgen::prelude::*;

use frost_session::{
	message,
	relay::FrostChannel,
	session::{Ceremony, Protocol},
	setup::{SetupMsg, SignSetup},
};

use crate::to_js_err;

type P = PallasBlake2b512;
type Ident = frost_core::Identifier<P>;

fn ser_err<E: std::fmt::Debug>(e: E) -> froztlib::errors::lib_error {
	let _ = e;
	froztlib::errors::lib_error::LIB_SERIALIZATION_ERROR
}

/// Orchard FROST sign ceremony via relay.
///
/// Mirrors `frozt_sign_run` but parameterised on `PallasBlake2b512`.
async fn frozt_orchard_sign_run(
	key_package: KeyPackage<P>,
	pub_key_package: PublicKeyPackage<P>,
	msg_to_sign: Vec<u8>,
	is_coordinator: bool,
	num_signers: usize,
	ch: FrostChannel,
) -> Result<Vec<u8>, froztlib::errors::lib_error> {
	use froztlib::errors::lib_error;

	let my_ident = *key_package.identifier();

	let (nonces, commitments, commit_bytes) = {
		let mut rng = rand::thread_rng();
		let (n, c) = frost_core::round1::commit::<P, _>(key_package.signing_share(), &mut rng);
		let bytes = c.serialize().map_err(ser_err)?;
		(n, c, bytes)
	};
	ch.broadcast(commit_bytes).await;

	let mut commit_map: BTreeMap<Ident, SigningCommitments<P>> = BTreeMap::new();
	commit_map.insert(my_ident, commitments);

	for _ in 0..(num_signers - 1) {
		let (sender_raw, data) = ch.recv().await;
		let sender = Ident::try_from(sender_raw)
			.map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
		let c = SigningCommitments::<P>::deserialize(&data).map_err(ser_err)?;
		commit_map.insert(sender, c);
	}

	let signing_package = SigningPackage::<P>::new(commit_map, &msg_to_sign);

	let (_sp_bytes, randomizer) = if is_coordinator {
		let rp = RandomizedParams::<P>::new(
			pub_key_package.verifying_key(),
			&signing_package,
			rand::thread_rng(),
		).map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
		let randomizer = *rp.randomizer();

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
		let randomizer = Randomizer::<P>::deserialize(rand_ser)
			.map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
		(sp_ser, randomizer)
	};

	let share = frost_rerandomized::sign(&signing_package, &nonces, &key_package, randomizer)
		.map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
	let share_bytes = share.serialize();
	ch.broadcast(share_bytes).await;

	let mut shares: BTreeMap<Ident, SignatureShare<P>> = BTreeMap::new();
	shares.insert(my_ident, share);

	for _ in 0..(num_signers - 1) {
		let (sender_raw, data) = ch.recv().await;
		let sender = Ident::try_from(sender_raw)
			.map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
		let s = SignatureShare::<P>::deserialize(&data).map_err(ser_err)?;
		shares.insert(sender, s);
	}

	let randomized_params =
		RandomizedParams::<P>::from_randomizer(pub_key_package.verifying_key(), randomizer);
	let signature = frost_rerandomized::aggregate(
		&signing_package, &shares, &pub_key_package, &randomized_params,
	).map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

	let sig_bytes = signature.serialize().map_err(ser_err)?;
	Ok(sig_bytes)
}

/// Relay-based Orchard FROST signing session.
///
/// This uses PallasBlake2b512 (RedPallas) for Orchard spend auth signatures.
/// The setup, feed/takeMsg/msgReceiver/result interface mirrors FroztSignSession.
#[wasm_bindgen]
pub struct FroztOrchardSignSession {
	protocol: Box<dyn Ceremony<Result<Vec<u8>, froztlib::errors::lib_error>>>,
	setup: SetupMsg,
	my_id: u16,
}

#[wasm_bindgen]
impl FroztOrchardSignSession {
	#[wasm_bindgen(js_name = "fromSetup")]
	pub fn from_setup(
		setup_bytes: &[u8],
		my_party_name: &str,
		key_package: &[u8],
		pub_key_package: &[u8],
	) -> Result<FroztOrchardSignSession, JsError> {
		let sign_setup = SignSetup::decode(setup_bytes).map_err(to_js_err)?;
		let setup = sign_setup.base;
		let my_id = setup.frost_id_by_name(my_party_name.as_bytes())
			.ok_or_else(|| JsError::new("party name not found in setup"))?;

		let kp = KeyPackage::<P>::deserialize(key_package).map_err(to_js_err)?;
		let pkp = PublicKeyPackage::<P>::deserialize(pub_key_package).map_err(to_js_err)?;

		let is_coordinator = setup.coordinator_id() == my_id;
		let num_signers = setup.parties.len();
		let msg_to_sign = sign_setup.message;

		let protocol: Box<dyn Ceremony<Result<Vec<u8>, _>>> =
			Box::new(Protocol::start(move |ch| {
				frozt_orchard_sign_run(kp, pkp, msg_to_sign, is_coordinator, num_signers, ch)
			}));

		Ok(FroztOrchardSignSession { protocol, setup, my_id })
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
