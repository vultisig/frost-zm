use blake2b_simd::Params as Blake2bParams;

use crate::{
	bytes::*,
	errors::*,
	tx::{hash_header, hash_sapling, SpendParts, OutputParts},
};

/// Serialised Orchard action (per ZIP-244 / Zcash v5 transaction format).
///
/// Each action is 820 bytes in the v5 wire format:
///   cv: 32, rk: 32, encrypted_note (cmx + epk + enc + out): 580,
///   nullifier: 32, zkproof: 0 (stored separately, 2720 per proof)
///
/// This struct holds the components needed for sighash computation and
/// serialisation, without the full proving logic.
pub struct OrchardActionParts {
	pub cv_net: [u8; 32],
	pub nullifier: [u8; 32],
	pub rk: [u8; 32],
	pub cmx: [u8; 32],
	pub ephemeral_key: [u8; 32],
	pub enc_ciphertext: Vec<u8>,   // 580 bytes
	pub out_ciphertext: [u8; 80],
}

/// Orchard bundle components for sighash computation and serialisation.
pub struct OrchardBundle {
	pub actions: Vec<OrchardActionParts>,
	pub flags: u8,
	pub value_balance: i64,
	pub anchor: [u8; 32],
	/// Per-action proofs (2720 bytes each, or 0 if proofs are added later).
	pub proofs: Vec<Vec<u8>>,
	/// Per-action spend auth signatures (64 bytes each).
	pub spend_auth_sigs: Vec<[u8; 64]>,
	/// Binding signature (64 bytes).
	pub binding_sig: [u8; 64],
}

/// Compute the Orchard digest for the v5 sighash (ZIP-244 § T.4).
///
/// When there are no Orchard actions, returns the empty hash.
pub fn hash_orchard_bundle(bundle: Option<&OrchardBundle>) -> [u8; 32] {
	let bundle = match bundle {
		Some(b) if !b.actions.is_empty() => b,
		_ => return crate::tx::hash_empty_orchard(),
	};

	let actions_compact = {
		let mut h = Blake2bParams::new()
			.hash_length(32)
			.personal(b"ZTxIdOrcActCHash")
			.to_state();
		for action in &bundle.actions {
			h.update(&action.nullifier);
			h.update(&action.cmx);
			h.update(&action.ephemeral_key);
			h.update(&action.enc_ciphertext[..52]);
		}
		h.finalize()
	};

	let actions_memos = {
		let mut h = Blake2bParams::new()
			.hash_length(32)
			.personal(b"ZTxIdOrcActMHash")
			.to_state();
		for action in &bundle.actions {
			h.update(&action.enc_ciphertext[52..564]);
		}
		h.finalize()
	};

	let actions_noncompact = {
		let mut h = Blake2bParams::new()
			.hash_length(32)
			.personal(b"ZTxIdOrcActNHash")
			.to_state();
		for action in &bundle.actions {
			h.update(&action.cv_net);
			h.update(&action.rk);
			h.update(&action.enc_ciphertext[564..]);
			h.update(&action.out_ciphertext);
		}
		h.finalize()
	};

	let actions_digest = {
		let mut h = Blake2bParams::new()
			.hash_length(32)
			.personal(b"ZTxIdOrcActsHash")
			.to_state();
		h.update(actions_compact.as_bytes());
		h.update(actions_memos.as_bytes());
		h.update(actions_noncompact.as_bytes());
		h.finalize()
	};

	let mut h = Blake2bParams::new()
		.hash_length(32)
		.personal(b"ZTxIdOrchardHash")
		.to_state();
	h.update(actions_digest.as_bytes());
	h.update(&bundle.flags.to_le_bytes());
	h.update(&bundle.value_balance.to_le_bytes());
	h.update(&bundle.anchor);
	h.finalize().as_bytes().try_into().unwrap()
}

/// Compute v5 sighash with both Sapling and Orchard bundles.
pub fn compute_v5_sighash_full(
	sapling_spends: &[SpendParts],
	sapling_outputs: &[OutputParts],
	sapling_value_balance: i64,
	orchard_bundle: Option<&OrchardBundle>,
	consensus_branch_id: u32,
	expiry_height: u32,
) -> [u8; 32] {
	let header_digest = hash_header(consensus_branch_id, expiry_height);
	let transparent_digest = hash_empty_transparent();
	let sapling_digest = hash_sapling(sapling_spends, sapling_outputs, sapling_value_balance);
	let orchard_digest = hash_orchard_bundle(orchard_bundle);

	let mut personal = [0u8; 16];
	personal[..12].copy_from_slice(b"ZcashTxHash_");
	personal[12..].copy_from_slice(&consensus_branch_id.to_le_bytes());

	let mut h = Blake2bParams::new()
		.hash_length(32)
		.personal(&personal)
		.to_state();
	h.update(&header_digest);
	h.update(&transparent_digest);
	h.update(&sapling_digest);
	h.update(&orchard_digest);
	h.finalize().as_bytes().try_into().unwrap()
}

fn hash_empty_transparent() -> [u8; 32] {
	Blake2bParams::new()
		.hash_length(32)
		.personal(b"ZTxIdTranspaHash")
		.to_state()
		.finalize()
		.as_bytes()
		.try_into()
		.unwrap()
}

/// Extract the Orchard per-action sighash for FROST signing.
///
/// Each Orchard action requires its own SpendAuth signature.
/// The sighash is the same for all actions in a given transaction,
/// but the randomized verification key (rk) differs per action.
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_orchard_compute_sighash(
	_sapling_spends_count: u32,
	sapling_value_balance: i64,
	orchard_actions_data: Option<&go_slice>,
	orchard_flags: u8,
	orchard_value_balance: i64,
	orchard_anchor: Option<&go_slice>,
	consensus_branch_id: u32,
	expiry_height: u32,
	out_sighash: Option<&mut tss_buffer>,
) -> lib_error {
	with_error_handler(|| {
		let out = out_sighash.ok_or(lib_error::LIB_NULL_PTR)?;
		let anchor_data = orchard_anchor.ok_or(lib_error::LIB_NULL_PTR)?;

		if anchor_data.len() != 32 {
			return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
		}

		let anchor: [u8; 32] = anchor_data.as_slice().try_into().unwrap();

		let actions = match orchard_actions_data {
			Some(data) if !data.is_empty() => parse_orchard_actions(data.as_slice())?,
			_ => Vec::new(),
		};

		let bundle = if !actions.is_empty() {
			Some(OrchardBundle {
				actions,
				flags: orchard_flags,
				value_balance: orchard_value_balance,
				anchor,
				proofs: Vec::new(),
				spend_auth_sigs: Vec::new(),
				binding_sig: [0u8; 64],
			})
		} else {
			None
		};

		let sighash = compute_v5_sighash_full(
			&[], &[], sapling_value_balance,
			bundle.as_ref(),
			consensus_branch_id,
			expiry_height,
		);

		*out = tss_buffer::from_vec(sighash.to_vec());
		Ok(())
	})
}

/// Parse serialised Orchard actions from wire format.
///
/// Each action is encoded as:
///   cv_net (32) + nullifier (32) + rk (32) + cmx (32) + epk (32) +
///   enc_ciphertext (580) + out_ciphertext (80) = 820 bytes
const ACTION_WIRE_SIZE: usize = 820;

fn parse_orchard_actions(data: &[u8]) -> Result<Vec<OrchardActionParts>, lib_error> {
	if data.len() % ACTION_WIRE_SIZE != 0 {
		return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
	}

	let n = data.len() / ACTION_WIRE_SIZE;
	let mut actions = Vec::with_capacity(n);

	for i in 0..n {
		let off = i * ACTION_WIRE_SIZE;
		let cv_net: [u8; 32] = data[off..off+32].try_into().unwrap();
		let nullifier: [u8; 32] = data[off+32..off+64].try_into().unwrap();
		let rk: [u8; 32] = data[off+64..off+96].try_into().unwrap();
		let cmx: [u8; 32] = data[off+96..off+128].try_into().unwrap();
		let ephemeral_key: [u8; 32] = data[off+128..off+160].try_into().unwrap();
		let enc_ciphertext = data[off+160..off+740].to_vec();
		let out_ciphertext: [u8; 80] = data[off+740..off+820].try_into().unwrap();

		actions.push(OrchardActionParts {
			cv_net,
			nullifier,
			rk,
			cmx,
			ephemeral_key,
			enc_ciphertext,
			out_ciphertext,
		});
	}

	Ok(actions)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn make_dummy_action(seed: u8) -> OrchardActionParts {
		OrchardActionParts {
			cv_net: [seed; 32],
			nullifier: [seed.wrapping_add(1); 32],
			rk: [seed.wrapping_add(2); 32],
			cmx: [seed.wrapping_add(3); 32],
			ephemeral_key: [seed.wrapping_add(4); 32],
			enc_ciphertext: vec![seed.wrapping_add(5); 580],
			out_ciphertext: [seed.wrapping_add(6); 80],
		}
	}

	fn serialise_action(a: &OrchardActionParts) -> Vec<u8> {
		let mut buf = Vec::with_capacity(ACTION_WIRE_SIZE);
		buf.extend_from_slice(&a.cv_net);
		buf.extend_from_slice(&a.nullifier);
		buf.extend_from_slice(&a.rk);
		buf.extend_from_slice(&a.cmx);
		buf.extend_from_slice(&a.ephemeral_key);
		buf.extend_from_slice(&a.enc_ciphertext);
		buf.extend_from_slice(&a.out_ciphertext);
		buf
	}

	#[test]
	fn test_hash_orchard_empty_matches_existing() {
		let empty = hash_orchard_bundle(None);
		let existing_empty = crate::tx::hash_empty_orchard();
		assert_eq!(empty, existing_empty, "empty orchard hash should match existing stub");
	}

	#[test]
	fn test_hash_orchard_with_actions() {
		let action = make_dummy_action(0xAA);
		let bundle = OrchardBundle {
			actions: vec![action],
			flags: 0x03,
			value_balance: 1000,
			anchor: [0xBB; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};

		let hash = hash_orchard_bundle(Some(&bundle));
		let empty = hash_orchard_bundle(None);
		assert_ne!(hash, empty, "hash with actions should differ from empty");
		assert_ne!(hash, [0u8; 32], "hash should be non-zero");
	}

	#[test]
	fn test_hash_orchard_deterministic() {
		let _action = make_dummy_action(0xCC);
		let bundle1 = OrchardBundle {
			actions: vec![make_dummy_action(0xCC)],
			flags: 0x03,
			value_balance: 500,
			anchor: [0xDD; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};
		let bundle2 = OrchardBundle {
			actions: vec![make_dummy_action(0xCC)],
			flags: 0x03,
			value_balance: 500,
			anchor: [0xDD; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};
		assert_eq!(
			hash_orchard_bundle(Some(&bundle1)),
			hash_orchard_bundle(Some(&bundle2)),
			"identical bundles should produce identical hashes",
		);
	}

	#[test]
	fn test_hash_orchard_varies_with_flags() {
		let _action = make_dummy_action(0x11);
		let b1 = OrchardBundle {
			actions: vec![make_dummy_action(0x11)],
			flags: 0x01,
			value_balance: 0,
			anchor: [0; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};
		let b2 = OrchardBundle {
			actions: vec![make_dummy_action(0x11)],
			flags: 0x03,
			value_balance: 0,
			anchor: [0; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};
		assert_ne!(
			hash_orchard_bundle(Some(&b1)),
			hash_orchard_bundle(Some(&b2)),
			"different flags should produce different hashes",
		);
	}

	#[test]
	fn test_full_sighash_with_orchard() {
		let bundle = OrchardBundle {
			actions: vec![make_dummy_action(0x22)],
			flags: 0x03,
			value_balance: 1000,
			anchor: [0x33; 32],
			proofs: Vec::new(),
			spend_auth_sigs: Vec::new(),
			binding_sig: [0u8; 64],
		};

		let with_orchard = compute_v5_sighash_full(
			&[], &[], 0,
			Some(&bundle),
			0xc2d6_d0b4, 100,
		);

		let without_orchard = compute_v5_sighash_full(
			&[], &[], 0,
			None,
			0xc2d6_d0b4, 100,
		);

		assert_ne!(with_orchard, without_orchard, "sighash should differ with Orchard bundle");
	}

	#[test]
	fn test_parse_orchard_actions() {
		let action = make_dummy_action(0x44);
		let wire = serialise_action(&action);
		assert_eq!(wire.len(), ACTION_WIRE_SIZE);

		let parsed = parse_orchard_actions(&wire).unwrap();
		assert_eq!(parsed.len(), 1);
		assert_eq!(parsed[0].cv_net, action.cv_net);
		assert_eq!(parsed[0].nullifier, action.nullifier);
		assert_eq!(parsed[0].rk, action.rk);
		assert_eq!(parsed[0].cmx, action.cmx);
	}

	#[test]
	fn test_parse_orchard_actions_invalid_size() {
		let bad_data = vec![0u8; 100];
		assert!(parse_orchard_actions(&bad_data).is_err());
	}

	#[test]
	fn test_ffi_compute_sighash() {
		let action = make_dummy_action(0x55);
		let wire = serialise_action(&action);
		let actions_slice = go_slice::from(wire.as_slice());
		let anchor = [0x66u8; 32];
		let anchor_slice = go_slice::from(anchor.as_ref());
		let mut sighash_buf = tss_buffer::empty();

		assert_eq!(
			frozt_orchard_compute_sighash(
				0, 0,
				Some(&actions_slice),
				0x03, 1000,
				Some(&anchor_slice),
				0xc2d6_d0b4, 100,
				Some(&mut sighash_buf),
			),
			lib_error::LIB_OK,
		);

		let sighash = sighash_buf.into_vec();
		assert_eq!(sighash.len(), 32);
		assert_ne!(sighash, vec![0u8; 32]);
	}
}
