use group::ff::Field;
use orchard::keys::FullViewingKey;
use pasta_curves::pallas;
use reddsa::frost::redpallas::PallasBlake2b512;
use zcash_address::unified::Encoding;

use crate::{
	bytes::*,
	errors::*,
};

type P = PallasBlake2b512;

/// Orchard extras layout (64 bytes total):
///   [0..32]  — nk bytes  (NullifierDerivingKey, Pallas base field element)
///   [32..64] — rivk bytes (CommitIvkRandomness, Pallas scalar field element)
pub const ORCHARD_EXTRAS_LEN: usize = 64;

/// Generate random Orchard extras (nk, rivk).
///
/// nk must be a valid Pallas base field element.
/// rivk must be a valid Pallas scalar field element.
/// These are generated once during DKG and stored alongside the key share.
/// Combined with the FROST group public key (which becomes the
/// SpendValidatingKey), they form the Orchard FullViewingKey.
pub fn generate_orchard_extras_raw() -> Result<Vec<u8>, lib_error> {
	use group::ff::PrimeField;
	let mut rng = rand::thread_rng();
	let mut extras = vec![0u8; ORCHARD_EXTRAS_LEN];

	let nk = pallas::Base::random(&mut rng);
	extras[..32].copy_from_slice(&nk.to_repr());

	let rivk = pallas::Scalar::random(&mut rng);
	extras[32..64].copy_from_slice(&rivk.to_repr());

	Ok(extras)
}

/// Build an Orchard FullViewingKey from the FROST group public key + extras.
///
/// The group verifying key (32 bytes on Pallas) becomes the SpendValidatingKey (ak).
/// extras[0..32] = nk bytes, extras[32..64] = rivk bytes.
/// The full FVK is constructed as 96 bytes: ak || nk || rivk, then parsed.
///
/// `pkp_data` accepts either:
///   - the already-serialized 32-byte group verifying key (i.e. the
///     `group_public` hex that `orchard-frost-wasm` exposes and that callers
///     store in `OrchardKeyBundle.publicKeyPackage.groupPublic`), or
///   - a full `frost_core::keys::PublicKeyPackage<PallasBlake2b512>` byte
///     string (used by in-tree keygen tests).
///
/// Both paths extract the 32-byte ak; passing 32 bytes directly is preferred
/// because the PublicKeyPackage serialisation is version-specific across
/// frost-core crate majors and is brittle to carry across language
/// boundaries.
pub fn build_orchard_fvk(
	pkp_data: &[u8],
	extras: &[u8],
) -> Result<FullViewingKey, lib_error> {
	if extras.len() != ORCHARD_EXTRAS_LEN {
		return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
	}

	let ak_bytes: [u8; 32] = if pkp_data.len() == 32 {
		let mut ak = [0u8; 32];
		ak.copy_from_slice(pkp_data);
		ak
	} else {
		let pkp = frost_core::keys::PublicKeyPackage::<P>::deserialize(pkp_data)
			.map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
		let ak_serialized = pkp.verifying_key().serialize()
			.map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
		ak_serialized.as_ref().try_into()
			.map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?
	};

	let mut fvk_raw = [0u8; 96];
	fvk_raw[..32].copy_from_slice(&ak_bytes);
	fvk_raw[32..64].copy_from_slice(&extras[..32]);  // nk
	fvk_raw[64..96].copy_from_slice(&extras[32..64]); // rivk

	FullViewingKey::from_bytes(&fvk_raw).ok_or(lib_error::LIB_ORCHARD_ERROR)
}

/// Derive Orchard extras from a seed (ZIP-32 Orchard key path).
pub fn derive_orchard_extras_from_seed(
	seed: &[u8],
	account_index: u32,
) -> Result<Vec<u8>, lib_error> {
	if seed.len() != 64 {
		return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
	}

	let account = zip32::AccountId::try_from(account_index)
		.map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;

	let sk = orchard::keys::SpendingKey::from_zip32_seed(
		seed,
		133,   // coin_type for Zcash mainnet
		account,
	).map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;

	let fvk = FullViewingKey::from(&sk);
	let fvk_bytes = fvk.to_bytes();

	// FVK bytes layout: [0..32] = ak, [32..64] = nk, [64..96] = rivk
	let mut extras = vec![0u8; ORCHARD_EXTRAS_LEN];
	extras[..32].copy_from_slice(&fvk_bytes[32..64]);  // nk
	extras[32..64].copy_from_slice(&fvk_bytes[64..96]); // rivk

	Ok(extras)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_orchard_generate_extras(
	out_extras: Option<&mut tss_buffer>,
) -> lib_error {
	with_error_handler(|| {
		let out = out_extras.ok_or(lib_error::LIB_NULL_PTR)?;
		let extras = generate_orchard_extras_raw()?;
		*out = tss_buffer::from_vec(extras);
		Ok(())
	})
}

/// Derive Orchard keys from the FROST group public key + extras.
/// Returns the default Orchard address (raw bytes) and the IVK.
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_orchard_derive_keys(
	pub_key_package: Option<&go_slice>,
	orchard_extras: Option<&go_slice>,
	out_address: Option<&mut tss_buffer>,
	out_ivk: Option<&mut tss_buffer>,
) -> lib_error {
	with_error_handler(|| {
		let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
		let extras_data = orchard_extras.ok_or(lib_error::LIB_NULL_PTR)?;
		let out_addr = out_address.ok_or(lib_error::LIB_NULL_PTR)?;
		let out_i = out_ivk.ok_or(lib_error::LIB_NULL_PTR)?;

		let fvk = build_orchard_fvk(pkp_data.as_slice(), extras_data.as_slice())?;

		let ivk = fvk.to_ivk(orchard::keys::Scope::External);
		let address = fvk.address_at(0u64, orchard::keys::Scope::External);

		*out_addr = tss_buffer::from_vec(address.to_raw_address_bytes().to_vec());
		*out_i = tss_buffer::from_vec(ivk.to_bytes().to_vec());

		Ok(())
	})
}

/// Build the Orchard FullViewingKey bytes (96 bytes: ak || nk || rivk).
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_orchard_build_fvk(
	pub_key_package: Option<&go_slice>,
	orchard_extras: Option<&go_slice>,
	out_fvk: Option<&mut tss_buffer>,
) -> lib_error {
	with_error_handler(|| {
		let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
		let extras_data = orchard_extras.ok_or(lib_error::LIB_NULL_PTR)?;
		let out = out_fvk.ok_or(lib_error::LIB_NULL_PTR)?;

		let fvk = build_orchard_fvk(pkp_data.as_slice(), extras_data.as_slice())?;
		*out = tss_buffer::from_vec(fvk.to_bytes().to_vec());

		Ok(())
	})
}

/// Build a unified address containing the Orchard receiver (and optionally Sapling/P2PKH).
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_orchard_build_unified_address(
	pub_key_package: Option<&go_slice>,
	orchard_extras: Option<&go_slice>,
	diversifier_index: u64,
	out_address: Option<&mut tss_buffer>,
) -> lib_error {
	with_error_handler(|| {
		let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
		let extras_data = orchard_extras.ok_or(lib_error::LIB_NULL_PTR)?;
		let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

		let fvk = build_orchard_fvk(pkp_data.as_slice(), extras_data.as_slice())?;

		let address = fvk.address_at(diversifier_index, orchard::keys::Scope::External);
		let orchard_receiver = zcash_address::unified::Receiver::Orchard(
			address.to_raw_address_bytes(),
		);

		let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])
			.map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;

		let encoded = ua.encode(&zcash_protocol::consensus::NetworkType::Main);
		*out = tss_buffer::from_vec(encoded.into_bytes());

		Ok(())
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_orchard_generate_and_derive_keys() {
		let dkg_results = crate::orchard_keygen::tests::run_orchard_dkg(3, 2);
		let pkp = &dkg_results[0].1;

		let mut extras_buf = tss_buffer::empty();
		assert_eq!(
			frozt_orchard_generate_extras(Some(&mut extras_buf)),
			lib_error::LIB_OK,
		);
		let extras = extras_buf.into_vec();
		assert_eq!(extras.len(), ORCHARD_EXTRAS_LEN);

		let pkp_slice = go_slice::from(pkp.as_slice());
		let extras_slice = go_slice::from(extras.as_slice());

		let mut addr_buf = tss_buffer::empty();
		let mut ivk_buf = tss_buffer::empty();

		assert_eq!(
			frozt_orchard_derive_keys(
				Some(&pkp_slice),
				Some(&extras_slice),
				Some(&mut addr_buf),
				Some(&mut ivk_buf),
			),
			lib_error::LIB_OK,
		);

		let addr = addr_buf.into_vec();
		let ivk = ivk_buf.into_vec();

		assert_eq!(addr.len(), 43, "Orchard raw address is 43 bytes");
		assert!(!ivk.is_empty(), "IVK should be non-empty");
	}

	#[test]
	fn test_orchard_build_fvk() {
		let dkg_results = crate::orchard_keygen::tests::run_orchard_dkg(3, 2);
		let pkp = &dkg_results[0].1;

		let mut extras_buf = tss_buffer::empty();
		assert_eq!(
			frozt_orchard_generate_extras(Some(&mut extras_buf)),
			lib_error::LIB_OK,
		);
		let extras = extras_buf.into_vec();

		let pkp_slice = go_slice::from(pkp.as_slice());
		let extras_slice = go_slice::from(extras.as_slice());
		let mut fvk_buf = tss_buffer::empty();

		assert_eq!(
			frozt_orchard_build_fvk(
				Some(&pkp_slice),
				Some(&extras_slice),
				Some(&mut fvk_buf),
			),
			lib_error::LIB_OK,
		);

		let fvk_bytes = fvk_buf.into_vec();
		assert_eq!(fvk_bytes.len(), 96, "Orchard FVK is 96 bytes (ak || nk || rivk)");
	}

	#[test]
	fn test_orchard_build_unified_address() {
		let dkg_results = crate::orchard_keygen::tests::run_orchard_dkg(3, 2);
		let pkp = &dkg_results[0].1;

		let mut extras_buf = tss_buffer::empty();
		assert_eq!(
			frozt_orchard_generate_extras(Some(&mut extras_buf)),
			lib_error::LIB_OK,
		);
		let extras = extras_buf.into_vec();

		let pkp_slice = go_slice::from(pkp.as_slice());
		let extras_slice = go_slice::from(extras.as_slice());
		let mut addr_buf = tss_buffer::empty();

		assert_eq!(
			frozt_orchard_build_unified_address(
				Some(&pkp_slice),
				Some(&extras_slice),
				0,
				Some(&mut addr_buf),
			),
			lib_error::LIB_OK,
		);

		let addr_str = String::from_utf8(addr_buf.into_vec()).unwrap();
		assert!(addr_str.starts_with("u1"), "Unified address should start with u1: {}", addr_str);
	}

	#[test]
	fn test_orchard_deterministic_from_seed() {
		let seed = hex::decode(
			"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
			 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
		).unwrap();

		let extras = derive_orchard_extras_from_seed(&seed, 0).unwrap();
		assert_eq!(extras.len(), ORCHARD_EXTRAS_LEN);

		let extras2 = derive_orchard_extras_from_seed(&seed, 0).unwrap();
		assert_eq!(extras, extras2, "deterministic derivation should be identical");

		let extras_acct1 = derive_orchard_extras_from_seed(&seed, 1).unwrap();
		assert_ne!(extras, extras_acct1, "different accounts should produce different extras");
	}

	#[test]
	fn test_orchard_invalid_extras_size() {
		let dkg_results = crate::orchard_keygen::tests::run_orchard_dkg(3, 2);
		let pkp = &dkg_results[0].1;

		let bad_extras = vec![0u8; 32];
		let pkp_slice = go_slice::from(pkp.as_slice());
		let extras_slice = go_slice::from(bad_extras.as_slice());
		let mut fvk_buf = tss_buffer::empty();

		assert_eq!(
			frozt_orchard_build_fvk(
				Some(&pkp_slice),
				Some(&extras_slice),
				Some(&mut fvk_buf),
			),
			lib_error::LIB_INVALID_BUFFER_SIZE,
		);
	}
}
