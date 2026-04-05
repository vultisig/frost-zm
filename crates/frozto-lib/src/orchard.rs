use group::ff::{Field, PrimeField};
use orchard::keys::{
    FullViewingKey, IncomingViewingKey, Scope, SpendingKey,
};
use orchard::note::ExtractedNoteCommitment;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use orchard::note::{Nullifier, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::Note;
use pasta_curves::pallas;
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
    COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};
use zip32::AccountId;
use zeroize::Zeroize;

use reddsa::frost::redpallas::PallasBlake2b512;

use crate::{
    bytes::*,
    errors::*,
};

type P = PallasBlake2b512;

const EXTRAS_LEN: usize = 64;

pub fn build_fvk_raw(pkp_data: &[u8], extras: &[u8]) -> Result<[u8; 96], lib_error> {
    if extras.len() != EXTRAS_LEN {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let pkp = frost_core::keys::PublicKeyPackage::<P>::deserialize(pkp_data)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    let ak_serialized = pkp
        .verifying_key()
        .serialize()
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let mut fvk_raw = [0u8; 96];
    fvk_raw[..32].copy_from_slice(ak_serialized.as_ref());
    fvk_raw[32..64].copy_from_slice(&extras[..32]);
    fvk_raw[64..96].copy_from_slice(&extras[32..64]);

    Ok(fvk_raw)
}

fn build_fvk(pkp_data: &[u8], extras: &[u8]) -> Result<FullViewingKey, lib_error> {
    let fvk_raw = build_fvk_raw(pkp_data, extras)?;
    FullViewingKey::from_bytes(&fvk_raw).ok_or(lib_error::LIB_ORCHARD_ERROR)
}

pub fn generate_extras_raw() -> Result<Vec<u8>, lib_error> {
    let mut rng = rand::thread_rng();
    let mut extras = [0u8; EXTRAS_LEN];

    let nk = pallas::Base::random(&mut rng);
    let mut nk_repr = nk.to_repr();
    extras[..32].copy_from_slice(&nk_repr);
    nk_repr.zeroize();

    let rivk = pallas::Scalar::random(&mut rng);
    let mut rivk_repr = rivk.to_repr();
    extras[32..64].copy_from_slice(&rivk_repr);
    rivk_repr.zeroize();

    Ok(extras.to_vec())
}

pub fn derive_extras_from_seed(seed: &[u8], account_index: u32) -> Result<Vec<u8>, lib_error> {
    if seed.len() != 64 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let account = AccountId::try_from(account_index)
        .map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;
    let sk = SpendingKey::from_zip32_seed(seed, 133, account)
        .map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;
    let fvk = FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();

    let mut extras = [0u8; EXTRAS_LEN];
    extras[..32].copy_from_slice(&fvk_bytes[32..64]);
    extras[32..64].copy_from_slice(&fvk_bytes[64..96]);

    Ok(extras.to_vec())
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_generate_extras(
    out_orchard_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_orchard_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras = generate_extras_raw()?;
        *out = tss_buffer::from_vec(extras);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_derive_keys(
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

        let fvk = build_fvk(pkp_data.as_slice(), extras_data.as_slice())?;

        let ivk = fvk.to_ivk(Scope::External);
        let addr = ivk.address_at(0u32);

        let addr_bytes = addr.to_raw_address_bytes();
        let ivk_bytes = ivk.to_bytes();

        *out_addr = tss_buffer::from_vec(addr_bytes.to_vec());
        *out_i = tss_buffer::from_vec(ivk_bytes.to_vec());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_build_fvk(
    pub_key_package: Option<&go_slice>,
    orchard_extras: Option<&go_slice>,
    out_fvk: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = orchard_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_fvk.ok_or(lib_error::LIB_NULL_PTR)?;

        let fvk_raw = build_fvk_raw(pkp_data.as_slice(), extras_data.as_slice())?;
        *out = tss_buffer::from_vec(fvk_raw.to_vec());
        Ok(())
    })
}

struct FullOutput {
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_try_decrypt_compact(
    ivk_bytes: Option<&go_slice>,
    nullifier: Option<&go_slice>,
    cmx: Option<&go_slice>,
    ephemeral_key: Option<&go_slice>,
    ciphertext: Option<&go_slice>,
    out_value: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let ivk_data = ivk_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let nf_data = nullifier.ok_or(lib_error::LIB_NULL_PTR)?;
        let cmx_data = cmx.ok_or(lib_error::LIB_NULL_PTR)?;
        let epk_data = ephemeral_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let ct_data = ciphertext.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_value.ok_or(lib_error::LIB_NULL_PTR)?;

        if ivk_data.len() != 64 || cmx_data.len() != 32 || epk_data.len() != 32 || nf_data.len() != 32 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        if ct_data.len() != COMPACT_NOTE_SIZE {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let ivk_arr: [u8; 64] = ivk_data.as_slice()[..64].try_into().unwrap();
        let ivk = IncomingViewingKey::from_bytes(&ivk_arr);
        if ivk.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let ivk = ivk.unwrap();
        let prepared = ivk.prepare();

        let nf_bytes: [u8; 32] = nf_data.as_slice()[..32].try_into().unwrap();
        let nf = Nullifier::from_bytes(&nf_bytes);
        if nf.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let nf = nf.unwrap();

        let cmx_bytes: [u8; 32] = cmx_data.as_slice()[..32].try_into().unwrap();
        let extracted_cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
        if extracted_cmx.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let extracted_cmx = extracted_cmx.unwrap();

        let epk_bytes: [u8; 32] = epk_data.as_slice()[..32].try_into().unwrap();

        let mut enc_ct = [0u8; COMPACT_NOTE_SIZE];
        enc_ct.copy_from_slice(&ct_data.as_slice()[..COMPACT_NOTE_SIZE]);

        let compact = CompactAction::from_parts(
            nf,
            extracted_cmx,
            EphemeralKeyBytes(epk_bytes),
            enc_ct,
        );

        let domain = OrchardDomain::for_compact_action(&compact);
        let result = try_compact_note_decryption(&domain, &prepared, &compact);

        match result {
            Some((note, _addr)) => {
                *out = note.value().inner();
                Ok(())
            }
            None => Err(lib_error::LIB_ORCHARD_ERROR),
        }
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_decrypt_note_full(
    ivk_bytes: Option<&go_slice>,
    nullifier: Option<&go_slice>,
    cmx: Option<&go_slice>,
    ephemeral_key: Option<&go_slice>,
    enc_ciphertext: Option<&go_slice>,
    out_note_data: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ivk_data = ivk_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let nf_data = nullifier.ok_or(lib_error::LIB_NULL_PTR)?;
        let cmx_data = cmx.ok_or(lib_error::LIB_NULL_PTR)?;
        let epk_data = ephemeral_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let ct_data = enc_ciphertext.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_note_data.ok_or(lib_error::LIB_NULL_PTR)?;

        if ivk_data.len() != 64 || cmx_data.len() != 32 || epk_data.len() != 32 || nf_data.len() != 32 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        if ct_data.len() != ENC_CIPHERTEXT_SIZE {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let ivk_arr: [u8; 64] = ivk_data.as_slice()[..64].try_into().unwrap();
        let ivk = IncomingViewingKey::from_bytes(&ivk_arr);
        if ivk.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let ivk = ivk.unwrap();
        let prepared = ivk.prepare();

        let nf_bytes: [u8; 32] = nf_data.as_slice()[..32].try_into().unwrap();
        let nf = Nullifier::from_bytes(&nf_bytes);
        if nf.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let nf = nf.unwrap();

        let cmx_bytes: [u8; 32] = cmx_data.as_slice()[..32].try_into().unwrap();
        let extracted_cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
        if extracted_cmx.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let extracted_cmx = extracted_cmx.unwrap();

        let epk_bytes: [u8; 32] = epk_data.as_slice()[..32].try_into().unwrap();

        let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ct.copy_from_slice(&ct_data.as_slice()[..ENC_CIPHERTEXT_SIZE]);

        let output = FullOutput {
            cmx: extracted_cmx,
            ephemeral_key: EphemeralKeyBytes(epk_bytes),
            enc_ciphertext: enc_ct,
        };

        let dummy_compact = CompactAction::from_parts(
            nf,
            extracted_cmx,
            EphemeralKeyBytes(epk_bytes),
            [0u8; COMPACT_NOTE_SIZE],
        );
        let domain = OrchardDomain::for_compact_action(&dummy_compact);
        let result = try_note_decryption(&domain, &prepared, &output);

        match result {
            Some((note, addr, _memo)) => {
                let rseed_bytes = note.rseed().as_bytes();
                let rho_bytes = note.rho().to_bytes();
                let mut note_data = Vec::with_capacity(83);
                note_data.extend_from_slice(addr.diversifier().as_array());
                note_data.extend_from_slice(&note.value().inner().to_le_bytes());
                note_data.extend_from_slice(rseed_bytes);
                note_data.extend_from_slice(&rho_bytes);
                *out = tss_buffer::from_vec(note_data);
                Ok(())
            }
            None => Err(lib_error::LIB_ORCHARD_ERROR),
        }
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_orchard_compute_nullifier(
    pkp_bytes: Option<&go_slice>,
    extras_bytes: Option<&go_slice>,
    note_data: Option<&go_slice>,
    out_nullifier: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pkp_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = extras_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let nd = note_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_nullifier.ok_or(lib_error::LIB_NULL_PTR)?;

        if nd.len() != 83 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let fvk = build_fvk(pkp_data.as_slice(), extras_data.as_slice())?;

        let nd_slice = nd.as_slice();
        let diversifier_bytes: [u8; 11] = nd_slice[..11].try_into().unwrap();
        let diversifier = orchard::keys::Diversifier::from_bytes(diversifier_bytes);

        let value = u64::from_le_bytes(nd_slice[11..19].try_into().unwrap());

        let rseed_bytes: [u8; 32] = nd_slice[19..51].try_into().unwrap();
        let rho_bytes: [u8; 32] = nd_slice[51..83].try_into().unwrap();

        let rho = Rho::from_bytes(&rho_bytes);
        if rho.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let rho = rho.unwrap();

        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho);
        if rseed.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let rseed = rseed.unwrap();

        let addr = fvk.address(diversifier, Scope::External);
        let note = Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed);
        if note.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let note = note.unwrap();

        let nf = note.nullifier(&fvk);

        *out = tss_buffer::from_vec(nf.to_bytes().to_vec());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchard_generate_extras() {
        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozto_orchard_generate_extras(Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();
        assert_eq!(extras.len(), EXTRAS_LEN);

        let nk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
        let nk: Option<pallas::Base> = pallas::Base::from_repr(nk_bytes).into();
        assert!(nk.is_some(), "nk should be a valid Pallas base field element");

        let rivk_bytes: [u8; 32] = extras[32..64].try_into().unwrap();
        let rivk: Option<pallas::Scalar> = pallas::Scalar::from_repr(rivk_bytes).into();
        assert!(rivk.is_some(), "rivk should be a valid Pallas scalar");
    }

    #[test]
    fn test_orchard_derive_extras_from_seed() {
        let seed = abandon_seed();
        let extras = derive_extras_from_seed(&seed, 0).unwrap();
        assert_eq!(extras.len(), EXTRAS_LEN);

        let extras2 = derive_extras_from_seed(&seed, 0).unwrap();
        assert_eq!(extras, extras2, "deterministic derivation");

        let extras_diff = derive_extras_from_seed(&seed, 1).unwrap();
        assert_ne!(extras, extras_diff, "different account gives different extras");
    }

    #[test]
    fn test_orchard_seedless_derive_keys() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        assert!(!results.is_empty());
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozto_orchard_generate_extras(Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        let mut ivk_buf = tss_buffer::empty();

        assert_eq!(
            frozto_orchard_derive_keys(
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
        assert_eq!(ivk.len(), 64, "Orchard IVK is 64 bytes");
    }

    #[test]
    fn test_orchard_import_and_derive() {
        let seed = abandon_seed();
        let extras = derive_extras_from_seed(&seed, 0).unwrap();

        let import = crate::key_import::tests::run_key_import_with_seed(&seed, 3, 2);
        let pkp = &import.results[0].1;

        let fvk = build_fvk(pkp, &extras);
        assert!(fvk.is_ok(), "should build a valid FVK from imported key + extras");
    }

    #[test]
    fn test_orchard_build_fvk_roundtrip() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = generate_extras_raw().unwrap();

        let fvk_raw = build_fvk_raw(pkp, &extras).unwrap();
        assert_eq!(fvk_raw.len(), 96);

        let fvk = FullViewingKey::from_bytes(&fvk_raw);
        if let Some(fvk) = fvk {
            let roundtrip = fvk.to_bytes();
            assert_eq!(fvk_raw, roundtrip);
        }
    }

    fn abandon_seed() -> Vec<u8> {
        hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap()
    }

    #[test]
    fn e2e_key_import_address_matches_standard_orchard() {
        let seed = abandon_seed();
        let extras = derive_extras_from_seed(&seed, 0).unwrap();

        let account = zip32::AccountId::try_from(0u32).unwrap();
        let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
        let standard_fvk = FullViewingKey::from(&sk);
        let standard_ivk = standard_fvk.to_ivk(Scope::External);
        let standard_addr = standard_ivk.address_at(0u32);
        let standard_addr_bytes = standard_addr.to_raw_address_bytes();

        let import = crate::key_import::tests::run_key_import_with_seed(&seed, 3, 2);
        let pkp = &import.results[0].1;

        let frost_fvk_raw = build_fvk_raw(pkp, &extras).unwrap();
        let frost_fvk = FullViewingKey::from_bytes(&frost_fvk_raw).unwrap();

        assert_eq!(
            standard_fvk.to_bytes()[32..],
            frost_fvk.to_bytes()[32..],
            "nk and rivk must match between standard and FROST FVK"
        );

        let frost_ivk = frost_fvk.to_ivk(Scope::External);
        let frost_addr = frost_ivk.address_at(0u32);
        let frost_addr_bytes = frost_addr.to_raw_address_bytes();

        assert_eq!(
            standard_addr_bytes, frost_addr_bytes,
            "FROST-imported key must produce the same Orchard address as standard derivation"
        );
    }

    #[test]
    fn e2e_encrypt_decrypt_nullifier_cycle() {
        use orchard::note::Nullifier as OrchardNullifier;
        use orchard::note_encryption::testing::fake_compact_action;
        use orchard::value::NoteValue;

        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = generate_extras_raw().unwrap();

        let fvk = build_fvk(pkp, &extras).unwrap();
        let ivk = fvk.to_ivk(Scope::External);
        let addr = ivk.address_at(0u32);

        let mut rng = rand::thread_rng();
        let nf_old = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);
            bytes[31] &= 0x3f;
            OrchardNullifier::from_bytes(&bytes).unwrap()
        };
        let value = NoteValue::from_raw(1_000_000);

        let (compact_action, created_note) =
            fake_compact_action(&mut rng, nf_old, addr, value, None);

        let prepared = ivk.prepare();
        let domain = orchard::note_encryption::OrchardDomain::for_compact_action(&compact_action);
        let decrypted = zcash_note_encryption::try_compact_note_decryption(
            &domain, &prepared, &compact_action,
        );
        assert!(decrypted.is_some(), "must decrypt note addressed to our key");

        let (decrypted_note, decrypted_addr) = decrypted.unwrap();
        assert_eq!(decrypted_note.value(), value);
        assert_eq!(decrypted_addr, addr);

        let nf_created = created_note.nullifier(&fvk);
        let nf_decrypted = decrypted_note.nullifier(&fvk);
        assert_eq!(nf_created, nf_decrypted, "nullifiers must match");

        let wrong_extras = generate_extras_raw().unwrap();
        let wrong_fvk_result = build_fvk(pkp, &wrong_extras);
        if let Ok(wrong_fvk) = wrong_fvk_result {
            let wrong_ivk = wrong_fvk.to_ivk(Scope::External);
            let wrong_prepared = wrong_ivk.prepare();
            let wrong_result = zcash_note_encryption::try_compact_note_decryption(
                &domain, &wrong_prepared, &compact_action,
            );
            assert!(wrong_result.is_none(), "wrong key must NOT decrypt note");
        }
    }

    #[test]
    fn e2e_dkg_sign_verify_redpallas() {
        use reddsa::frost::redpallas::PallasBlake2b512;
        use frost_rerandomized::{Randomizer, RandomizedParams};

        type PP = PallasBlake2b512;

        let dkg_results = crate::keygen::tests::run_dkg(3, 2);
        let (sig_bytes, randomizer_bytes) = crate::sign::tests::run_sign(&dkg_results, &[0, 1]);

        let pkp = frost_core::keys::PublicKeyPackage::<PP>::deserialize(&dkg_results[0].1).unwrap();
        let sig = frost_core::Signature::<PP>::deserialize(&sig_bytes).unwrap();
        let randomizer = Randomizer::<PP>::deserialize(&randomizer_bytes).unwrap();

        let randomized_params =
            RandomizedParams::<PP>::from_randomizer(pkp.verifying_key(), randomizer);
        let result = randomized_params
            .randomized_verifying_key()
            .verify(b"test message for frozto signing", &sig);
        assert!(result.is_ok(), "RedPallas signature must verify");

        let (sig2_bytes, rand2_bytes) = crate::sign::tests::run_sign(&dkg_results, &[1, 2]);
        let sig2 = frost_core::Signature::<PP>::deserialize(&sig2_bytes).unwrap();
        let rand2 = Randomizer::<PP>::deserialize(&rand2_bytes).unwrap();
        let params2 = RandomizedParams::<PP>::from_randomizer(pkp.verifying_key(), rand2);
        let result2 = params2
            .randomized_verifying_key()
            .verify(b"test message for frozto signing", &sig2);
        assert!(result2.is_ok(), "different signer subset must also produce valid sig");
    }

    #[test]
    fn e2e_nullifier_via_ffi_matches_direct() {
        use orchard::note::Nullifier as OrchardNullifier;
        use orchard::note_encryption::testing::fake_compact_action;
        use orchard::value::NoteValue;
        use orchard::note_encryption::OrchardDomain;

        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = generate_extras_raw().unwrap();

        let fvk = build_fvk(pkp, &extras).unwrap();
        let ivk = fvk.to_ivk(Scope::External);
        let addr = ivk.address_at(0u32);

        let mut rng = rand::thread_rng();
        let nf_old = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);
            bytes[31] &= 0x3f;
            OrchardNullifier::from_bytes(&bytes).unwrap()
        };
        let value = NoteValue::from_raw(42_000);

        let (compact_action, note) =
            fake_compact_action(&mut rng, nf_old, addr, value, None);

        let expected_nf = note.nullifier(&fvk);

        let mut note_data = Vec::with_capacity(83);
        note_data.extend_from_slice(addr.diversifier().as_array());
        note_data.extend_from_slice(&note.value().inner().to_le_bytes());
        note_data.extend_from_slice(note.rseed().as_bytes());
        note_data.extend_from_slice(&note.rho().to_bytes());

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let nd_slice = go_slice::from(note_data.as_slice());
        let mut nf_buf = tss_buffer::empty();

        assert_eq!(
            frozto_orchard_compute_nullifier(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&nd_slice),
                Some(&mut nf_buf),
            ),
            lib_error::LIB_OK,
        );

        let nf_ffi = nf_buf.into_vec();
        assert_eq!(nf_ffi, expected_nf.to_bytes().to_vec(), "FFI nullifier must match direct computation");
    }

    #[test]
    fn e2e_compact_decrypt_via_ffi() {
        use orchard::note::Nullifier as OrchardNullifier;
        use orchard::note_encryption::testing::fake_compact_action;
        use orchard::value::NoteValue;

        let results = crate::keygen::tests::run_dkg(3, 2);
        let pkp = &results[0].1;
        let extras = generate_extras_raw().unwrap();

        let fvk = build_fvk(pkp, &extras).unwrap();
        let ivk = fvk.to_ivk(Scope::External);
        let ivk_bytes = ivk.to_bytes();
        let addr = ivk.address_at(0u32);

        let mut rng = rand::thread_rng();
        let nf_old = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);
            bytes[31] &= 0x3f;
            OrchardNullifier::from_bytes(&bytes).unwrap()
        };
        let value = NoteValue::from_raw(500_000);

        let (compact_action, _note) =
            fake_compact_action(&mut rng, nf_old, addr, value, None);

        let ivk_slice = go_slice::from(ivk_bytes.as_ref());
        let nf_bytes = compact_action.nullifier().to_bytes();
        let nf_slice = go_slice::from(nf_bytes.as_ref());
        let cmx_bytes = compact_action.cmx().to_bytes();
        let cmx_slice = go_slice::from(cmx_bytes.as_ref());
        let epk_bytes = compact_action.ephemeral_key().0;
        let epk_slice = go_slice::from(epk_bytes.as_ref());
        let enc_ct = compact_action.enc_ciphertext();
        let enc_slice = go_slice::from(enc_ct.as_ref());

        let mut out_value: u64 = 0;

        assert_eq!(
            frozto_orchard_try_decrypt_compact(
                Some(&ivk_slice),
                Some(&nf_slice),
                Some(&cmx_slice),
                Some(&epk_slice),
                Some(&enc_slice),
                Some(&mut out_value),
            ),
            lib_error::LIB_OK,
        );

        assert_eq!(out_value, 500_000, "decrypted value must match");
    }
}
