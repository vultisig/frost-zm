use std::collections::BTreeMap;

use frost_core::keys::KeyPackage;
use frost_core::keys::PublicKeyPackage;
use frost_core::round1::SigningCommitments;
use frost_core::round1::SigningNonces;
use frost_core::round2::SignatureShare;
use frost_core::SigningPackage;
use frost_rerandomized::Randomizer;
use frost_rerandomized::RandomizedParams;
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::{
    bytes::*,
    codec,
    errors::*,
    handle::Handle,
};

type P = PallasBlake2b512;
type Identifier = frost_core::Identifier<P>;

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozto serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

fn decode_shares_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, SignatureShare<P>>, lib_error> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(ser_err),
        |b| SignatureShare::<P>::deserialize(b).map_err(ser_err),
    )
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_sign_commit(
    key_package: Option<&go_slice>,
    out_nonces: Option<&mut Handle>,
    out_commitments: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_nonces = out_nonces.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_commitments = out_commitments.ok_or(lib_error::LIB_NULL_PTR)?;

        let kp = KeyPackage::<P>::deserialize(kp_data.as_slice()).map_err(ser_err)?;

        let (nonces, commitments_bytes) =
            frost_ceremony::sign::sign_commit::<P>(&kp)?;

        *out_nonces = Handle::allocate(nonces)?;
        *out_commitments = tss_buffer::from_vec(commitments_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_sign_new_package(
    message: Option<&go_slice>,
    commitments_map: Option<&go_slice>,
    pub_key_package: Option<&go_slice>,
    out_signing_package: Option<&mut tss_buffer>,
    out_randomizer_seed: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let cm_data = commitments_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sp = out_signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_seed = out_randomizer_seed.ok_or(lib_error::LIB_NULL_PTR)?;

        let commitments: BTreeMap<Identifier, SigningCommitments<P>> = codec::decode_map(
            cm_data.as_slice(),
            |b| Identifier::deserialize(b).map_err(ser_err),
            |b| SigningCommitments::<P>::deserialize(b).map_err(ser_err),
        )?;
        let pkp = PublicKeyPackage::<P>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;

        let signing_package = SigningPackage::<P>::new(commitments, msg.as_slice());

        let randomized_params = RandomizedParams::<P>::new(
            pkp.verifying_key(),
            &signing_package,
            rand::thread_rng(),
        )
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

        let randomizer_bytes = randomized_params.randomizer().serialize();
        let sp_bytes = signing_package.serialize().map_err(ser_err)?;

        *out_sp = tss_buffer::from_vec(sp_bytes);
        *out_seed = tss_buffer::from_vec(randomizer_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_sign(
    signing_package: Option<&go_slice>,
    nonces: Handle,
    key_package: Option<&go_slice>,
    randomizer_seed: Option<&go_slice>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp_data = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let seed_data = randomizer_seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_share = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let sp = SigningPackage::<P>::deserialize(sp_data.as_slice()).map_err(ser_err)?;
        let nonces = nonces.take::<SigningNonces<P>>()?;
        let kp = KeyPackage::<P>::deserialize(kp_data.as_slice()).map_err(ser_err)?;

        let randomizer = Randomizer::<P>::deserialize(seed_data.as_slice())
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

        let share = frost_rerandomized::sign(&sp, &nonces, &kp, randomizer)
            .map_err(|e| frost_ceremony::blame::frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

        let share_bytes = share.serialize();

        *out_share = tss_buffer::from_vec(share_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_sign_aggregate(
    signing_package: Option<&go_slice>,
    shares_map: Option<&go_slice>,
    pub_key_package: Option<&go_slice>,
    randomizer_seed: Option<&go_slice>,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp_data = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let sm_data = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let seed_data = randomizer_seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sig = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;

        let sp = SigningPackage::<P>::deserialize(sp_data.as_slice()).map_err(ser_err)?;
        let shares = decode_shares_map(sm_data.as_slice())?;
        let pkp = PublicKeyPackage::<P>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;

        let randomizer = Randomizer::<P>::deserialize(seed_data.as_slice())
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

        let randomized_params =
            RandomizedParams::<P>::from_randomizer(pkp.verifying_key(), randomizer);

        let signature = frost_rerandomized::aggregate(
            &sp,
            &shares,
            &pkp,
            &randomized_params,
        )
        .map_err(|e| frost_ceremony::blame::frost_err_to_blame(e, lib_error::LIB_SIGNING_ERROR))?;

        let sig_bytes = signature.serialize().map_err(ser_err)?;

        *out_sig = tss_buffer::from_vec(sig_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_verify_signature(
    message: Option<&go_slice>,
    signature: Option<&go_slice>,
    pub_key_package: Option<&go_slice>,
    randomizer_seed: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig_data = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let seed_data = randomizer_seed.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkp = PublicKeyPackage::<P>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;
        let randomizer = Randomizer::<P>::deserialize(seed_data.as_slice())
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
        let sig = frost_core::Signature::<P>::deserialize(sig_data.as_slice()).map_err(ser_err)?;

        let randomized_params =
            RandomizedParams::<P>::from_randomizer(pkp.verifying_key(), randomizer);

        randomized_params
            .randomized_verifying_key()
            .verify(msg.as_slice(), &sig)
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

        Ok(())
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg;

    pub fn run_sign(key_results: &[(Vec<u8>, Vec<u8>)], signer_indices: &[usize]) -> (Vec<u8>, Vec<u8>) {
        let signer_ids: Vec<u16> = signer_indices.iter().map(|i| (*i + 1) as u16).collect();

        let mut nonce_handles = Vec::new();
        let mut commitments_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for &idx in signer_indices {
            let kp_slice = go_slice::from(key_results[idx].0.as_slice());

            let mut nonces = Handle::null();
            let mut commitments = tss_buffer::empty();

            assert_eq!(
                frozto_sign_commit(Some(&kp_slice), Some(&mut nonces), Some(&mut commitments)),
                lib_error::LIB_OK,
            );

            nonce_handles.push(nonces);
            commitments_entries.push((signer_ids[commitments_entries.len()], commitments.into_vec()));
        }

        let commitments_map = encode_id_map(&commitments_entries);
        let cm_slice = go_slice::from(commitments_map.as_slice());
        let pkp_slice = go_slice::from(key_results[signer_indices[0]].1.as_slice());

        let message = b"test message for frozto signing";
        let msg_slice = go_slice::from(message.as_ref());

        let mut signing_package = tss_buffer::empty();
        let mut randomizer_seed = tss_buffer::empty();

        assert_eq!(
            frozto_sign_new_package(
                Some(&msg_slice),
                Some(&cm_slice),
                Some(&pkp_slice),
                Some(&mut signing_package),
                Some(&mut randomizer_seed),
            ),
            lib_error::LIB_OK,
        );

        let sp_bytes = signing_package.into_vec();
        let seed_bytes = randomizer_seed.into_vec();

        let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for (i, &idx) in signer_indices.iter().enumerate() {
            let sp_slice = go_slice::from(sp_bytes.as_slice());
            let kp_slice = go_slice::from(key_results[idx].0.as_slice());
            let seed_slice = go_slice::from(seed_bytes.as_slice());

            let mut share = tss_buffer::empty();

            assert_eq!(
                frozto_sign(
                    Some(&sp_slice),
                    nonce_handles[i],
                    Some(&kp_slice),
                    Some(&seed_slice),
                    Some(&mut share),
                ),
                lib_error::LIB_OK,
            );

            share_entries.push((signer_ids[i], share.into_vec()));
        }

        let shares_map = encode_id_map(&share_entries);
        let sm_slice = go_slice::from(shares_map.as_slice());
        let sp_slice = go_slice::from(sp_bytes.as_slice());
        let seed_slice = go_slice::from(seed_bytes.as_slice());

        let mut signature = tss_buffer::empty();

        assert_eq!(
            frozto_sign_aggregate(
                Some(&sp_slice),
                Some(&sm_slice),
                Some(&pkp_slice),
                Some(&seed_slice),
                Some(&mut signature),
            ),
            lib_error::LIB_OK,
        );

        let sig_bytes = signature.into_vec();
        assert!(!sig_bytes.is_empty());
        (sig_bytes, seed_bytes)
    }

    #[test]
    fn test_sign_2x3() {
        let dkg_results = run_dkg(3, 2);
        run_sign(&dkg_results, &[0, 1]);
    }

    #[test]
    fn test_sign_and_verify() {
        let dkg_results = run_dkg(3, 2);

        let message = b"test message for frozto signing";
        let (sig_bytes, randomizer_bytes) = run_sign(&dkg_results, &[0, 1]);

        let msg_slice = go_slice::from(message.as_ref());
        let sig_slice = go_slice::from(sig_bytes.as_slice());
        let pkp_slice = go_slice::from(dkg_results[0].1.as_slice());
        let seed_slice = go_slice::from(randomizer_bytes.as_slice());

        assert_eq!(
            frozto_verify_signature(
                Some(&msg_slice),
                Some(&sig_slice),
                Some(&pkp_slice),
                Some(&seed_slice),
            ),
            lib_error::LIB_OK,
            "valid signature should verify",
        );

        let wrong_msg = b"wrong message";
        let wrong_slice = go_slice::from(wrong_msg.as_ref());
        assert_eq!(
            frozto_verify_signature(
                Some(&wrong_slice),
                Some(&sig_slice),
                Some(&pkp_slice),
                Some(&seed_slice),
            ),
            lib_error::LIB_SIGNING_ERROR,
            "wrong message should fail verification",
        );
    }

    #[test]
    fn test_verify_different_signer_combos() {
        let dkg_results = run_dkg(3, 2);
        let message = b"test message for frozto signing";

        let (sig01, rand01) = run_sign(&dkg_results, &[0, 1]);
        let (sig12, rand12) = run_sign(&dkg_results, &[1, 2]);
        let (sig02, rand02) = run_sign(&dkg_results, &[0, 2]);

        let msg_slice = go_slice::from(message.as_ref());
        let pkp_slice = go_slice::from(dkg_results[0].1.as_slice());

        for (sig, rand, label) in [
            (&sig01, &rand01, "0,1"),
            (&sig12, &rand12, "1,2"),
            (&sig02, &rand02, "0,2"),
        ] {
            let sig_slice = go_slice::from(sig.as_slice());
            let seed_slice = go_slice::from(rand.as_slice());
            assert_eq!(
                frozto_verify_signature(
                    Some(&msg_slice),
                    Some(&sig_slice),
                    Some(&pkp_slice),
                    Some(&seed_slice),
                ),
                lib_error::LIB_OK,
                "signers [{label}] should produce valid signature",
            );
        }
    }

    fn encode_id_map(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (id, v) in entries {
            let id_bytes = Identifier::try_from(*id).unwrap().serialize();
            buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&id_bytes);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        buf
    }
}
