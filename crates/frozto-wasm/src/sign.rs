#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use frost_core::round1::SigningCommitments;
#[cfg(test)]
use frost_core::round2::SignatureShare;

#[cfg(test)]
use wasm_bindgen::prelude::*;

#[cfg(test)]
use crate::{codec, to_js_err, Identifier, P};

#[cfg(test)]
pub(crate) fn decode_commitments_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, SigningCommitments<P>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| SigningCommitments::<P>::deserialize(b).map_err(to_js_err),
    )
}

#[cfg(test)]
pub(crate) fn decode_shares_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, SignatureShare<P>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| SignatureShare::<P>::deserialize(b).map_err(to_js_err),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::keys::{KeyPackage, PublicKeyPackage};
    use frost_core::round1::SigningNonces;
    use frost_core::SigningPackage;
    use frost_rerandomized::{Randomizer, RandomizedParams};
    use crate::keygen::tests::run_dkg_native;
    use wasm_bindgen_test::*;

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

    #[test]
    fn test_sign_2x3() {
        let dkg_results = run_dkg_native(3, 2);
        let signer_indices = [0usize, 1];
        let signer_ids: Vec<u16> =
            signer_indices.iter().map(|i| (*i + 1) as u16).collect();

        let mut nonce_list = Vec::new();
        let mut commitments_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for &idx in &signer_indices {
            let kp = &dkg_results[idx].0;
            let kp_obj = KeyPackage::<P>::deserialize(kp).unwrap();

            let mut rng = rand::thread_rng();
            let (nonces, commitments) =
                frost_core::round1::commit(kp_obj.signing_share(), &mut rng);

            let nonces_bytes = nonces.serialize().unwrap();
            let commitments_bytes = commitments.serialize().unwrap();

            nonce_list.push(nonces_bytes);
            commitments_entries
                .push((signer_ids[commitments_entries.len()], commitments_bytes));
        }

        let commitments_map = encode_id_map(&commitments_entries);
        let pkp_bytes = &dkg_results[signer_indices[0]].1;
        let pkp = PublicKeyPackage::<P>::deserialize(pkp_bytes).unwrap();

        let message = b"test message for frozto signing";

        let commitments_decoded = decode_commitments_map(&commitments_map).unwrap();
        let signing_package =
            SigningPackage::<P>::new(commitments_decoded, message.as_ref());

        let randomized_params = RandomizedParams::<P>::new(
            pkp.verifying_key(),
            &signing_package,
            rand::thread_rng(),
        )
        .unwrap();

        let randomizer_bytes = randomized_params.randomizer().serialize();
        let sp_bytes = signing_package.serialize().unwrap();

        let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for (i, &idx) in signer_indices.iter().enumerate() {
            let sp = SigningPackage::<P>::deserialize(&sp_bytes).unwrap();
            let nonces =
                SigningNonces::<P>::deserialize(&nonce_list[i]).unwrap();
            let kp = KeyPackage::<P>::deserialize(&dkg_results[idx].0).unwrap();
            let randomizer =
                Randomizer::<P>::deserialize(&randomizer_bytes).unwrap();

            let share =
                frost_rerandomized::sign(&sp, &nonces, &kp, randomizer).unwrap();

            share_entries.push((signer_ids[i], share.serialize()));
        }

        let shares_map = encode_id_map(&share_entries);
        let shares_decoded = decode_shares_map(&shares_map).unwrap();
        let sp = SigningPackage::<P>::deserialize(&sp_bytes).unwrap();
        let randomizer =
            Randomizer::<P>::deserialize(&randomizer_bytes).unwrap();
        let randomized_params =
            RandomizedParams::<P>::from_randomizer(pkp.verifying_key(), randomizer);

        let signature = frost_rerandomized::aggregate(
            &sp,
            &shares_decoded,
            &pkp,
            &randomized_params,
        )
        .unwrap();

        let sig_bytes = signature.serialize().unwrap();
        assert!(!sig_bytes.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_sign_2x3_wasm() {
        test_sign_2x3();
    }
}
