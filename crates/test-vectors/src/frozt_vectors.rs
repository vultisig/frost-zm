use std::collections::BTreeMap;

use frost_core::keys::dkg;
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::SigningPackage;
use frost_rerandomized::{Randomizer, RandomizedParams};
use reddsa::frost::redjubjub::JubjubBlake2b512;
use serde_json::{json, Value};

use crate::common;

type J = JubjubBlake2b512;
type Identifier = frost_core::Identifier<J>;

fn abandon_seed() -> Vec<u8> {
    hex::decode(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    )
    .unwrap()
}

fn run_dkg(n: u16, t: u16) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut secrets1 = Vec::new();
    let mut packages1 = Vec::new();

    for i in 1..=n {
        let (secret, pkg_bytes) =
            frost_ceremony::dkg::dkg_part1::<J>(i, n, t).unwrap();
        secrets1.push(secret);
        packages1.push((i, pkg_bytes));
    }

    let mut secrets2 = Vec::new();
    let mut all_r2: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

    for i in 0..n as usize {
        let others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let r1_map = common::encode_map::<J>(&others);
        let r1_pkgs: BTreeMap<Identifier, dkg::round1::Package<J>> =
            frost_ceremony::dkg::decode_r1_map::<J>(&r1_map).unwrap();
        let (s2, r2_pkgs) = dkg::part2(secrets1.remove(0), &r1_pkgs).unwrap();
        let r2_bytes = frost_ceremony::dkg::encode_r2_map::<J>(&r2_pkgs).unwrap();
        secrets2.push(s2);
        all_r2.push(common::decode_map::<J>(&r2_bytes));
    }

    let mut results = Vec::new();

    for i in 0..n as usize {
        let r1_others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let my_id = (i + 1) as u16;
        let mut r2_for_me = Vec::new();
        for (sender_idx, r2_pkgs) in all_r2.iter().enumerate() {
            if sender_idx == i {
                continue;
            }
            let sender_id = (sender_idx + 1) as u16;
            for (recipient_id, pkg_bytes) in r2_pkgs {
                if *recipient_id == my_id {
                    r2_for_me.push((sender_id, pkg_bytes.clone()));
                }
            }
        }

        let r1_enc = common::encode_map::<J>(&r1_others);
        let r2_enc = common::encode_map::<J>(&r2_for_me);
        let r1_pkgs = frost_ceremony::dkg::decode_r1_map::<J>(&r1_enc).unwrap();
        let r2_pkgs = frost_ceremony::dkg::decode_r2_map::<J>(&r2_enc).unwrap();
        let (kp, pkp) = dkg::part3(&secrets2.remove(0), &r1_pkgs, &r2_pkgs).unwrap();
        let kp_bytes = kp.serialize().unwrap();
        let pkp_bytes = pkp.serialize().unwrap();
        results.push((kp_bytes, pkp_bytes));
    }

    results
}

fn run_key_import(
    n: u16,
    t: u16,
    seed: &[u8],
    account_index: u32,
) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>, Vec<u8>) {
    let sk = froztlib::key_import::derive_spending_key(seed, account_index).unwrap();
    let vk = froztlib::key_import::spending_key_to_vk(&sk).unwrap();
    let extras = froztlib::sapling::derive_extras_from_seed(seed, account_index).unwrap();

    let mut secrets1 = Vec::new();
    let mut packages1 = Vec::new();

    for i in 1..=n {
        let constant_term = if i == 1 {
            use frost_core::{Ciphersuite, Field, Group};
            type F = <<J as Ciphersuite>::Group as Group>::Field;
            let sk_scalar: frost_core::Scalar<J> = F::deserialize(&sk).unwrap();
            frost_ceremony::key_import::derive_constant_term::<J>(sk_scalar, n)
        } else {
            use frost_core::{Ciphersuite, Field, Group};
            type F = <<J as Ciphersuite>::Group as Group>::Field;
            F::one()
        };
        let (secret, pkg_bytes) =
            frost_ceremony::key_import::key_import_part1::<J>(i, n, t, constant_term)
                .unwrap();
        secrets1.push(secret);
        packages1.push((i, pkg_bytes));
    }

    let mut secrets2 = Vec::new();
    let mut all_r2: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

    for i in 0..n as usize {
        let others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let r1_map = common::encode_map::<J>(&others);
        let r1_pkgs = frost_ceremony::dkg::decode_r1_map::<J>(&r1_map).unwrap();
        let (s2, r2_pkgs) = dkg::part2(secrets1.remove(0), &r1_pkgs).unwrap();
        let r2_bytes = frost_ceremony::dkg::encode_r2_map::<J>(&r2_pkgs).unwrap();
        secrets2.push(s2);
        all_r2.push(common::decode_map::<J>(&r2_bytes));
    }

    let mut results = Vec::new();

    for i in 0..n as usize {
        let r1_others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let my_id = (i + 1) as u16;
        let mut r2_for_me = Vec::new();
        for (sender_idx, r2_pkgs) in all_r2.iter().enumerate() {
            if sender_idx == i {
                continue;
            }
            let sender_id = (sender_idx + 1) as u16;
            for (recipient_id, pkg_bytes) in r2_pkgs {
                if *recipient_id == my_id {
                    r2_for_me.push((sender_id, pkg_bytes.clone()));
                }
            }
        }

        let r1_enc = common::encode_map::<J>(&r1_others);
        let r2_enc = common::encode_map::<J>(&r2_for_me);

        let (kp, pkp) =
            frost_ceremony::key_import::key_import_part3::<J>(
                secrets2.remove(0),
                &r1_enc,
                &r2_enc,
                &vk,
            )
            .unwrap();
        let kp_bytes = kp.serialize().unwrap();
        let pkp_bytes = pkp.serialize().unwrap();
        results.push((kp_bytes, pkp_bytes));
    }

    (results, vk, extras)
}

fn run_sign(
    key_results: &[(Vec<u8>, Vec<u8>)],
    signer_indices: &[usize],
    message: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let signer_ids: Vec<u16> = signer_indices.iter().map(|i| (*i + 1) as u16).collect();

    let mut nonces_list: Vec<SigningNonces<J>> = Vec::new();
    let mut commitments_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let kp = KeyPackage::<J>::deserialize(&key_results[idx].0).unwrap();
        let (nonces, commit_bytes) =
            frost_ceremony::sign::sign_commit::<J>(&kp).unwrap();
        nonces_list.push(nonces);
        commitments_entries.push((signer_ids[commitments_entries.len()], commit_bytes));
    }

    let commit_map_bytes = common::encode_map::<J>(&commitments_entries);
    let commitments: BTreeMap<Identifier, SigningCommitments<J>> =
        frost_ffi::codec::decode_map(
            &commit_map_bytes,
            |b| Identifier::deserialize(b).map_err(|_| frost_ffi::errors::lib_error::LIB_SERIALIZATION_ERROR),
            |b| SigningCommitments::<J>::deserialize(b).map_err(|_| frost_ffi::errors::lib_error::LIB_SERIALIZATION_ERROR),
        )
        .unwrap();

    let pkp = PublicKeyPackage::<J>::deserialize(&key_results[signer_indices[0]].1).unwrap();
    let signing_package = SigningPackage::<J>::new(commitments, message);

    let randomized_params = RandomizedParams::<J>::new(
        pkp.verifying_key(),
        &signing_package,
        rand::thread_rng(),
    )
    .unwrap();

    let randomizer_bytes = randomized_params.randomizer().serialize();

    let randomizer = Randomizer::<J>::deserialize(&randomizer_bytes).unwrap();

    let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for (i, &idx) in signer_indices.iter().enumerate() {
        let kp = KeyPackage::<J>::deserialize(&key_results[idx].0).unwrap();
        let share =
            frost_rerandomized::sign(&signing_package, &nonces_list[i], &kp, randomizer)
                .unwrap();
        share_entries.push((signer_ids[i], share.serialize()));
    }

    let shares: BTreeMap<Identifier, SignatureShare<J>> = frost_ffi::codec::decode_map(
        &common::encode_map::<J>(&share_entries),
        |b| Identifier::deserialize(b).map_err(|_| frost_ffi::errors::lib_error::LIB_SERIALIZATION_ERROR),
        |b| SignatureShare::<J>::deserialize(b).map_err(|_| frost_ffi::errors::lib_error::LIB_SERIALIZATION_ERROR),
    )
    .unwrap();

    let randomized_params2 =
        RandomizedParams::<J>::from_randomizer(pkp.verifying_key(), randomizer);

    let signature =
        frost_rerandomized::aggregate(&signing_package, &shares, &pkp, &randomized_params2)
            .unwrap();

    let sig_bytes = signature.serialize().unwrap();
    (sig_bytes, randomizer_bytes)
}

fn verify_sig(
    message: &[u8],
    sig_bytes: &[u8],
    pkp_bytes: &[u8],
    randomizer_bytes: &[u8],
) -> bool {
    let pkp = PublicKeyPackage::<J>::deserialize(pkp_bytes).unwrap();
    let randomizer = Randomizer::<J>::deserialize(randomizer_bytes).unwrap();
    let sig = frost_core::Signature::<J>::deserialize(sig_bytes).unwrap();
    let params = RandomizedParams::<J>::from_randomizer(pkp.verifying_key(), randomizer);
    params
        .randomized_verifying_key()
        .verify(message, &sig)
        .is_ok()
}

fn derive_sapling_keys(pkp_bytes: &[u8], extras: &[u8]) -> (String, Vec<u8>, Vec<u8>) {
    let dfvk_raw = froztlib::sapling::build_dfvk_raw(pkp_bytes, extras).unwrap();
    let dfvk =
        sapling_crypto::zip32::DiversifiableFullViewingKey::from_bytes(&dfvk_raw).unwrap();

    let (_, addr) = dfvk.default_address();
    let hrp = bech32::Hrp::parse("zs").unwrap();
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes()).unwrap();

    let ivk = dfvk.fvk().vk.ivk();
    use group::ff::PrimeField;
    let ivk_bytes = ivk.0.to_repr().to_vec();

    use group::GroupEncoding;
    use sapling_crypto::constants::PROOF_GENERATION_KEY_GENERATOR;
    let nsk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
    let nsk: jubjub::Fr = jubjub::Fr::from_repr(nsk_bytes).unwrap();
    let nk = PROOF_GENERATION_KEY_GENERATOR * nsk;
    let nk_bytes = nk.to_bytes().to_vec();

    (encoded, ivk_bytes, nk_bytes)
}

pub fn generate() -> Value {
    let seed = abandon_seed();

    println!("  Running key import (2-of-3) from abandon seed...");
    let (import_results, expected_vk, extras) = run_key_import(3, 2, &seed, 0);

    let pkp_bytes = &import_results[0].1;
    let (z_addr, ivk, nk) = derive_sapling_keys(pkp_bytes, &extras);
    println!("  Derived sapling address: {}", z_addr);
    assert_eq!(
        z_addr,
        "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta"
    );

    println!("  Running DKG (2-of-3)...");
    let dkg_results = run_dkg(3, 2);

    let message = b"test message for frozt signing";
    let sighash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        h[31] = 0xCD;
        h
    };

    let mut signing_vectors = Vec::new();

    for (label, signers) in [("1,2", &[0, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])] {
        println!("  Signing with import keys, signers [{}]...", label);
        let (sig, rand) = run_sign(&import_results, signers, message);
        let verified = verify_sig(message, &sig, pkp_bytes, &rand);
        assert!(verified, "signature from signers [{}] should verify", label);

        signing_vectors.push(json!({
            "source": "key_import",
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(&sig),
            "randomizer_hex": hex::encode(&rand),
            "verified": verified,
        }));
    }

    println!("  Signing sighash with import keys...");
    let (sig_sh, rand_sh) = run_sign(&import_results, &[0, 1], &sighash);
    let sh_verified = verify_sig(&sighash, &sig_sh, pkp_bytes, &rand_sh);
    assert!(sh_verified);
    signing_vectors.push(json!({
        "source": "key_import",
        "signers": [1, 2],
        "message_hex": hex::encode(&sighash),
        "message_type": "sighash",
        "signature_hex": hex::encode(&sig_sh),
        "randomizer_hex": hex::encode(&rand_sh),
        "verified": sh_verified,
    }));

    for (label, signers) in [("1,2", &[0, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])] {
        println!("  Signing with DKG keys, signers [{}]...", label);
        let (sig, rand) = run_sign(&dkg_results, signers, message);
        let verified = verify_sig(message, &sig, &dkg_results[0].1, &rand);
        assert!(verified);
        signing_vectors.push(json!({
            "source": "dkg",
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(&sig),
            "randomizer_hex": hex::encode(&rand),
            "verified": verified,
        }));
    }

    let dkg_pkp = PublicKeyPackage::<J>::deserialize(&dkg_results[0].1).unwrap();
    let dkg_vk = dkg_pkp.verifying_key().serialize().unwrap();

    json!({
        "chain": "frozt",
        "version": 1,
        "threshold": { "min_signers": 2, "max_signers": 3 },

        "key_import": {
            "seed_hex": hex::encode(&seed),
            "account_index": 0,
            "derived_spending_key_hex": hex::encode(&froztlib::key_import::derive_spending_key(&seed, 0).unwrap()),
            "expected_verifying_key_hex": hex::encode(&expected_vk),
            "key_packages": {
                "1": hex::encode(&import_results[0].0),
                "2": hex::encode(&import_results[1].0),
                "3": hex::encode(&import_results[2].0),
            },
            "pub_key_package_hex": hex::encode(pkp_bytes),
            "verifying_key_hex": hex::encode(&expected_vk),
        },

        "dkg": {
            "key_packages": {
                "1": hex::encode(&dkg_results[0].0),
                "2": hex::encode(&dkg_results[1].0),
                "3": hex::encode(&dkg_results[2].0),
            },
            "pub_key_package_hex": hex::encode(&dkg_results[0].1),
            "verifying_key_hex": hex::encode(&dkg_vk),
        },

        "sapling": {
            "extras_hex": hex::encode(&extras),
            "address": z_addr,
            "ivk_hex": hex::encode(&ivk),
            "nk_hex": hex::encode(&nk),
            "dfvk_hex": hex::encode(&froztlib::sapling::build_dfvk_raw(pkp_bytes, &extras).unwrap()),
        },

        "signing": signing_vectors,
    })
}
