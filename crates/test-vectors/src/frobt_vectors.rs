use frost_secp256k1::Secp256K1Sha256;
use serde_json::{json, Value};

use crate::common;

type S = Secp256K1Sha256;

pub fn generate() -> Value {
    let seed = [0u8; 64];

    println!("  Deriving keys from seed...");
    let (sk, cc, pub_key) = frobtlib::ceremony::key_import::derive_from_seed(&seed, 0).unwrap();

    println!("  Running key import (2-of-3)...");
    let import_bundles = run_key_import(3, 2, &sk, &cc, &pub_key);

    println!("  Running DKG (2-of-3)...");
    let dkg_bundles = run_dkg(3, 2);

    let import_bundle0 =
        frobtlib::keyshare::bundle::KeyShareBundle::deserialize(&import_bundles[0]).unwrap();
    let import_vk = import_bundle0.verifying_key_bytes().unwrap();

    let dkg_bundle0 =
        frobtlib::keyshare::bundle::KeyShareBundle::deserialize(&dkg_bundles[0]).unwrap();
    let dkg_vk = dkg_bundle0.verifying_key_bytes().unwrap();

    println!("  Deriving Bitcoin addresses...");
    let import_root_addr =
        frobtlib::bitcoin::address::derive_root_address(&import_bundles[0]).unwrap();
    println!("    Import root address: {}", import_root_addr);

    let dkg_root_addr =
        frobtlib::bitcoin::address::derive_root_address(&dkg_bundles[0]).unwrap();
    println!("    DKG root address: {}", dkg_root_addr);

    let mut child_addresses = Vec::new();
    for (change, index) in [(0, 0), (0, 1), (1, 0)] {
        let addr = frobtlib::bitcoin::address::derive_address_from_bundle(
            &dkg_bundles[0],
            change,
            index,
        )
        .unwrap();
        println!("    Child ({},{}): {}", change, index, addr);
        child_addresses.push(json!({
            "change": change,
            "index": index,
            "address": addr,
        }));
    }

    let message = b"test message for frobt signing";
    let mut signing_vectors = Vec::new();

    for (label, signers) in [("1,2", &[0usize, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])]
    {
        println!("  Regular signing with import keys, signers [{}]...", label);
        let sig = run_sign(&import_bundles, signers, message);
        let verified = frobtlib::ceremony::sign::verify_signature(
            message,
            &sig,
            &import_bundles[signers[0]],
        )
        .is_ok();
        assert!(verified);
        signing_vectors.push(json!({
            "source": "key_import",
            "type": "regular",
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(&sig),
            "verified": verified,
        }));
    }

    let taproot_msg = b"taproot test sighash";
    let merkle_root = [0xABu8; 32];

    for (label, signers) in [("1,2", &[0usize, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])]
    {
        println!("  Taproot signing (no merkle) with DKG keys, signers [{}]...", label);
        let sig = run_taproot_sign(&dkg_bundles, signers, taproot_msg, None);
        let verified = frobtlib::ceremony::sign::verify_taproot_signature(
            taproot_msg,
            &sig,
            &dkg_bundles[signers[0]],
            None,
        )
        .is_ok();
        assert!(verified);
        signing_vectors.push(json!({
            "source": "dkg",
            "type": "taproot",
            "merkle_root_hex": null,
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(taproot_msg),
            "signature_hex": hex::encode(&sig),
            "verified": verified,
        }));
    }

    println!("  Taproot signing with merkle root...");
    let sig_mr = run_taproot_sign(&dkg_bundles, &[0, 1], taproot_msg, Some(&merkle_root));
    let verified_mr = frobtlib::ceremony::sign::verify_taproot_signature(
        taproot_msg,
        &sig_mr,
        &dkg_bundles[0],
        Some(&merkle_root),
    )
    .is_ok();
    assert!(verified_mr);
    let fails_without_mr = frobtlib::ceremony::sign::verify_taproot_signature(
        taproot_msg,
        &sig_mr,
        &dkg_bundles[0],
        None,
    )
    .is_err();
    assert!(fails_without_mr);
    signing_vectors.push(json!({
        "source": "dkg",
        "type": "taproot",
        "merkle_root_hex": hex::encode(&merkle_root),
        "signers": [1, 2],
        "message_hex": hex::encode(taproot_msg),
        "signature_hex": hex::encode(&sig_mr),
        "verified": verified_mr,
        "fails_without_merkle_root": fails_without_mr,
    }));

    println!("  Deriving child public keys...");
    let mut child_keys = Vec::new();
    for (change, index) in [(0, 0), (0, 1), (1, 0)] {
        let child_pub =
            frobtlib::ceremony::ckd::derive_child_pubkey(&dkg_bundles[0], change, index)
                .unwrap();
        let child_pub2 =
            frobtlib::ceremony::ckd::derive_child_pubkey(&dkg_bundles[1], change, index)
                .unwrap();
        assert_eq!(child_pub, child_pub2);
        child_keys.push(json!({
            "change": change,
            "index": index,
            "child_pubkey_hex": hex::encode(&child_pub),
        }));
    }

    json!({
        "chain": "frobt",
        "version": 1,
        "threshold": { "min_signers": 2, "max_signers": 3 },

        "key_import": {
            "seed_hex": hex::encode(&seed),
            "account_index": 0,
            "derived_private_key_hex": hex::encode(&sk),
            "derived_chain_code_hex": hex::encode(&cc),
            "derived_public_key_hex": hex::encode(&pub_key),
            "bundles": {
                "1": hex::encode(&import_bundles[0]),
                "2": hex::encode(&import_bundles[1]),
                "3": hex::encode(&import_bundles[2]),
            },
            "verifying_key_hex": hex::encode(&import_vk),
            "chain_code_hex": hex::encode(&import_bundle0.metadata.chain_code),
        },

        "dkg": {
            "bundles": {
                "1": hex::encode(&dkg_bundles[0]),
                "2": hex::encode(&dkg_bundles[1]),
                "3": hex::encode(&dkg_bundles[2]),
            },
            "verifying_key_hex": hex::encode(&dkg_vk),
            "chain_code_hex": hex::encode(&dkg_bundle0.metadata.chain_code),
        },

        "addresses": {
            "import_root_address": import_root_addr,
            "dkg_root_address": dkg_root_addr,
            "child_addresses": child_addresses,
        },

        "signing": signing_vectors,

        "child_key_derivation": child_keys,
    })
}

fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
    let part1 = |id: u16, max: u16, min: u16| {
        frobtlib::ceremony::dkg::dkg_part1(id, max, min).unwrap()
    };
    let part2 = |s: frobtlib::ceremony::dkg::DkgRound1Secret, data: &[u8]| {
        frobtlib::ceremony::dkg::dkg_part2(s, data).unwrap()
    };
    let part3 = |s: frobtlib::ceremony::dkg::DkgRound2Secret, r1: &[u8], r2: &[u8]| {
        frobtlib::ceremony::dkg::dkg_part3(s, r1, r2, 0, 0).unwrap()
    };

    let (bundles, _vk) = common::run_dkg_3phase::<S, _, _>(n, t, part1, part2, part3);
    bundles
}

fn run_key_import(
    n: u16,
    t: u16,
    private_key: &[u8; 32],
    chain_code: &[u8; 32],
    expected_pub: &[u8],
) -> Vec<Vec<u8>> {
    let expected_pub_owned = expected_pub.to_vec();
    let sk_copy = *private_key;
    let cc_copy = *chain_code;

    let mut secrets = Vec::new();
    let mut packages = Vec::new();

    for i in 1..=n {
        let (sk_opt, cc_opt) = if i == 1 {
            (Some(&sk_copy), Some(&cc_copy))
        } else {
            (None, None)
        };
        let (secret, pkg) =
            frobtlib::ceremony::key_import::key_import_part1(i, n, t, sk_opt, cc_opt)
                .unwrap();
        secrets.push(secret);
        packages.push((i, pkg));
    }

    let mut secrets2 = Vec::new();
    let mut all_r2: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

    for i in 0..n as usize {
        let others: Vec<_> = packages
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let r1_map = common::encode_map::<S>(&others);
        let (s2, r2_bytes) =
            frobtlib::ceremony::dkg::dkg_part2(secrets.remove(0), &r1_map).unwrap();
        secrets2.push(s2);
        all_r2.push(common::decode_map::<S>(&r2_bytes));
    }

    let mut results = Vec::new();

    for i in 0..n as usize {
        let r1_others: Vec<_> = packages
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

        let r1_enc = common::encode_map::<S>(&r1_others);
        let r2_enc = common::encode_map::<S>(&r2_for_me);

        let (bundle_bytes, _) = frobtlib::ceremony::key_import::key_import_part3(
            secrets2.remove(0),
            &r1_enc,
            &r2_enc,
            &expected_pub_owned,
            0,
            0,
        )
        .unwrap();

        results.push(bundle_bytes);
    }

    results
}

fn run_sign(bundles: &[Vec<u8>], signer_indices: &[usize], message: &[u8]) -> Vec<u8> {
    let signer_ids: Vec<u16> = signer_indices.iter().map(|i| (*i + 1) as u16).collect();

    let mut nonces_list = Vec::new();
    let mut commit_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let (nonces, commit_bytes) =
            frobtlib::ceremony::sign::sign_commit(&bundles[idx]).unwrap();
        nonces_list.push(nonces);
        commit_entries.push((signer_ids[commit_entries.len()], commit_bytes));
    }

    let commit_map = common::encode_map::<S>(&commit_entries);
    let sp_bytes =
        frobtlib::ceremony::sign::sign_create_package(message, &commit_map).unwrap();

    let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for (i, &idx) in signer_indices.iter().enumerate() {
        let nonces = nonces_list.remove(0);
        let share =
            frobtlib::ceremony::sign::sign(&sp_bytes, nonces, &bundles[idx]).unwrap();
        share_entries.push((signer_ids[i], share));
    }

    let shares_map = common::encode_map::<S>(&share_entries);
    frobtlib::ceremony::sign::sign_aggregate(
        &sp_bytes,
        &shares_map,
        &bundles[signer_indices[0]],
    )
    .unwrap()
}

fn run_taproot_sign(
    bundles: &[Vec<u8>],
    signer_indices: &[usize],
    message: &[u8],
    merkle_root: Option<&[u8]>,
) -> Vec<u8> {
    let signer_ids: Vec<u16> = signer_indices.iter().map(|i| (*i + 1) as u16).collect();

    let mut nonces_list = Vec::new();
    let mut commit_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let (nonces, commit_bytes) =
            frobtlib::ceremony::sign::sign_commit(&bundles[idx]).unwrap();
        nonces_list.push(nonces);
        commit_entries.push((signer_ids[commit_entries.len()], commit_bytes));
    }

    let commit_map = common::encode_map::<S>(&commit_entries);
    let sp_bytes =
        frobtlib::ceremony::sign::sign_create_package(message, &commit_map).unwrap();

    let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for (i, &idx) in signer_indices.iter().enumerate() {
        let nonces = nonces_list.remove(0);
        let share = frobtlib::ceremony::sign::sign_taproot(
            &sp_bytes,
            nonces,
            &bundles[idx],
            merkle_root,
        )
        .unwrap();
        share_entries.push((signer_ids[i], share));
    }

    let shares_map = common::encode_map::<S>(&share_entries);
    frobtlib::ceremony::sign::sign_aggregate_taproot(
        &sp_bytes,
        &shares_map,
        &bundles[signer_indices[0]],
        merkle_root,
    )
    .unwrap()
}
