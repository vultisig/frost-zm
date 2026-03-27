use frost_ed25519::Ed25519Sha512;
use serde_json::{json, Value};

use crate::common;

type E = Ed25519Sha512;

pub fn generate() -> Value {
    let seed = [0xABu8; 32];

    println!("  Deriving keys from seed...");
    let (spend_key, view_key) =
        fromtlib::ceremony::key_import::derive_keys_from_seed(&seed).unwrap();
    let spend_pub = fromtlib::ceremony::key_import::spend_key_to_public(&spend_key).unwrap();

    println!("  Running key import (2-of-3)...");
    let import_bundles = run_key_import(3, 2, &spend_key, &spend_pub);

    println!("  Running DKG (2-of-3)...");
    let dkg_bundles = run_dkg(3, 2);

    let import_bundle0 =
        fromtlib::keyshare::bundle::KeyShareBundle::deserialize(&import_bundles[0]).unwrap();
    let import_vk = import_bundle0
        .pub_key_package
        .verifying_key()
        .serialize()
        .unwrap();

    let dkg_bundle0 =
        fromtlib::keyshare::bundle::KeyShareBundle::deserialize(&dkg_bundles[0]).unwrap();
    let dkg_vk = dkg_bundle0
        .pub_key_package
        .verifying_key()
        .serialize()
        .unwrap();

    println!("  Deriving Monero addresses...");
    let import_vk_slice: &[u8] = import_vk.as_ref();
    let import_vk_arr: [u8; 32] = import_vk_slice[..32].try_into().unwrap();
    let import_addr = fromtlib::monero::address::derive_address(
        &import_vk_arr,
        &import_bundle0.metadata.view_key,
        0,
    )
    .unwrap();
    println!("    Import main address: {}", import_addr);

    let mut subaddresses = Vec::new();
    for (account, index) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        let sub = fromtlib::monero::subaddress::derive_subaddress(
            &import_vk_arr,
            &import_bundle0.metadata.view_key,
            account,
            index,
            0,
        )
        .unwrap();
        println!("    Subaddress ({},{}): {}", account, index, sub);
        subaddresses.push(json!({
            "account": account,
            "index": index,
            "address": sub,
        }));
    }

    let message = b"test message for fromt signing";
    let mut signing_vectors = Vec::new();

    for (label, signers) in [("1,2", &[0usize, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])]
    {
        println!("  Signing with import keys, signers [{}]...", label);
        let sig = run_sign(&import_bundles, signers);
        let verified = fromtlib::ceremony::sign::verify_signature(
            message,
            &sig,
            &import_bundles[signers[0]],
        )
        .is_ok();
        assert!(verified, "signature should verify for signers [{}]", label);

        signing_vectors.push(json!({
            "source": "key_import",
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(&sig),
            "verified": verified,
        }));
    }

    let sighash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        h[31] = 0xCD;
        h
    };
    println!("  Signing sighash...");
    let sig_sh = run_sign_with_msg(&import_bundles, &[0, 1], &sighash);
    let sh_verified = fromtlib::ceremony::sign::verify_signature(
        &sighash,
        &sig_sh,
        &import_bundles[0],
    )
    .is_ok();
    assert!(sh_verified);
    signing_vectors.push(json!({
        "source": "key_import",
        "signers": [1, 2],
        "message_hex": hex::encode(&sighash),
        "message_type": "sighash",
        "signature_hex": hex::encode(&sig_sh),
        "verified": sh_verified,
    }));

    for (label, signers) in [("1,2", &[0usize, 1][..]), ("2,3", &[1, 2][..]), ("1,3", &[0, 2][..])]
    {
        println!("  Signing with DKG keys, signers [{}]...", label);
        let sig = run_sign(&dkg_bundles, signers);
        let verified = fromtlib::ceremony::sign::verify_signature(
            message,
            &sig,
            &dkg_bundles[signers[0]],
        )
        .is_ok();
        assert!(verified);
        signing_vectors.push(json!({
            "source": "dkg",
            "signers": signers.iter().map(|i| i + 1).collect::<Vec<_>>(),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(&sig),
            "verified": verified,
        }));
    }

    println!("  Computing key images...");
    let key_images = generate_key_images(&import_bundles);

    json!({
        "chain": "fromt",
        "version": 1,
        "threshold": { "min_signers": 2, "max_signers": 3 },

        "key_import": {
            "seed_hex": hex::encode(&seed),
            "spend_key_hex": hex::encode(&spend_key),
            "view_key_hex": hex::encode(&view_key),
            "spend_public_key_hex": hex::encode(&spend_pub),
            "bundles": {
                "1": hex::encode(&import_bundles[0]),
                "2": hex::encode(&import_bundles[1]),
                "3": hex::encode(&import_bundles[2]),
            },
            "verifying_key_hex": hex::encode(import_vk_slice),
            "aggregated_view_key_hex": hex::encode(&import_bundle0.metadata.view_key),
        },

        "dkg": {
            "bundles": {
                "1": hex::encode(&dkg_bundles[0]),
                "2": hex::encode(&dkg_bundles[1]),
                "3": hex::encode(&dkg_bundles[2]),
            },
            "verifying_key_hex": hex::encode(&dkg_vk as &[u8]),
            "aggregated_view_key_hex": hex::encode(&dkg_bundle0.metadata.view_key),
        },

        "addresses": {
            "main_address": import_addr,
            "network": 0,
            "subaddresses": subaddresses,
        },

        "signing": signing_vectors,

        "key_images": key_images,
    })
}

fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
    let part1 = |id: u16, max: u16, min: u16| {
        fromtlib::ceremony::dkg::dkg_part1(id, max, min).unwrap()
    };
    let part2 = |s: fromtlib::ceremony::dkg::DkgRound1Secret, data: &[u8]| {
        fromtlib::ceremony::dkg::dkg_part2(s, data).unwrap()
    };
    let part3 = |s: fromtlib::ceremony::dkg::DkgRound2Secret, r1: &[u8], r2: &[u8]| {
        fromtlib::ceremony::dkg::dkg_part3(s, r1, r2, 0, 0).unwrap()
    };

    let (bundles, _vk) = common::run_dkg_3phase::<E, _, _>(n, t, part1, part2, part3);
    bundles
}

fn run_key_import(n: u16, t: u16, spend_key: &[u8; 32], expected_pub: &[u8]) -> Vec<Vec<u8>> {
    let expected_pub_owned = expected_pub.to_vec();
    let spend_key_copy = *spend_key;

    let mut secrets = Vec::new();
    let mut packages = Vec::new();

    for i in 1..=n {
        let sk_opt = if i == 1 { Some(&spend_key_copy) } else { None };
        let (secret, pkg) =
            fromtlib::ceremony::key_import::key_import_part1(i, n, t, sk_opt).unwrap();
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
        let r1_map = common::encode_map::<E>(&others);
        let (s2, r2_bytes) =
            fromtlib::ceremony::dkg::dkg_part2(secrets.remove(0), &r1_map).unwrap();
        secrets2.push(s2);
        all_r2.push(common::decode_map::<E>(&r2_bytes));
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

        let r1_enc = common::encode_map::<E>(&r1_others);
        let r2_enc = common::encode_map::<E>(&r2_for_me);

        let (bundle_bytes, _) = fromtlib::ceremony::key_import::key_import_part3(
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

fn run_sign(bundles: &[Vec<u8>], signer_indices: &[usize]) -> Vec<u8> {
    let message = b"test message for fromt signing";
    run_sign_with_msg(bundles, signer_indices, message)
}

fn run_sign_with_msg(bundles: &[Vec<u8>], signer_indices: &[usize], message: &[u8]) -> Vec<u8> {
    let signer_ids: Vec<u16> = signer_indices.iter().map(|i| (*i + 1) as u16).collect();

    let mut nonces_list = Vec::new();
    let mut commit_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let (nonces, commit_bytes) =
            fromtlib::ceremony::sign::sign_commit(&bundles[idx]).unwrap();
        nonces_list.push(nonces);
        commit_entries.push((signer_ids[commit_entries.len()], commit_bytes));
    }

    let commit_map = common::encode_map::<E>(&commit_entries);
    let sp_bytes =
        fromtlib::ceremony::sign::sign_create_package(message, &commit_map).unwrap();

    let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

    for (i, &idx) in signer_indices.iter().enumerate() {
        let nonces = nonces_list.remove(0);
        let share =
            fromtlib::ceremony::sign::sign(&sp_bytes, nonces, &bundles[idx]).unwrap();
        share_entries.push((signer_ids[i], share));
    }

    let shares_map = common::encode_map::<E>(&share_entries);
    fromtlib::ceremony::sign::sign_aggregate(
        &sp_bytes,
        &shares_map,
        &bundles[signer_indices[0]],
    )
    .unwrap()
}

fn generate_key_images(bundles: &[Vec<u8>]) -> Value {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

    let mut test_outputs = Vec::new();
    for seed_byte in 1u8..=3 {
        let scalar =
            curve25519_dalek::Scalar::from_bytes_mod_order([seed_byte; 32]);
        let point = &scalar * ED25519_BASEPOINT_TABLE;
        let output_key = point.compress().to_bytes();

        let mut ko_bytes = [0u8; 32];
        ko_bytes[0] = seed_byte.wrapping_add(42);
        let key_offset =
            curve25519_dalek::Scalar::from_bytes_mod_order(ko_bytes).to_bytes();

        test_outputs.push(fromtlib::ceremony::key_image::KeyImageOutput {
            output_key,
            key_offset,
        });
    }

    let outputs_data = fromtlib::ceremony::key_image::encode_outputs(&test_outputs);

    let signer_ids: Vec<u16> = vec![1, 2];
    let mut signer_ids_bytes = Vec::new();
    signer_ids_bytes.extend_from_slice(&(signer_ids.len() as u32).to_le_bytes());
    for id in &signer_ids {
        signer_ids_bytes.extend_from_slice(&(*id as u32).to_le_bytes());
    }

    let (state1, partial1) = fromtlib::ceremony::key_image::key_image_part1(
        &bundles[0],
        &outputs_data,
        &signer_ids,
    )
    .unwrap();

    let (state2, partial2) = fromtlib::ceremony::key_image::key_image_part1(
        &bundles[1],
        &outputs_data,
        &signer_ids,
    )
    .unwrap();

    let ki1 = fromtlib::ceremony::key_image::key_image_part2(
        state1,
        &[(2u16, partial2.clone())],
    )
    .unwrap();

    let ki2 = fromtlib::ceremony::key_image::key_image_part2(
        state2,
        &[(1u16, partial1.clone())],
    )
    .unwrap();

    assert_eq!(ki1, ki2, "key images from different parties should match");

    let mut key_image_entries = Vec::new();
    for (i, output) in test_outputs.iter().enumerate() {
        let start = i * 32;
        let end = start + 32;
        key_image_entries.push(json!({
            "output_key_hex": hex::encode(&output.output_key),
            "key_offset_hex": hex::encode(&output.key_offset),
            "key_image_hex": hex::encode(&ki1[start..end]),
        }));
    }

    json!({
        "signers": [1, 2],
        "outputs": key_image_entries,
        "key_images_consistent_across_parties": true,
    })
}
