use frost_core::{
    Ciphersuite, Field, Group,
};
use frost_ed25519::Ed25519Sha512;
use tiny_keccak::{Hasher, Keccak};

use std::collections::BTreeMap;

use crate::{
    ceremony::dkg::{
        decode_r1_map_with_vk, decode_r2_map, ser_err,
        DkgRound1Secret, DkgRound2Secret,
    },
    errors::lib_error,
};

type E = Ed25519Sha512;
type Identifier = frost_core::Identifier<E>;
type Scalar = frost_core::Scalar<E>;
type F = <<E as Ciphersuite>::Group as Group>::Field;
type G = <E as Ciphersuite>::Group;

pub fn derive_keys_from_seed(
    seed: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), lib_error> {
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(*seed);
    let spend_key_bytes = spend_scalar.to_bytes();

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(&spend_key_bytes);
    keccak.finalize(&mut hash);
    let view_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(hash);
    let view_key_bytes = view_scalar.to_bytes();

    Ok((spend_key_bytes, view_key_bytes))
}

pub fn spend_key_to_public(spend_key: &[u8; 32]) -> Result<Vec<u8>, lib_error> {
    let scalar: Scalar = F::deserialize(spend_key).map_err(ser_err)?;
    let point = <G as Group>::generator() * scalar;
    let point_bytes =
        <E as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;
    let bytes: &[u8] = point_bytes.as_ref();
    Ok(bytes.to_vec())
}

pub fn key_import_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    spend_key: Option<&[u8; 32]>,
) -> Result<(DkgRound1Secret, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    let (constant_term, vk_share_bytes) = match spend_key {
        Some(sk_bytes) => {
            let sk_scalar: Scalar = F::deserialize(sk_bytes).map_err(ser_err)?;
            let ct = frost_ceremony::key_import::derive_constant_term::<E>(sk_scalar, max_signers);

            let mut keccak = Keccak::v256();
            let mut hash = [0u8; 32];
            keccak.update(sk_bytes);
            keccak.finalize(&mut hash);
            let vk_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(hash);
            let vk_bytes: [u8; 32] = vk_scalar.to_bytes();

            (ct, vk_bytes)
        }
        None => (F::one(), [0u8; 32]),
    };

    let (secret, mut pkg_bytes) =
        frost_ceremony::key_import::key_import_part1::<E>(id, max_signers, min_signers, constant_term)?;

    pkg_bytes.extend_from_slice(&vk_share_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        view_key_share: vk_share_bytes,
    };

    Ok((out_secret, pkg_bytes))
}

pub fn key_import_part3(
    secret: DkgRound2Secret,
    r1_data: &[u8],
    r2_data: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, vk_shares) = decode_r1_map_with_vk(r1_data)?;
    let r2_pkgs = decode_r2_map(r2_data)?;

    let (key_package, pub_key_package) =
        frost_core::keys::dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|e| frost_ceremony::blame::frost_err_to_blame(e, lib_error::LIB_DKG_ERROR))?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    let view_key = aggregate_import_view_key(&secret.view_key_share, &vk_shares)?;

    let bundle = crate::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        view_key,
        network,
        birthday,
    );

    let bundle_bytes = bundle.serialize()?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_import_view_key(
    own_share: &[u8; 32],
    other_shares: &BTreeMap<Identifier, [u8; 32]>,
) -> Result<[u8; 32], lib_error> {
    let own_arr: &[u8; 32] = own_share;
    let mut sum: Scalar = F::deserialize(own_arr).map_err(ser_err)?;

    for (_, share_bytes) in other_shares {
        let s: Scalar = F::deserialize(share_bytes).map_err(ser_err)?;
        sum = sum + s;
    }

    let result_serialized = F::serialize(&sum);
    let result: [u8; 32] = result_serialized
        .as_ref()
        .try_into()
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg;
    use crate::ceremony::dkg::tests::{decode_test_map, encode_test_map};
    use crate::keyshare::bundle::KeyShareBundle;

    fn derive_test_key() -> ([u8; 32], [u8; 32], Vec<u8>) {
        let seed = [0xABu8; 32];
        let (sk, vk) = derive_keys_from_seed(&seed).unwrap();
        let pub_key = spend_key_to_public(&sk).unwrap();
        (sk, vk, pub_key)
    }

    pub fn run_key_import(
        n: u16,
        t: u16,
        spend_key: &[u8; 32],
        expected_pub: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut secrets = Vec::new();
        let mut packages = Vec::new();

        for i in 1..=n {
            let sk_opt = if i == 1 { Some(spend_key) } else { None };
            let (secret, pkg) = key_import_part1(i, n, t, sk_opt).unwrap();
            secrets.push(secret);
            packages.push((i, pkg));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..n as usize {
            let others: Vec<_> = packages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let r1_map = encode_test_map(&others);
            let (secret2, r2_bytes) =
                dkg::dkg_part2(secrets.remove(0), &r1_map).unwrap();
            secrets2.push(secret2);
            all_r2_packages.push(decode_test_map(&r2_bytes));
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
            for (sender_idx, r2_pkgs) in all_r2_packages.iter().enumerate() {
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

            let r1_map = encode_test_map(&r1_others);
            let r2_map = encode_test_map(&r2_for_me);

            let (bundle_bytes, _) = key_import_part3(
                secrets2.remove(0),
                &r1_map,
                &r2_map,
                expected_pub,
                0,
                0,
            )
            .unwrap();

            results.push(bundle_bytes);
        }

        results
    }

    #[test]
    fn test_key_import_2of3() {
        let (sk, _vk, pub_key) = derive_test_key();
        let results = run_key_import(3, 2, &sk, &pub_key);
        assert_eq!(results.len(), 3);

        let b0 = KeyShareBundle::deserialize(&results[0]).unwrap();
        let b1 = KeyShareBundle::deserialize(&results[1]).unwrap();
        let b2 = KeyShareBundle::deserialize(&results[2]).unwrap();

        assert_eq!(b0.view_key, b1.view_key);
        assert_eq!(b1.view_key, b2.view_key);

        let vk0 = b0.pub_key_package.verifying_key().serialize().unwrap();
        assert_eq!(vk0, pub_key);
    }

    #[test]
    fn test_derive_keys() {
        let seed = [0xABu8; 32];
        let (sk1, vk1) = derive_keys_from_seed(&seed).unwrap();
        let (sk2, vk2) = derive_keys_from_seed(&seed).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);

        let seed2 = [0xCDu8; 32];
        let (sk3, _) = derive_keys_from_seed(&seed2).unwrap();
        assert_ne!(sk1, sk3);
    }
}
