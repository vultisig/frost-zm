use frost_core::{Ciphersuite, Field, Group};
use frost_secp256k1::Secp256K1Sha256;

use crate::{
    ceremony::dkg::{
        decode_r1_map_with_cc, decode_r2_map, ser_err,
        DkgRound1Secret, DkgRound2Secret, CC_LEN,
    },
    errors::lib_error,
    keyshare::bundle::KeyShareBundle,
};

type S = Secp256K1Sha256;
type Identifier = frost_core::Identifier<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;

pub fn reshare_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_share: Option<&[u8]>,
    old_ids_data: Option<&[u8]>,
) -> Result<(DkgRound1Secret, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    let (additive_share, chain_code_bytes) = match old_key_share {
        Some(bundle_data) if !bundle_data.is_empty() => {
            let bundle = KeyShareBundle::deserialize(bundle_data)?;
            let old_ids_bytes = old_ids_data.ok_or(lib_error::LIB_NULL_PTR)?;
            let old_ids =
                frost_ceremony::reshare::decode_old_identifiers::<S>(old_ids_bytes)?;
            let additive_share = frost_ceremony::reshare::compute_additive_share::<S>(
                &bundle.key_package,
                &old_ids,
                max_signers,
            )?;
            (additive_share, bundle.chain_code)
        }
        _ => (F::one(), [0u8; 32]),
    };

    let (secret, mut pkg_bytes) =
        frost_ceremony::reshare::reshare_part1::<S>(id, max_signers, min_signers, additive_share)?;

    pkg_bytes.extend_from_slice(&chain_code_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        chain_code_share: chain_code_bytes,
    };

    Ok((out_secret, pkg_bytes))
}

pub fn reshare_part3(
    secret: DkgRound2Secret,
    r1_data: &[u8],
    r2_data: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, cc_shares) = decode_r1_map_with_cc(r1_data)?;
    let r2_pkgs = decode_r2_map(r2_data)?;

    let (key_package, pub_key_package) =
        frost_core::keys::dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    let chain_code = aggregate_reshare_chain_code(&secret.chain_code_share, &cc_shares)?;

    let bundle = KeyShareBundle::new(key_package, pub_key_package, chain_code, network, birthday);
    let bundle_bytes = bundle.serialize()?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_reshare_chain_code(
    own_share: &[u8; CC_LEN],
    other_shares: &std::collections::BTreeMap<Identifier, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], lib_error> {
    let zero = [0u8; CC_LEN];
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    if *own_share != zero {
        return Ok(*own_share);
    }
    Err(lib_error::LIB_RESHARE_ERROR)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ceremony::dkg;
    use crate::ceremony::dkg::tests::{decode_test_map, encode_test_map, run_dkg};

    pub fn run_reshare(
        old_bundles: &[Vec<u8>],
        new_n: u16,
        new_t: u16,
        old_ids: &[u16],
    ) -> Vec<Vec<u8>> {
        let old_bundle = KeyShareBundle::deserialize(&old_bundles[0]).unwrap();
        let expected_vk = old_bundle
            .pub_key_package
            .verifying_key()
            .serialize()
            .unwrap();

        let old_ids_bytes: Vec<u8> =
            old_ids.iter().flat_map(|id| id.to_le_bytes()).collect();

        let mut secrets = Vec::new();
        let mut packages = Vec::new();

        for i in 1..=new_n {
            let (secret, pkg) = if old_ids.contains(&i) {
                reshare_part1(
                    i,
                    new_n,
                    new_t,
                    Some(&old_bundles[(i - 1) as usize]),
                    Some(&old_ids_bytes),
                )
                .unwrap()
            } else {
                reshare_part1(i, new_n, new_t, None, None).unwrap()
            };
            secrets.push(secret);
            packages.push((i, pkg));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..new_n as usize {
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

        for i in 0..new_n as usize {
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

            let (bundle_bytes, _) = reshare_part3(
                secrets2.remove(0),
                &r1_map,
                &r2_map,
                expected_vk.as_ref(),
                0,
                old_bundle.birthday,
            )
            .unwrap();

            results.push(bundle_bytes);
        }

        results
    }

    #[test]
    fn test_reshare_2of2_to_2of3() {
        let results_2of2 = run_dkg(2, 2);
        let b0 = KeyShareBundle::deserialize(&results_2of2[0]).unwrap();
        let vk = b0.pub_key_package.verifying_key().clone();

        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);
        let b1 = KeyShareBundle::deserialize(&results_2of3[0]).unwrap();
        assert_eq!(*b1.pub_key_package.verifying_key(), vk);
    }

    #[test]
    fn test_reshare_chain() {
        let results_2of2 = run_dkg(2, 2);
        let b0 = KeyShareBundle::deserialize(&results_2of2[0]).unwrap();
        let vk = b0.pub_key_package.verifying_key().clone();

        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);
        let b1 = KeyShareBundle::deserialize(&results_2of3[0]).unwrap();
        assert_eq!(*b1.pub_key_package.verifying_key(), vk);

        let results_3of4 = run_reshare(&results_2of3, 4, 3, &[1, 2, 3]);
        let b2 = KeyShareBundle::deserialize(&results_3of4[0]).unwrap();
        assert_eq!(*b2.pub_key_package.verifying_key(), vk);
    }

    #[test]
    fn test_reshare_preserves_chain_code() {
        let results_2of2 = run_dkg(2, 2);
        let b0 = KeyShareBundle::deserialize(&results_2of2[0]).unwrap();
        let original_cc = b0.chain_code;

        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);
        for bundle_bytes in &results_2of3 {
            let b = KeyShareBundle::deserialize(bundle_bytes).unwrap();
            assert_eq!(b.chain_code, original_cc);
        }
    }

    #[test]
    fn test_reshare_then_sign() {
        let results_2of2 = run_dkg(2, 2);
        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);

        use crate::ceremony::sign::tests::run_sign;
        let message = b"test message for frobt signing";

        let sig = run_sign(&results_2of3, &[0, 1]);
        crate::ceremony::sign::verify_signature(message.as_ref(), &sig, &results_2of3[0]).unwrap();

        let sig12 = run_sign(&results_2of3, &[1, 2]);
        crate::ceremony::sign::verify_signature(message.as_ref(), &sig12, &results_2of3[1]).unwrap();
    }
}
