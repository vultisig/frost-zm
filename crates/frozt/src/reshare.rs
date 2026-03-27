use frost_core::{
    keys::{dkg, KeyPackage},
    Ciphersuite, Field, Group,
};
use reddsa::frost::redjubjub::JubjubBlake2b512;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
};

type J = JubjubBlake2b512;
type F = <<J as Ciphersuite>::Group as Group>::Field;

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozt serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_reshare_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_package: Option<&go_slice>,
    old_identifiers: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        if min_signers < 2 || max_signers < min_signers {
            return Err(lib_error::LIB_RESHARE_ERROR);
        }

        let additive_share = match old_key_package {
            Some(kp_data) if !kp_data.is_empty() => {
                let old_ids_data = old_identifiers.ok_or(lib_error::LIB_NULL_PTR)?;
                let old_ids =
                    frost_ceremony::reshare::decode_old_identifiers::<J>(old_ids_data.as_slice())?;
                let kp = KeyPackage::<J>::deserialize(kp_data.as_slice()).map_err(ser_err)?;
                frost_ceremony::reshare::compute_additive_share::<J>(&kp, &old_ids, max_signers)?
            }
            _ => F::one(),
        };

        let (secret, pkg_bytes) =
            frost_ceremony::reshare::reshare_part1::<J>(identifier, max_signers, min_signers, additive_share)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_reshare_part3(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    round2_packages: Option<&go_slice>,
    expected_vk: Option<&go_slice>,
    out_key_package: Option<&mut tss_buffer>,
    out_pub_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let r2_data = round2_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let vk_data = expected_vk.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_kp = out_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pkp = out_pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::round2::SecretPackage<J>>()?;

        let (key_package, pub_key_package) = frost_ceremony::reshare::reshare_part3::<J>(
            secret_pkg,
            r1_data.as_slice(),
            r2_data.as_slice(),
            vk_data.as_slice(),
        )?;

        let kp_bytes = key_package.serialize().map_err(ser_err)?;
        let pkp_bytes = pub_key_package.serialize().map_err(ser_err)?;

        *out_kp = tss_buffer::from_vec(kp_bytes);
        *out_pkp = tss_buffer::from_vec(pkp_bytes);

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use crate::keygen::tests::{decode_test_map, encode_test_map, run_dkg};
    use frost_core::keys::PublicKeyPackage;

    pub fn run_reshare(
        old_results: &[(Vec<u8>, Vec<u8>)],
        new_n: u16,
        new_t: u16,
        old_ids: &[u16],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let pkp = PublicKeyPackage::<J>::deserialize(&old_results[0].1).unwrap();
        let expected_vk = pkp.verifying_key().serialize().unwrap();

        let old_ids_bytes: Vec<u8> = old_ids.iter().flat_map(|id| id.to_le_bytes()).collect();

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=new_n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();

            if old_ids.contains(&i) {
                let kp_data = &old_results[(i - 1) as usize].0;
                let kp_slice = go_slice::from(kp_data.as_slice());
                let ids_slice = go_slice::from(old_ids_bytes.as_slice());

                assert_eq!(
                    frozt_reshare_part1(
                        i,
                        new_n,
                        new_t,
                        Some(&kp_slice),
                        Some(&ids_slice),
                        Some(&mut secret),
                        Some(&mut package),
                    ),
                    lib_error::LIB_OK,
                );
            } else {
                assert_eq!(
                    frozt_reshare_part1(
                        i,
                        new_n,
                        new_t,
                        None,
                        None,
                        Some(&mut secret),
                        Some(&mut package),
                    ),
                    lib_error::LIB_OK,
                );
            }

            secrets1.push(secret);
            packages1.push((i, package.into_vec()));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..new_n as usize {
            let others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let r1_map = encode_test_map(&others);
            let r1_slice = go_slice::from(r1_map.as_slice());

            let mut secret = Handle::null();
            let mut packages = tss_buffer::empty();

            assert_eq!(
                keygen::frozt_dkg_part2(
                    secrets1[i],
                    Some(&r1_slice),
                    Some(&mut secret),
                    Some(&mut packages),
                ),
                lib_error::LIB_OK,
            );

            secrets2.push(secret);
            let r2_bytes = packages.into_vec();
            all_r2_packages.push(decode_test_map(&r2_bytes));
        }

        let mut results = Vec::new();

        for i in 0..new_n as usize {
            let r1_others: Vec<_> = packages1
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
            let r1_slice = go_slice::from(r1_map.as_slice());
            let r2_slice = go_slice::from(r2_map.as_slice());
            let vk_slice = go_slice::from(expected_vk.as_ref());

            let mut kp = tss_buffer::empty();
            let mut pkp = tss_buffer::empty();

            assert_eq!(
                frozt_reshare_part3(
                    secrets2[i],
                    Some(&r1_slice),
                    Some(&r2_slice),
                    Some(&vk_slice),
                    Some(&mut kp),
                    Some(&mut pkp),
                ),
                lib_error::LIB_OK,
            );

            results.push((kp.into_vec(), pkp.into_vec()));
        }

        results
    }

    #[test]
    fn test_reshare_2of2_to_2of3() {
        let results_2of2 = run_dkg(2, 2);

        let pkp0 = PublicKeyPackage::<J>::deserialize(&results_2of2[0].1).unwrap();
        let vk = pkp0.verifying_key();

        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);

        let pkp1 = PublicKeyPackage::<J>::deserialize(&results_2of3[0].1).unwrap();
        assert_eq!(*vk, *pkp1.verifying_key());
    }

    #[test]
    fn test_reshare_chain() {
        let results_2of2 = run_dkg(2, 2);
        let pkp_initial = PublicKeyPackage::<J>::deserialize(&results_2of2[0].1).unwrap();
        let vk = pkp_initial.verifying_key().clone();

        let results_2of3 = run_reshare(&results_2of2, 3, 2, &[1, 2]);
        let pkp_2of3 = PublicKeyPackage::<J>::deserialize(&results_2of3[0].1).unwrap();
        assert_eq!(vk, *pkp_2of3.verifying_key());

        let results_3of4 = run_reshare(&results_2of3, 4, 3, &[1, 2, 3]);
        let pkp_3of4 = PublicKeyPackage::<J>::deserialize(&results_3of4[0].1).unwrap();
        assert_eq!(vk, *pkp_3of4.verifying_key());
    }
}
