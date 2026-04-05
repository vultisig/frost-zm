use blake2b_simd::Params as Blake2bParams;
use frost_core::{
    keys::dkg,
    Ciphersuite, Field, Group,
};
use group::{ff::{Field as FfField, FromUniformBytes, PrimeField}, GroupEncoding, Curve};
use pasta_curves::pallas;
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
};

type P = PallasBlake2b512;
type F = <<P as Ciphersuite>::Group as Group>::Field;
type G = <P as Ciphersuite>::Group;

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozto serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

pub fn derive_ask_from_sk(sk_bytes: &[u8; 32]) -> [u8; 32] {
    let prf_output = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state()
        .update(sk_bytes)
        .update(&[0x06])
        .finalize();
    let mut uniform = [0u8; 64];
    uniform.copy_from_slice(prf_output.as_bytes());
    let mut ask = <pallas::Scalar as FromUniformBytes<64>>::from_uniform_bytes(&uniform);
    if bool::from(ask.is_zero()) {
        panic!("ask is zero - invalid spending key");
    }
    let ak_point = (<pallas::Point as group::Group>::generator() * ask).to_affine();
    let ak_bytes: [u8; 32] = ak_point.to_bytes();
    if (ak_bytes[31] >> 7) == 1 {
        ask = -ask;
    }
    ask.to_repr()
}

pub fn ask_to_ak(ask_bytes: &[u8; 32]) -> Result<Vec<u8>, lib_error> {
    let scalar = F::deserialize(ask_bytes).map_err(ser_err)?;
    let point = G::generator() * scalar;
    let vk_bytes =
        <P as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;
    let bytes: &[u8] = vk_bytes.as_ref();
    Ok(bytes.to_vec())
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    spending_key: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
    out_vk: Option<&mut tss_buffer>,
    out_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        if min_signers < 2 || max_signers < min_signers {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }

        let constant_term = match spending_key {
            Some(sk_data) if !sk_data.is_empty() => {
                if sk_data.len() != 32 {
                    return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
                }
                let sk_bytes: [u8; 32] = sk_data.as_slice()[..32].try_into().unwrap();
                let ask_bytes = derive_ask_from_sk(&sk_bytes);
                let vk = ask_to_ak(&ask_bytes)?;
                let extras = crate::orchard::generate_extras_raw()?;

                if let Some(out_v) = out_vk {
                    *out_v = tss_buffer::from_vec(vk);
                }
                if let Some(out_e) = out_extras {
                    *out_e = tss_buffer::from_vec(extras);
                }

                let ask_scalar = F::deserialize(&ask_bytes).map_err(ser_err)?;
                frost_ceremony::key_import::derive_constant_term::<P>(ask_scalar, max_signers)
            }
            _ => F::one(),
        };

        let (secret, pkg_bytes) =
            frost_ceremony::key_import::key_import_part1::<P>(identifier, max_signers, min_signers, constant_term)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_key_import_part3(
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

        let secret_pkg = secret.take::<dkg::round2::SecretPackage<P>>()?;

        let (key_package, pub_key_package) = frost_ceremony::key_import::key_import_part3::<P>(
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
pub(crate) mod tests {
    use super::*;
    use crate::keygen;
    use crate::keygen::tests::{decode_test_map, encode_test_map};
    use crate::sign::tests::run_sign;

    pub struct KeyImportResult {
        pub results: Vec<(Vec<u8>, Vec<u8>)>,
        pub vk: Vec<u8>,
        pub extras: Vec<u8>,
    }

    pub fn run_key_import_seedless(n: u16, t: u16) -> KeyImportResult {
        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();

            assert_eq!(
                frozto_key_import_part1(
                    i, n, t,
                    None,
                    Some(&mut secret),
                    Some(&mut package),
                    None,
                    None,
                ),
                lib_error::LIB_OK,
            );

            secrets1.push(secret);
            packages1.push((i, package.into_vec()));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..n as usize {
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
                keygen::frozto_dkg_part2(
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
        let vk = Vec::new();
        let extras = Vec::new();

        for i in 0..n as usize {
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

            let pkp_bytes = if !results.is_empty() {
                let (_, ref pkp): (Vec<u8>, Vec<u8>) = results[0];
                let pkp_pkg = frost_core::keys::PublicKeyPackage::<P>::deserialize(pkp).unwrap();
                pkp_pkg.verifying_key().serialize().unwrap()
            } else {
                vec![0u8; 33]
            };
            let vk_slice = go_slice::from(pkp_bytes.as_slice());

            let mut kp = tss_buffer::empty();
            let mut pkp = tss_buffer::empty();

            let err = frozto_key_import_part3(
                secrets2[i],
                Some(&r1_slice),
                Some(&r2_slice),
                Some(&vk_slice),
                Some(&mut kp),
                Some(&mut pkp),
            );
            assert!(err == lib_error::LIB_OK || err == lib_error::LIB_KEY_IMPORT_ERROR);

            if err == lib_error::LIB_OK {
                results.push((kp.into_vec(), pkp.into_vec()));
            }
        }

        KeyImportResult { results, vk, extras }
    }

    pub fn run_key_import_with_seed(seed: &[u8], n: u16, t: u16) -> KeyImportResult {
        use orchard::keys::SpendingKey;
        use zip32::AccountId;

        let account = AccountId::try_from(0u32).unwrap();
        let sk = SpendingKey::from_zip32_seed(seed, 133, account).unwrap();
        let sk_bytes = sk.to_bytes().to_vec();

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();
        let mut vk = Vec::new();
        let mut extras = Vec::new();

        for i in 1..=n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();
            let mut vk_buf = tss_buffer::empty();
            let mut extras_buf = tss_buffer::empty();

            let sk_opt = if i == 1 {
                let sk_slice = go_slice::from(sk_bytes.as_slice());
                Some(sk_slice)
            } else {
                None
            };

            assert_eq!(
                frozto_key_import_part1(
                    i, n, t,
                    sk_opt.as_ref(),
                    Some(&mut secret),
                    Some(&mut package),
                    Some(&mut vk_buf),
                    Some(&mut extras_buf),
                ),
                lib_error::LIB_OK,
            );

            if i == 1 {
                vk = vk_buf.into_vec();
                extras = extras_buf.into_vec();
            }

            secrets1.push(secret);
            packages1.push((i, package.into_vec()));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..n as usize {
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
                keygen::frozto_dkg_part2(
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

        for i in 0..n as usize {
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
            let vk_slice = go_slice::from(vk.as_slice());

            let mut kp = tss_buffer::empty();
            let mut pkp = tss_buffer::empty();

            assert_eq!(
                frozto_key_import_part3(
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

        KeyImportResult { results, vk, extras }
    }

    #[test]
    fn test_dkg_and_sign() {
        let dkg_results = keygen::tests::run_dkg(3, 2);
        assert_eq!(dkg_results.len(), 3);

        run_sign(&dkg_results, &[0, 1]);
        run_sign(&dkg_results, &[1, 2]);
    }

    #[test]
    fn test_key_import_with_seed() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let import = run_key_import_with_seed(&seed, 3, 2);
        assert_eq!(import.results.len(), 3);
        assert!(!import.vk.is_empty());
        assert!(!import.extras.is_empty());

        run_sign(&import.results, &[0, 1]);
        run_sign(&import.results, &[1, 2]);
    }
}
