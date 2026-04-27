use frost_core::keys::dkg;
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
};

type P = PallasBlake2b512;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_dkg_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let (secret, pkg_bytes) =
            frost_ceremony::dkg::dkg_part1::<P>(identifier, max_signers, min_signers)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_dkg_part2(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_packages: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_packages = out_packages.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::round1::SecretPackage<P>>()?;

        let (secret2, r2_bytes) =
            frost_ceremony::dkg::dkg_part2::<P>(secret_pkg, r1_data.as_slice())?;

        *out_secret = Handle::allocate(secret2)?;
        *out_packages = tss_buffer::from_vec(r2_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_dkg_part3(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    round2_packages: Option<&go_slice>,
    out_key_package: Option<&mut tss_buffer>,
    out_pub_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let r2_data = round2_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_kp = out_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pkp = out_pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::round2::SecretPackage<P>>()?;

        let (key_package, pub_key_package) =
            frost_ceremony::dkg::dkg_part3::<P>(secret_pkg, r1_data.as_slice(), r2_data.as_slice())?;

        let kp_bytes = key_package.serialize().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let pkp_bytes = pub_key_package.serialize().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        *out_kp = tss_buffer::from_vec(kp_bytes);
        *out_pkp = tss_buffer::from_vec(pkp_bytes);

        Ok(())
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keyshare::identifier_to_u16;

    type Identifier = frost_core::Identifier<P>;

    pub fn run_dkg(n: u16, t: u16) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();

            assert_eq!(
                frozto_dkg_part1(i, n, t, Some(&mut secret), Some(&mut package)),
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
                frozto_dkg_part2(
                    secrets1[i],
                    Some(&r1_slice),
                    Some(&mut secret),
                    Some(&mut packages),
                ),
                lib_error::LIB_OK,
            );

            secrets2.push(secret);

            let r2_bytes = packages.into_vec();
            let r2_decoded = decode_test_map(&r2_bytes);
            all_r2_packages.push(r2_decoded);
        }

        let mut results = Vec::new();

        for i in 0..n as usize {
            let r1_others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let mut r2_for_me = Vec::new();
            let my_id = (i + 1) as u16;
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

            let mut kp = tss_buffer::empty();
            let mut pkp = tss_buffer::empty();

            assert_eq!(
                frozto_dkg_part3(
                    secrets2[i],
                    Some(&r1_slice),
                    Some(&r2_slice),
                    Some(&mut kp),
                    Some(&mut pkp),
                ),
                lib_error::LIB_OK,
            );

            results.push((kp.into_vec(), pkp.into_vec()));
        }

        results
    }

    pub(crate) fn encode_test_map(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
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

    pub(crate) fn decode_test_map(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut pos = 0;
        let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut entries = Vec::new();
        for _ in 0..count {
            let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let id = Identifier::deserialize(&data[pos..pos + klen]).unwrap();
            pos += klen;
            let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let v = data[pos..pos + vlen].to_vec();
            pos += vlen;

            let id_u16 = identifier_to_u16(&id).unwrap();
            entries.push((id_u16, v));
        }
        entries
    }

    #[test]
    fn test_dkg_2x3() {
        let results = run_dkg(3, 2);
        assert_eq!(results.len(), 3);

        let pkp0 = frost_core::keys::PublicKeyPackage::<P>::deserialize(&results[0].1).unwrap();
        let pkp1 = frost_core::keys::PublicKeyPackage::<P>::deserialize(&results[1].1).unwrap();
        let pkp2 = frost_core::keys::PublicKeyPackage::<P>::deserialize(&results[2].1).unwrap();

        assert_eq!(pkp0.verifying_key(), pkp1.verifying_key());
        assert_eq!(pkp1.verifying_key(), pkp2.verifying_key());
    }
}
