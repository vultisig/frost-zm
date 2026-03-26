use crate::{
    bytes::*,
    ceremony::{dkg, key_import},
    errors::*,
    handle::Handle,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_dkg_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let (secret, pkg_bytes) = dkg::dkg_part1(identifier, max_signers, min_signers)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_dkg_part2(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_packages: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_packages = out_packages.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::DkgRound1Secret>()?;

        let (secret2, r2_bytes) = dkg::dkg_part2(secret_pkg, r1_data.as_slice())?;

        *out_secret = Handle::allocate(secret2)?;
        *out_packages = tss_buffer::from_vec(r2_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_dkg_part3(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    round2_packages: Option<&go_slice>,
    network: u8,
    birthday: u64,
    out_key_share: Option<&mut tss_buffer>,
    out_pub_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let r2_data = round2_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_ks = out_key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pk = out_pub_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::DkgRound2Secret>()?;

        let (bundle_bytes, pub_key_bytes) = dkg::dkg_part3(
            secret_pkg,
            r1_data.as_slice(),
            r2_data.as_slice(),
            network,
            birthday,
        )?;

        *out_ks = tss_buffer::from_vec(bundle_bytes);
        *out_pk = tss_buffer::from_vec(pub_key_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_derive_from_seed(
    seed: Option<&go_slice>,
    account_index: u32,
    out_private_key: Option<&mut tss_buffer>,
    out_chain_code: Option<&mut tss_buffer>,
    out_public_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let seed_data = seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sk = out_private_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_cc = out_chain_code.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pk = out_public_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let (sk, cc, pk) = key_import::derive_from_seed(seed_data.as_slice(), account_index)?;

        *out_sk = tss_buffer::from_vec(sk.to_vec());
        *out_cc = tss_buffer::from_vec(cc.to_vec());
        *out_pk = tss_buffer::from_vec(pk);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    private_key: Option<&go_slice>,
    chain_code: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let sk_opt: Option<&[u8; 32]> = private_key.and_then(|s| {
            let sl = s.as_slice();
            if sl.len() == 32 {
                sl.try_into().ok()
            } else {
                None
            }
        });

        let cc_opt: Option<&[u8; 32]> = chain_code.and_then(|s| {
            let sl = s.as_slice();
            if sl.len() == 32 {
                sl.try_into().ok()
            } else {
                None
            }
        });

        let (secret, pkg_bytes) =
            key_import::key_import_part1(identifier, max_signers, min_signers, sk_opt, cc_opt)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_key_import_part3(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    round2_packages: Option<&go_slice>,
    expected_vk: Option<&go_slice>,
    network: u8,
    birthday: u64,
    out_key_share: Option<&mut tss_buffer>,
    out_pub_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let r2_data = round2_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let vk_data = expected_vk.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_ks = out_key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pk = out_pub_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::DkgRound2Secret>()?;

        let (bundle_bytes, pub_key_bytes) = key_import::key_import_part3(
            secret_pkg,
            r1_data.as_slice(),
            r2_data.as_slice(),
            vk_data.as_slice(),
            network,
            birthday,
        )?;

        *out_ks = tss_buffer::from_vec(bundle_bytes);
        *out_pk = tss_buffer::from_vec(pub_key_bytes);

        Ok(())
    })
}
