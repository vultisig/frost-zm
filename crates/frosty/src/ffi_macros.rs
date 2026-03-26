#[macro_export]
macro_rules! define_frosty_ffi_dkg {
    ($prefix:ident, $ciphersuite:ty, $meta_type:ty) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _dkg_part1>](
                identifier: u16,
                max_signers: u16,
                min_signers: u16,
                out_secret: Option<&mut frosty::Handle>,
                out_package: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let out_secret = out_secret.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_package = out_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let (secret, pkg_bytes) =
                        frosty::ceremony::dkg::dkg_part1::<$ciphersuite>(identifier, max_signers, min_signers)?;

                    *out_secret = frosty::Handle::allocate(secret)?;
                    *out_package = frosty::tss_buffer::from_vec(pkg_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _dkg_part2>](
                secret: frosty::Handle,
                round1_packages: Option<&frosty::go_slice>,
                out_secret: Option<&mut frosty::Handle>,
                out_packages: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let r1_data = round1_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_secret = out_secret.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_packages = out_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let secret_pkg = secret.take::<frosty::ceremony::dkg::DkgRound1Secret<$ciphersuite>>()?;

                    let (secret2, r2_bytes) =
                        frosty::ceremony::dkg::dkg_part2::<$ciphersuite>(secret_pkg, r1_data.as_slice())?;

                    *out_secret = frosty::Handle::allocate(secret2)?;
                    *out_packages = frosty::tss_buffer::from_vec(r2_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _dkg_part3>](
                secret: frosty::Handle,
                round1_packages: Option<&frosty::go_slice>,
                round2_packages: Option<&frosty::go_slice>,
                network: u8,
                birthday: u64,
                out_key_share: Option<&mut frosty::tss_buffer>,
                out_pub_key: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let r1_data = round1_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let r2_data = round2_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_ks = out_key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_pk = out_pub_key.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let secret_pkg = secret.take::<frosty::ceremony::dkg::DkgRound2Secret<$ciphersuite>>()?;

                    let (bundle_bytes, pub_key_bytes) =
                        frosty::ceremony::dkg::dkg_part3::<$ciphersuite, $meta_type>(
                            secret_pkg,
                            r1_data.as_slice(),
                            r2_data.as_slice(),
                            |extra| <$meta_type>::from_dkg(extra, network, birthday),
                        )?;

                    *out_ks = frosty::tss_buffer::from_vec(bundle_bytes);
                    *out_pk = frosty::tss_buffer::from_vec(pub_key_bytes);

                    Ok(())
                })
            }
        }
    };
}

#[macro_export]
macro_rules! define_frosty_ffi_sign {
    ($prefix:ident, $ciphersuite:ty, $meta_type:ty) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _sign_commit>](
                key_share: Option<&frosty::go_slice>,
                out_nonces: Option<&mut frosty::Handle>,
                out_commitments: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_n = out_nonces.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_c = out_commitments.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let (nonces, commitments_bytes) =
                        frosty::ceremony::sign::sign_commit::<$ciphersuite, $meta_type>(ks.as_slice())?;

                    *out_n = frosty::Handle::allocate(nonces)?;
                    *out_c = frosty::tss_buffer::from_vec(commitments_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _sign_create_package>](
                message: Option<&frosty::go_slice>,
                commitments_map: Option<&frosty::go_slice>,
                out_package: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let msg = message.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let cm = commitments_map.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out = out_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let pkg_bytes =
                        frosty::ceremony::sign::sign_create_package::<$ciphersuite>(msg.as_slice(), cm.as_slice())?;
                    *out = frosty::tss_buffer::from_vec(pkg_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _sign>](
                signing_package: Option<&frosty::go_slice>,
                nonces: frosty::Handle,
                key_share: Option<&frosty::go_slice>,
                out_share: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let sp = signing_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out = out_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let nonces_obj = nonces.take::<frosty::ceremony::sign::SignNonces<$ciphersuite>>()?;
                    let share_bytes =
                        frosty::ceremony::sign::sign::<$ciphersuite, $meta_type>(sp.as_slice(), nonces_obj, ks.as_slice())?;

                    *out = frosty::tss_buffer::from_vec(share_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _sign_aggregate>](
                signing_package: Option<&frosty::go_slice>,
                shares_map: Option<&frosty::go_slice>,
                key_share: Option<&frosty::go_slice>,
                out_signature: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let sp = signing_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let sm = shares_map.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out = out_signature.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let sig_bytes =
                        frosty::ceremony::sign::sign_aggregate::<$ciphersuite, $meta_type>(
                            sp.as_slice(), sm.as_slice(), ks.as_slice()
                        )?;
                    *out = frosty::tss_buffer::from_vec(sig_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _verify_signature>](
                message: Option<&frosty::go_slice>,
                signature: Option<&frosty::go_slice>,
                key_share: Option<&frosty::go_slice>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let msg = message.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let sig = signature.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    frosty::ceremony::sign::verify_signature::<$ciphersuite, $meta_type>(
                        msg.as_slice(), sig.as_slice(), ks.as_slice()
                    )
                })
            }
        }
    };
}

#[macro_export]
macro_rules! define_frosty_ffi_reshare {
    ($prefix:ident, $ciphersuite:ty, $meta_type:ty) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _reshare_part1>](
                identifier: u16,
                max_signers: u16,
                min_signers: u16,
                old_key_share: Option<&frosty::go_slice>,
                old_identifiers: Option<&frosty::go_slice>,
                out_secret: Option<&mut frosty::Handle>,
                out_package: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let out_secret = out_secret.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_package = out_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let old_ks = old_key_share.map(|s| s.as_slice());
                    let old_ids = old_identifiers.map(|s| s.as_slice());

                    let (secret, pkg_bytes) =
                        frosty::ceremony::reshare::reshare_part1::<$ciphersuite, $meta_type>(
                            identifier, max_signers, min_signers, old_ks, old_ids
                        )?;

                    *out_secret = frosty::Handle::allocate(secret)?;
                    *out_package = frosty::tss_buffer::from_vec(pkg_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _reshare_part3>](
                secret: frosty::Handle,
                round1_packages: Option<&frosty::go_slice>,
                round2_packages: Option<&frosty::go_slice>,
                expected_vk: Option<&frosty::go_slice>,
                network: u8,
                birthday: u64,
                out_key_share: Option<&mut frosty::tss_buffer>,
                out_pub_key: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let r1_data = round1_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let r2_data = round2_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let vk_data = expected_vk.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_ks = out_key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_pk = out_pub_key.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let secret_pkg = secret.take::<frosty::ceremony::dkg::DkgRound2Secret<$ciphersuite>>()?;

                    let (bundle_bytes, pub_key_bytes) =
                        frosty::ceremony::reshare::reshare_part3::<$ciphersuite, $meta_type>(
                            secret_pkg,
                            r1_data.as_slice(),
                            r2_data.as_slice(),
                            vk_data.as_slice(),
                            |extra| <$meta_type>::from_dkg(extra, network, birthday),
                        )?;

                    *out_ks = frosty::tss_buffer::from_vec(bundle_bytes);
                    *out_pk = frosty::tss_buffer::from_vec(pub_key_bytes);

                    Ok(())
                })
            }
        }
    };
}

#[macro_export]
macro_rules! define_frosty_ffi_ckd {
    ($prefix:ident, $ciphersuite:ty, $meta_type:ty) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _ckd_derive>](
                key_share: Option<&frosty::go_slice>,
                change: u32,
                index: u32,
                out_child_share: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out = out_child_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let child_bytes =
                        frosty::ceremony::ckd::ckd_derive::<$ciphersuite, $meta_type>(ks.as_slice(), change, index)?;
                    *out = frosty::tss_buffer::from_vec(child_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _derive_child_pubkey>](
                key_share: Option<&frosty::go_slice>,
                change: u32,
                index: u32,
                out_child_pubkey: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let ks = key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out = out_child_pubkey.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let pub_bytes =
                        frosty::ceremony::ckd::derive_child_pubkey::<$ciphersuite, $meta_type>(ks.as_slice(), change, index)?;
                    *out = frosty::tss_buffer::from_vec(pub_bytes);

                    Ok(())
                })
            }
        }
    };
}

#[macro_export]
macro_rules! define_frosty_ffi_key_import {
    ($prefix:ident, $ciphersuite:ty, $meta_type:ty, $bip32_purpose:expr, $bip32_coin_type:expr) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _derive_from_seed>](
                seed: Option<&frosty::go_slice>,
                account_index: u32,
                out_private_key: Option<&mut frosty::tss_buffer>,
                out_chain_code: Option<&mut frosty::tss_buffer>,
                out_public_key: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let seed_data = seed.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_sk = out_private_key.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_cc = out_chain_code.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_pk = out_public_key.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let (sk, cc, pk) = frosty::ceremony::key_import::derive_from_seed::<$ciphersuite>(
                        seed_data.as_slice(), account_index, $bip32_purpose, $bip32_coin_type
                    )?;

                    *out_sk = frosty::tss_buffer::from_vec(sk.to_vec());
                    *out_cc = frosty::tss_buffer::from_vec(cc.to_vec());
                    *out_pk = frosty::tss_buffer::from_vec(pk);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _key_import_part1>](
                identifier: u16,
                max_signers: u16,
                min_signers: u16,
                private_key: Option<&frosty::go_slice>,
                chain_code: Option<&frosty::go_slice>,
                out_secret: Option<&mut frosty::Handle>,
                out_package: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let out_secret = out_secret.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_package = out_package.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let sk_opt: Option<&[u8; 32]> = private_key.and_then(|s| {
                        let sl = s.as_slice();
                        if sl.len() == 32 { sl.try_into().ok() } else { None }
                    });

                    let cc_opt: Option<&[u8; 32]> = chain_code.and_then(|s| {
                        let sl = s.as_slice();
                        if sl.len() == 32 { sl.try_into().ok() } else { None }
                    });

                    let (secret, pkg_bytes) =
                        frosty::ceremony::key_import::key_import_part1::<$ciphersuite>(
                            identifier, max_signers, min_signers, sk_opt, cc_opt
                        )?;

                    *out_secret = frosty::Handle::allocate(secret)?;
                    *out_package = frosty::tss_buffer::from_vec(pkg_bytes);

                    Ok(())
                })
            }

            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _key_import_part3>](
                secret: frosty::Handle,
                round1_packages: Option<&frosty::go_slice>,
                round2_packages: Option<&frosty::go_slice>,
                expected_vk: Option<&frosty::go_slice>,
                network: u8,
                birthday: u64,
                out_key_share: Option<&mut frosty::tss_buffer>,
                out_pub_key: Option<&mut frosty::tss_buffer>,
            ) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    let r1_data = round1_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let r2_data = round2_packages.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let vk_data = expected_vk.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_ks = out_key_share.ok_or(frosty::lib_error::LIB_NULL_PTR)?;
                    let out_pk = out_pub_key.ok_or(frosty::lib_error::LIB_NULL_PTR)?;

                    let secret_pkg = secret.take::<frosty::ceremony::dkg::DkgRound2Secret<$ciphersuite>>()?;

                    let (bundle_bytes, pub_key_bytes) =
                        frosty::ceremony::key_import::key_import_part3::<$ciphersuite, $meta_type>(
                            secret_pkg,
                            r1_data.as_slice(),
                            r2_data.as_slice(),
                            vk_data.as_slice(),
                            |extra| <$meta_type>::from_dkg(extra, network, birthday),
                        )?;

                    *out_ks = frosty::tss_buffer::from_vec(bundle_bytes);
                    *out_pk = frosty::tss_buffer::from_vec(pub_key_bytes);

                    Ok(())
                })
            }
        }
    };
}

#[macro_export]
macro_rules! define_frosty_ffi_handle_free {
    ($prefix:ident) => {
        paste::paste! {
            #[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
            pub extern "C" fn [<$prefix _handle_free>](h: frosty::Handle) -> frosty::lib_error {
                frosty::with_error_handler(|| {
                    frosty::Handle::free(h)?;
                    Ok(())
                })
            }
        }
    };
}
