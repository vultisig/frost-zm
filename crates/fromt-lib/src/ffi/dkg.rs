use crate::{
    bytes::*,
    ceremony::{dkg, key_import},
    errors::*,
    handle::Handle,
    keyshare::{bundle::KeyShareBundle, identifier::identifier_to_u16},
};

use frost_ed25519::Ed25519Sha512;
type E = Ed25519Sha512;
type Identifier = frost_core::Identifier<E>;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_dkg_part1(
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
pub extern "C" fn fromt_dkg_part2(
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
pub extern "C" fn fromt_dkg_part3(
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

        let (bundle_bytes, pub_key_bytes) =
            dkg::dkg_part3(secret_pkg, r1_data.as_slice(), r2_data.as_slice(), network, birthday)?;

        *out_ks = tss_buffer::from_vec(bundle_bytes);
        *out_pk = tss_buffer::from_vec(pub_key_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    spend_key: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let sk_opt = match spend_key {
            Some(sk) if !sk.is_empty() => {
                let arr: &[u8; 32] = sk
                    .as_slice()
                    .try_into()
                    .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
                Some(arr)
            }
            _ => None,
        };

        let (secret, pkg_bytes) =
            key_import::key_import_part1(identifier, max_signers, min_signers, sk_opt)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_key_import_part3(
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

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_derive_keys_from_seed(
    seed: Option<&go_slice>,
    out_spend_key: Option<&mut tss_buffer>,
    out_view_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let seed_data = seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sk = out_spend_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_vk = out_view_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let seed_arr: &[u8; 32] = seed_data
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;

        let (sk, vk) = key_import::derive_keys_from_seed(seed_arr)?;

        *out_sk = tss_buffer::from_vec(sk.to_vec());
        *out_vk = tss_buffer::from_vec(vk.to_vec());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_spend_key_to_public(
    spend_key: Option<&go_slice>,
    out_pub_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sk_data = spend_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_pub_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let sk_arr: &[u8; 32] = sk_data
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;

        let pub_bytes = key_import::spend_key_to_public(sk_arr)?;
        *out = tss_buffer::from_vec(pub_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_keyshare_public_key(
    key_share: Option<&go_slice>,
    out_pub_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_pub_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let vk_bytes = bundle.verifying_key_bytes()?;

        *out = tss_buffer::from_vec(vk_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_keyshare_view_key(
    key_share: Option<&go_slice>,
    out_view_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_view_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        *out = tss_buffer::from_vec(bundle.view_key.to_vec());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_keyshare_identifier(
    key_share: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        *out = identifier_to_u16(bundle.key_package.identifier())?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_keyshare_birthday(
    key_share: Option<&go_slice>,
    out_birthday: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_birthday.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        *out = bundle.birthday;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_encode_identifier(
    id: u16,
    out_bytes: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::try_from(id)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        *out = tss_buffer::from_vec(ident.serialize());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_decode_identifier(
    id_bytes: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let data = id_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::deserialize(data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        *out = identifier_to_u16(&ident)?;
        Ok(())
    })
}
