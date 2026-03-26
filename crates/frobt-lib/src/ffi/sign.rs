use crate::{
    bytes::*,
    ceremony::sign,
    errors::*,
    handle::Handle,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_commit(
    key_share: Option<&go_slice>,
    out_nonces: Option<&mut Handle>,
    out_commitments: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_n = out_nonces.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_c = out_commitments.ok_or(lib_error::LIB_NULL_PTR)?;

        let (nonces, commitments_bytes) = sign::sign_commit(ks.as_slice())?;

        *out_n = Handle::allocate(nonces)?;
        *out_c = tss_buffer::from_vec(commitments_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_create_package(
    message: Option<&go_slice>,
    commitments_map: Option<&go_slice>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let cm = commitments_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkg_bytes = sign::sign_create_package(msg.as_slice(), cm.as_slice())?;
        *out = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign(
    signing_package: Option<&go_slice>,
    nonces: Handle,
    key_share: Option<&go_slice>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let nonces_obj = nonces.take::<sign::SignNonces>()?;
        let share_bytes = sign::sign(sp.as_slice(), nonces_obj, ks.as_slice())?;

        *out = tss_buffer::from_vec(share_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_aggregate(
    signing_package: Option<&go_slice>,
    shares_map: Option<&go_slice>,
    key_share: Option<&go_slice>,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let sm = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;

        let sig_bytes = sign::sign_aggregate(sp.as_slice(), sm.as_slice(), ks.as_slice())?;
        *out = tss_buffer::from_vec(sig_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_verify_signature(
    message: Option<&go_slice>,
    signature: Option<&go_slice>,
    key_share: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        sign::verify_signature(msg.as_slice(), sig.as_slice(), ks.as_slice())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_taproot(
    signing_package: Option<&go_slice>,
    nonces: Handle,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());
        let nonces_obj = nonces.take::<sign::SignNonces>()?;
        let share_bytes = sign::sign_taproot(sp.as_slice(), nonces_obj, ks.as_slice(), mr)?;

        *out = tss_buffer::from_vec(share_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_aggregate_taproot(
    signing_package: Option<&go_slice>,
    shares_map: Option<&go_slice>,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let sm = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());
        let sig_bytes = sign::sign_aggregate_taproot(sp.as_slice(), sm.as_slice(), ks.as_slice(), mr)?;
        *out = tss_buffer::from_vec(sig_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_verify_taproot_signature(
    message: Option<&go_slice>,
    signature: Option<&go_slice>,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());
        sign::verify_taproot_signature(msg.as_slice(), sig.as_slice(), ks.as_slice(), mr)
    })
}
