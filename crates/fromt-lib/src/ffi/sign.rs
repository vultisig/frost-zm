use crate::{
    bytes::*,
    ceremony::sign,
    errors::*,
    handle::Handle,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_sign_commit(
    key_share: Option<&go_slice>,
    out_nonces: Option<&mut Handle>,
    out_commitments: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_nonces = out_nonces.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_commitments = out_commitments.ok_or(lib_error::LIB_NULL_PTR)?;

        let (nonces, commitments_bytes) = sign::sign_commit(ks_data.as_slice())?;

        *out_nonces = Handle::allocate(nonces)?;
        *out_commitments = tss_buffer::from_vec(commitments_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_sign_create_package(
    message: Option<&go_slice>,
    commitments_map: Option<&go_slice>,
    out_signing_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let cm_data = commitments_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sp = out_signing_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let sp_bytes =
            sign::sign_create_package(msg.as_slice(), cm_data.as_slice())?;

        *out_sp = tss_buffer::from_vec(sp_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_sign(
    signing_package: Option<&go_slice>,
    nonces: Handle,
    key_share: Option<&go_slice>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp_data = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_share = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let nonces_obj = nonces.take::<sign::SignNonces>()?;
        let share_bytes =
            sign::sign(sp_data.as_slice(), nonces_obj, ks_data.as_slice())?;

        *out_share = tss_buffer::from_vec(share_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_sign_aggregate(
    signing_package: Option<&go_slice>,
    shares_map: Option<&go_slice>,
    key_share: Option<&go_slice>,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp_data = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let sm_data = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sig = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;

        let sig_bytes = sign::sign_aggregate(
            sp_data.as_slice(),
            sm_data.as_slice(),
            ks_data.as_slice(),
        )?;

        *out_sig = tss_buffer::from_vec(sig_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_verify_signature(
    message: Option<&go_slice>,
    signature: Option<&go_slice>,
    key_share: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig_data = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        sign::verify_signature(
            msg.as_slice(),
            sig_data.as_slice(),
            ks_data.as_slice(),
        )
    })
}
