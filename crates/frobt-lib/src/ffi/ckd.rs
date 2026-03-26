use crate::{
    bytes::*,
    ceremony::ckd,
    errors::*,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_ckd_derive(
    key_share: Option<&go_slice>,
    change: u32,
    index: u32,
    out_child_key_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_child_key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let child_bytes = ckd::ckd_derive(ks.as_slice(), change, index)?;
        *out = tss_buffer::from_vec(child_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_derive_child_pubkey(
    key_share: Option<&go_slice>,
    change: u32,
    index: u32,
    out_pubkey: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_pubkey.ok_or(lib_error::LIB_NULL_PTR)?;

        let pub_bytes = ckd::derive_child_pubkey(ks.as_slice(), change, index)?;
        *out = tss_buffer::from_vec(pub_bytes);

        Ok(())
    })
}
