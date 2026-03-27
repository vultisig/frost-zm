use frosty::bytes::*;
use frosty::errors::*;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frosst_derive_address(
    key_share: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::solana::address::derive_address(ks.as_slice())?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frosst_pubkey_to_address(
    pubkey: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pk = pubkey.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::solana::address::pubkey_to_address(pk.as_slice())?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}
