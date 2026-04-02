use frosty::bytes::*;
use frosty::errors::*;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_derive_address(
    key_share: Option<&go_slice>,
    change: u32,
    index: u32,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::bitcoin::address::derive_address_from_bundle(
            ks.as_slice(),
            change,
            index,
        )?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_derive_root_address(
    key_share: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::bitcoin::address::derive_root_address(ks.as_slice())?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_derive_address_from_pubkey(
    pubkey: Option<&go_slice>,
    network: u8,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pk = pubkey.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::bitcoin::address::derive_p2tr_address(pk.as_slice(), network)?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}
