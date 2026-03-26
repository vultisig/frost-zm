use frosty::bytes::*;
use frosty::errors::*;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_derive_address(
    key_share: Option<&go_slice>,
    change: u32,
    index: u32,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::ethereum::address::derive_address_from_bundle(
            ks.as_slice(),
            change,
            index,
        )?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_derive_root_address(
    key_share: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::ethereum::address::derive_root_address(ks.as_slice())?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_eth_address(
    verifying_key: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let vk = verifying_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let addr = crate::ethereum::address::eth_address_hex(vk.as_slice())?;
        *out = tss_buffer::from_vec(addr.into_bytes());

        Ok(())
    })
}
