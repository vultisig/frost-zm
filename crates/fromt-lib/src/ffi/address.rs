use crate::{
    bytes::*,
    errors::*,
    keyshare::bundle::KeyShareBundle,
    monero::{address, subaddress},
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_derive_address(
    key_share: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let pub_key_bytes = bundle.verifying_key_bytes()?;

        let pub_key_arr: &[u8; 32] = pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let addr =
            address::derive_address(pub_key_arr, &bundle.view_key, bundle.network)?;

        *out = tss_buffer::from_vec(addr.into_bytes());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_derive_subaddress(
    key_share: Option<&go_slice>,
    account: u32,
    index: u32,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let pub_key_bytes = bundle.verifying_key_bytes()?;

        let pub_key_arr: &[u8; 32] = pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let addr = subaddress::derive_subaddress(
            pub_key_arr,
            &bundle.view_key,
            account,
            index,
            bundle.network,
        )?;

        *out = tss_buffer::from_vec(addr.into_bytes());
        Ok(())
    })
}
