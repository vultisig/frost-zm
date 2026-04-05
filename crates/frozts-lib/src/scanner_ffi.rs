#[cfg(feature = "scanner")]
use crate::{
    bytes::*,
    errors::*,
    scanner,
};

#[cfg(feature = "scanner")]
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_scan(
    dfvk: Option<&go_slice>,
    url: Option<&go_slice>,
    birthday: u64,
    out_result: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let dfvk_data = dfvk.ok_or(lib_error::LIB_NULL_PTR)?;
        let url_data = url.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_result.ok_or(lib_error::LIB_NULL_PTR)?;

        let url_str = std::str::from_utf8(url_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let result = scanner::scan(dfvk_data.as_slice(), url_str, birthday as u32)?;

        let json = serde_json::to_vec(&result)
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        *out = tss_buffer::from_vec(json);
        Ok(())
    })
}

#[cfg(feature = "scanner")]
#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_scan_balance(
    dfvk: Option<&go_slice>,
    url: Option<&go_slice>,
    birthday: u64,
    out_balance: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let dfvk_data = dfvk.ok_or(lib_error::LIB_NULL_PTR)?;
        let url_data = url.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_balance.ok_or(lib_error::LIB_NULL_PTR)?;

        let url_str = std::str::from_utf8(url_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let result = scanner::scan(dfvk_data.as_slice(), url_str, birthday as u32)?;

        *out = result.spendable_balance;
        Ok(())
    })
}
