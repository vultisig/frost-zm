pub use frost_ffi::bytes;
pub use frost_ffi::codec;
pub use frost_ffi::errors;
pub use frost_ffi::handle;

pub mod ceremony;
pub mod ethereum;
pub mod ffi;
pub mod keyshare;
mod session;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn froeth_handle_free(h: handle::Handle) -> errors::lib_error {
    errors::with_error_handler(|| {
        handle::Handle::free(h)?;
        Ok(())
    })
}
