pub mod scanner;
mod scanner_ffi;

pub use frost_ffi::bytes;
pub use frost_ffi::errors;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}
