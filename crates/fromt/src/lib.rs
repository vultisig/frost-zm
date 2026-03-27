use frost_ed25519::Ed25519Sha512;

pub use frosty::bytes;
pub use frosty::codec;
pub use frosty::errors;
pub use frosty::handle;

pub use crate::keyshare::bundle::ViewKeyMeta;

pub type E = Ed25519Sha512;
pub type Bundle = keyshare::bundle::KeyShareBundle;

pub mod ceremony;
pub mod ffi;
pub mod keyshare;
pub mod monero;
mod session;

frosty::define_frosty_ffi_dkg!(fromt, E, ViewKeyMeta);
frosty::define_frosty_ffi_sign!(fromt, E, ViewKeyMeta);
frosty::define_frosty_ffi_reshare!(fromt, E, ViewKeyMeta);
frosty::define_frosty_ffi_handle_free!(fromt);

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut frosty::tss_buffer>) {
    frosty::bytes::tss_buffer_free(buf);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
        frosty::ceremony::dkg::tests::run_dkg::<E, ViewKeyMeta>(n, t, |extra| {
            ViewKeyMeta::from_dkg(extra, 0, 0)
        })
    }
}
