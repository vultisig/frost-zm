use frost_ed25519::Ed25519Sha512;
use frosty::bundle::ChainCodeMeta;

pub use frosty::bytes;
pub use frosty::codec;
pub use frosty::errors;
pub use frosty::handle;

pub type S = Ed25519Sha512;
pub type Bundle = frosty::bundle::KeyShareBundle<S, ChainCodeMeta>;

pub mod solana;
pub mod ffi;
pub mod ceremony;
pub mod keyshare;

frosty::define_frosty_ffi_dkg!(frosst, S, ChainCodeMeta);
frosty::define_frosty_ffi_sign!(frosst, S, ChainCodeMeta);
frosty::define_frosty_ffi_reshare!(frosst, S, ChainCodeMeta);
frosty::define_frosty_ffi_key_import!(frosst, S, ChainCodeMeta, 44, 501);
frosty::define_frosty_ffi_handle_free!(frosst);

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut frosty::tss_buffer>) {
    frosty::bytes::tss_buffer_free(buf);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
        frosty::ceremony::dkg::tests::run_dkg::<S, ChainCodeMeta>(n, t, |extra| {
            ChainCodeMeta::from_dkg(extra, 0, 0)
        })
    }
}
