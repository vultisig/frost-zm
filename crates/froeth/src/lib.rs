use frost_secp256k1::Secp256K1Sha256;
use frosty::bundle::ChainCodeMeta;

pub use frosty::bytes;
pub use frosty::codec;
pub use frosty::errors;
pub use frosty::handle;

pub type S = Secp256K1Sha256;
pub type Bundle = frosty::bundle::KeyShareBundle<S, ChainCodeMeta>;

pub mod ethereum;
pub mod ffi;
pub mod ceremony;
pub mod keyshare;

frosty::define_frosty_ffi_dkg!(froeth, S, ChainCodeMeta);
frosty::define_frosty_ffi_sign!(froeth, S, ChainCodeMeta);
frosty::define_frosty_ffi_reshare!(froeth, S, ChainCodeMeta);
frosty::define_frosty_ffi_ckd!(froeth, S, ChainCodeMeta);
frosty::define_frosty_ffi_key_import!(froeth, S, ChainCodeMeta, 44, 60);
frosty::define_frosty_ffi_handle_free!(froeth);
frosty::define_frosty_ffi_keyshare!(froeth, S, ChainCodeMeta);

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
