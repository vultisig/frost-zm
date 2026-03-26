use frost_secp256k1::Secp256K1Sha256;
use frosty::bundle::ChainCodeMeta;

pub use frosty::bytes;
pub use frosty::codec;
pub use frosty::errors;
pub use frosty::handle;

pub type S = Secp256K1Sha256;
pub type Bundle = frosty::bundle::KeyShareBundle<S, ChainCodeMeta>;

pub mod bitcoin;
pub mod taproot;
pub mod ffi;
pub mod ceremony;
pub mod keyshare;
pub mod session;

frosty::define_frosty_ffi_dkg!(frobt, S, ChainCodeMeta);
frosty::define_frosty_ffi_sign!(frobt, S, ChainCodeMeta);
frosty::define_frosty_ffi_reshare!(frobt, S, ChainCodeMeta);
frosty::define_frosty_ffi_ckd!(frobt, S, ChainCodeMeta);
frosty::define_frosty_ffi_key_import!(frobt, S, ChainCodeMeta, 86, 0);
frosty::define_frosty_ffi_handle_free!(frobt);
frosty::define_frosty_ffi_keyshare!(frobt, S, ChainCodeMeta);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
        frosty::ceremony::dkg::tests::run_dkg::<S, ChainCodeMeta>(n, t, |extra| {
            ChainCodeMeta::from_dkg(extra, 0, 0)
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut frosty::tss_buffer>) {
    frosty::bytes::tss_buffer_free(buf);
}
