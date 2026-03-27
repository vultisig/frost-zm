//! Zcash threshold signing for Sapling (RedJubjub) and Orchard (RedPallas).
//!
//! Provides distributed key generation, threshold signing with rerandomisation,
//! key import, resharing, transaction building, and z-address derivation.
//! Sapling and Orchard operations share the generic `frost-ceremony` infrastructure
//! but are parameterised over different FROST ciphersuites.

pub use frost_ffi::bytes;
pub use frost_ffi::codec;
pub use frost_ffi::errors;
pub use frost_ffi::handle;

pub mod ceremony_metadata;
pub mod key_import;
mod keygen;
pub mod sapling;
mod keyshare;
mod reshare;
mod session;
mod sign;
pub mod tree;
pub mod tx;
pub mod shielding_tx;
mod zeroize_util;

pub mod orchard_keygen;
pub mod orchard_keys;
pub mod orchard_keyshare;
pub mod orchard_reshare;
pub mod orchard_sign;
pub mod orchard_tx;

pub use zeroize_util::{zeroize_scalar, zeroize_scalar_vec};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_handle_free(h: handle::Handle) -> errors::lib_error {
    errors::with_error_handler(|| {
        handle::Handle::free(h)?;
        Ok(())
    })
}
