//! Shared FFI infrastructure for threshold signing libraries.
//!
//! Provides opaque handle management, C-compatible buffer types (`go_slice`,
//! `tss_buffer`), binary map codec, and a unified error enum used by both
//! the Zcash and Monero crates.

pub mod bytes;
pub mod codec;
pub mod errors;
pub mod handle;
