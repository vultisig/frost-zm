use crate::{
    bytes::*,
    errors::*,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_compute_sighash(
    raw_tx: Option<&go_slice>,
    prevouts: Option<&go_slice>,
    input_index: u32,
    sighash_type: u8,
    out_sighash: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let tx = raw_tx.ok_or(lib_error::LIB_NULL_PTR)?;
        let prev = prevouts.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_sighash.ok_or(lib_error::LIB_NULL_PTR)?;

        let hash = crate::bitcoin::sighash::compute_taproot_sighash(
            tx.as_slice(),
            prev.as_slice(),
            input_index,
            sighash_type,
        )?;
        *out = tss_buffer::from_vec(hash.to_vec());

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_attach_witness(
    raw_tx: Option<&go_slice>,
    input_index: u32,
    signature: Option<&go_slice>,
    out_signed_tx: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let tx = raw_tx.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signed_tx.ok_or(lib_error::LIB_NULL_PTR)?;

        let signed = crate::bitcoin::witness::attach_taproot_witness(
            tx.as_slice(),
            input_index,
            sig.as_slice(),
        )?;
        *out = tss_buffer::from_vec(signed);

        Ok(())
    })
}
