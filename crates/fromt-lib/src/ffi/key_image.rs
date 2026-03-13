use crate::{
    bytes::*,
    ceremony::key_image,
    errors::*,
    handle::Handle,
};

use super::ckd::{decode_signer_ids, decode_ckd_packages};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_key_image_part1(
    key_share: Option<&go_slice>,
    outputs: Option<&go_slice>,
    signer_ids: Option<&go_slice>,
    out_state: Option<&mut Handle>,
    out_partials: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_data = outputs.ok_or(lib_error::LIB_NULL_PTR)?;
        let ids_data = signer_ids.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_state = out_state.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_partials = out_partials.ok_or(lib_error::LIB_NULL_PTR)?;

        let ids = decode_signer_ids(ids_data.as_slice())?;

        let (state, partials_bytes) =
            key_image::key_image_part1(ks_data.as_slice(), out_data.as_slice(), &ids)?;

        *out_state = Handle::allocate(state)?;
        *out_partials = tss_buffer::from_vec(partials_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_key_image_part2(
    state: Handle,
    r1_packages: Option<&go_slice>,
    out_key_images: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = r1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_key_images.ok_or(lib_error::LIB_NULL_PTR)?;

        let state_obj = state.take::<key_image::KeyImageState>()?;
        let packages = decode_ckd_packages(r1_data.as_slice())?;

        let ki_bytes = key_image::key_image_part2(state_obj, &packages)?;

        *out = tss_buffer::from_vec(ki_bytes);
        Ok(())
    })
}
