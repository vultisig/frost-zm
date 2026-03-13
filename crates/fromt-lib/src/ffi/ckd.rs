use crate::{
    bytes::*,
    ceremony::ckd,
    errors::*,
    handle::Handle,
};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_ckd_part1(
    key_share: Option<&go_slice>,
    account: u32,
    index: u32,
    signer_ids: Option<&go_slice>,
    out_state: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let ids_data = signer_ids.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_state = out_state.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let ids = decode_signer_ids(ids_data.as_slice())?;

        let (state, pkg_bytes) =
            ckd::ckd_part1(ks_data.as_slice(), account, index, &ids)?;

        *out_state = Handle::allocate(state)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_ckd_part2(
    state: Handle,
    r1_packages: Option<&go_slice>,
    out_child_key_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = r1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_child_key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let state_obj = state.take::<ckd::CkdState>()?;
        let packages = decode_ckd_packages(r1_data.as_slice())?;

        let child_bytes = ckd::ckd_part2(state_obj, &packages)?;

        *out = tss_buffer::from_vec(child_bytes);
        Ok(())
    })
}

pub(crate) fn decode_signer_ids(data: &[u8]) -> Result<Vec<u16>, lib_error> {
    if data.len() % 2 != 0 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = data.len() / 2;
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let id = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        ids.push(id);
    }
    Ok(ids)
}

pub(crate) fn decode_ckd_packages(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, lib_error> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if pos + 4 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + vlen > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let v = data[pos..pos + vlen].to_vec();
        pos += vlen;
        entries.push((id, v));
    }
    Ok(entries)
}
