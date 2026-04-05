use blake2b_simd::Params as Blake2bParams;

use crate::{
    bytes::*,
    errors::*,
    sapling,
};

const METADATA_VERSION: u8 = 1;
const HASH_LEN: usize = 32;

pub fn metadata_create(birthday: u64) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let extras = sapling::generate_extras_raw()?;

    let mut buf = Vec::with_capacity(1 + 8 + 96);
    buf.push(METADATA_VERSION);
    buf.extend_from_slice(&birthday.to_le_bytes());
    buf.extend_from_slice(&extras);

    Ok((extras, buf))
}

pub fn metadata_create_with_extras(extras: &[u8], birthday: u64) -> Result<Vec<u8>, lib_error> {
    if extras.len() != 96 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let mut buf = Vec::with_capacity(1 + 8 + 96);
    buf.push(METADATA_VERSION);
    buf.extend_from_slice(&birthday.to_le_bytes());
    buf.extend_from_slice(extras);

    Ok(buf)
}

pub fn metadata_parse(data: &[u8]) -> Result<(Vec<u8>, u64), lib_error> {
    if data.len() != 1 + 8 + 96 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    if data[0] != METADATA_VERSION {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }

    let birthday = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let extras = data[9..105].to_vec();

    Ok((extras, birthday))
}

pub fn metadata_hash(data: &[u8]) -> Result<[u8; HASH_LEN], lib_error> {
    if data.len() != 1 + 8 + 96 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let hash = Blake2bParams::new()
        .hash_length(HASH_LEN)
        .personal(b"frozts_metahash_")
        .hash(data);

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hash.as_bytes());
    Ok(out)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_keygen_metadata_create(
    birthday: u64,
    out_extras: Option<&mut tss_buffer>,
    out_metadata: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_e = out_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_m = out_metadata.ok_or(lib_error::LIB_NULL_PTR)?;

        let (extras, metadata) = metadata_create(birthday)?;

        *out_e = tss_buffer::from_vec(extras);
        *out_m = tss_buffer::from_vec(metadata);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_keygen_metadata_create_with_extras(
    extras: Option<&go_slice>,
    birthday: u64,
    out_metadata: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let extras_data = extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_m = out_metadata.ok_or(lib_error::LIB_NULL_PTR)?;

        let metadata = metadata_create_with_extras(extras_data.as_slice(), birthday)?;

        *out_m = tss_buffer::from_vec(metadata);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_keygen_metadata_parse(
    metadata: Option<&go_slice>,
    out_extras: Option<&mut tss_buffer>,
    out_birthday: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let meta_data = metadata.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_e = out_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_b = out_birthday.ok_or(lib_error::LIB_NULL_PTR)?;

        let (extras, birthday) = metadata_parse(meta_data.as_slice())?;

        *out_e = tss_buffer::from_vec(extras);
        *out_b = birthday;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozts_keygen_metadata_hash(
    metadata: Option<&go_slice>,
    out_hash: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let meta_data = metadata.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_h = out_hash.ok_or(lib_error::LIB_NULL_PTR)?;

        let hash = metadata_hash(meta_data.as_slice())?;

        *out_h = tss_buffer::from_vec(hash.to_vec());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_roundtrip() {
        let birthday = 3256538u64;
        let (extras, metadata) = metadata_create(birthday).unwrap();

        assert_eq!(extras.len(), 96);
        assert_eq!(metadata.len(), 1 + 8 + 96);

        let (parsed_extras, parsed_birthday) = metadata_parse(&metadata).unwrap();
        assert_eq!(parsed_extras, extras);
        assert_eq!(parsed_birthday, birthday);
    }

    #[test]
    fn test_metadata_create_with_extras() {
        let birthday = 3256538u64;
        let (extras, _) = metadata_create(birthday).unwrap();

        let metadata = metadata_create_with_extras(&extras, birthday).unwrap();
        let (parsed_extras, parsed_birthday) = metadata_parse(&metadata).unwrap();
        assert_eq!(parsed_extras, extras);
        assert_eq!(parsed_birthday, birthday);
    }

    #[test]
    fn test_metadata_hash_consistency() {
        let birthday = 3256538u64;
        let (_, metadata) = metadata_create(birthday).unwrap();

        let hash1 = metadata_hash(&metadata).unwrap();
        let hash2 = metadata_hash(&metadata).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_metadata_hash_differs_for_different_data() {
        let (_, meta1) = metadata_create(100).unwrap();
        let (_, meta2) = metadata_create(200).unwrap();

        let hash1 = metadata_hash(&meta1).unwrap();
        let hash2 = metadata_hash(&meta2).unwrap();
        assert_ne!(hash1, hash2);
    }
}
