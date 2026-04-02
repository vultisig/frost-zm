use frost_core::Ciphersuite;

use crate::errors::lib_error;

pub fn identifier_to_u16<C: Ciphersuite>(id: &frost_core::Identifier<C>) -> Result<u16, lib_error> {
    let serialized = id.serialize();
    let key: &[u8] = serialized.as_ref();

    for i in 1..=256u16 {
        let candidate = frost_core::Identifier::<C>::try_from(i);
        if let Ok(c) = candidate {
            let c_bytes = c.serialize();
            let c_slice: &[u8] = c_bytes.as_ref();
            if c_slice == key {
                return Ok(i);
            }
        }
    }

    Err(lib_error::LIB_INVALID_IDENTIFIER)
}
