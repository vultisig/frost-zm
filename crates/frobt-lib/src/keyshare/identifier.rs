use std::collections::HashMap;
use std::sync::OnceLock;

use frost_secp256k1::Secp256K1Sha256;

use crate::errors::lib_error;

type S = Secp256K1Sha256;
type Identifier = frost_core::Identifier<S>;

static ID_LOOKUP: OnceLock<HashMap<Vec<u8>, u16>> = OnceLock::new();

fn get_id_lookup() -> &'static HashMap<Vec<u8>, u16> {
    ID_LOOKUP.get_or_init(|| {
        let mut map = HashMap::with_capacity(256);
        for i in 1..=256u16 {
            let id_result = Identifier::try_from(i);
            if let Ok(id) = id_result {
                map.insert(id.serialize(), i);
            }
        }
        map
    })
}

pub fn identifier_to_u16(id: &Identifier) -> Result<u16, lib_error> {
    get_id_lookup()
        .get(&id.serialize())
        .copied()
        .ok_or(lib_error::LIB_INVALID_IDENTIFIER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_round_trip() {
        for i in 1..=256u16 {
            let id = Identifier::try_from(i).unwrap();
            let decoded = identifier_to_u16(&id).unwrap();
            assert_eq!(i, decoded);
        }
    }
}
