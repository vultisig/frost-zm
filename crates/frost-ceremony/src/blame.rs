use frost_core::{Ciphersuite, Identifier};
use frost_ffi::errors::{lib_error, set_blamed_party};

pub fn identifier_to_u16<C: Ciphersuite>(ident: &Identifier<C>) -> Option<u16> {
    let target = ident.serialize();
    for i in 1..=256u16 {
        let candidate = match Identifier::<C>::try_from(i) {
            Ok(c) => c,
            Err(_) => return None,
        };
        if candidate.serialize() == target {
            return Some(i);
        }
    }
    None
}

pub fn frost_err_to_blame<C: Ciphersuite>(
    err: frost_core::Error<C>,
    default: lib_error,
) -> lib_error {
    let Some(ident) = err.culprit() else {
        return default;
    };
    let Some(id) = identifier_to_u16::<C>(&ident) else {
        return default;
    };
    set_blamed_party(id);
    lib_error::LIB_BLAME
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ffi::errors::take_blamed_party;
    use frost_ed25519::Ed25519Sha512;

    type E = Ed25519Sha512;

    #[test]
    fn identifier_to_u16_roundtrip() {
        for i in 1..=20u16 {
            let ident = Identifier::<E>::try_from(i).unwrap();
            let result = identifier_to_u16::<E>(&ident);
            assert_eq!(result, Some(i));
        }
    }

    #[test]
    fn blame_with_culprit_sets_party() {
        let culprit = Identifier::<E>::try_from(3u16).unwrap();
        let err = frost_core::Error::<E>::InvalidSignatureShare { culprit };

        let result = frost_err_to_blame::<E>(err, lib_error::LIB_SIGNING_ERROR);
        assert_eq!(result, lib_error::LIB_BLAME);

        let blamed = take_blamed_party();
        assert_eq!(blamed, 3);
    }

    #[test]
    fn blame_without_culprit_returns_default() {
        let err = frost_core::Error::<E>::InvalidSignature;
        let result = frost_err_to_blame::<E>(err, lib_error::LIB_SIGNING_ERROR);
        assert_eq!(result, lib_error::LIB_SIGNING_ERROR);

        let blamed = take_blamed_party();
        assert_eq!(blamed, 0);
    }

    #[test]
    fn blame_proof_of_knowledge() {
        let culprit = Identifier::<E>::try_from(7u16).unwrap();
        let err = frost_core::Error::<E>::InvalidProofOfKnowledge { culprit };

        let result = frost_err_to_blame::<E>(err, lib_error::LIB_DKG_ERROR);
        assert_eq!(result, lib_error::LIB_BLAME);

        let blamed = take_blamed_party();
        assert_eq!(blamed, 7);
    }

    #[test]
    fn take_blamed_clears_state() {
        set_blamed_party(5);
        assert_eq!(take_blamed_party(), 5);
        assert_eq!(take_blamed_party(), 0);
    }
}
