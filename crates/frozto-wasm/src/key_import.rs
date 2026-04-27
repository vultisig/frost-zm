#[cfg(test)]
pub(crate) mod tests {
    use crate::P;
    use crate::keygen::tests::run_dkg_native;
    use wasm_bindgen_test::*;

    pub struct KeyImportResult {
        pub results: Vec<(Vec<u8>, Vec<u8>)>,
        pub vk: Vec<u8>,
        pub extras: Vec<u8>,
    }

    pub(crate) fn run_key_import_as_dkg(n: u16, t: u16) -> KeyImportResult {
        let results = run_dkg_native(n, t);
        let pkp = frost_core::keys::PublicKeyPackage::<P>::deserialize(&results[0].1).unwrap();
        let vk: Vec<u8> = pkp.verifying_key().serialize().unwrap();
        let extras = froztolib::orchard::generate_extras_raw().unwrap();
        KeyImportResult { results, vk, extras }
    }

    #[test]
    fn test_key_import_via_dkg() {
        let import = run_key_import_as_dkg(3, 2);
        assert_eq!(import.results.len(), 3);

        let pkp0 = frost_core::keys::PublicKeyPackage::<P>::deserialize(&import.results[0].1).unwrap();
        let pkp1 = frost_core::keys::PublicKeyPackage::<P>::deserialize(&import.results[1].1).unwrap();
        assert_eq!(pkp0.verifying_key(), pkp1.verifying_key());
    }

    #[wasm_bindgen_test]
    fn test_key_import_via_dkg_wasm() {
        test_key_import_via_dkg();
    }
}
