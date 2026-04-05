use orchard::keys::{FullViewingKey, IncomingViewingKey, Scope};
use orchard::note::ExtractedNoteCommitment;
use orchard::note::{Nullifier, RandomSeed, Rho};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use orchard::value::NoteValue;
use orchard::Note;
use wasm_bindgen::prelude::*;
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
    COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};

use crate::to_js_err;

const EXTRAS_LEN: usize = 64;

#[wasm_bindgen]
pub fn frozto_orchard_build_fvk(
    pub_key_package: &[u8],
    orchard_extras: &[u8],
) -> Result<Vec<u8>, JsError> {
    let fvk_raw = froztolib::orchard::build_fvk_raw(pub_key_package, orchard_extras)
        .map_err(to_js_err)?;
    Ok(fvk_raw.to_vec())
}

#[wasm_bindgen]
pub fn frozto_orchard_generate_extras() -> Result<Vec<u8>, JsError> {
    froztolib::orchard::generate_extras_raw().map_err(to_js_err)
}

#[wasm_bindgen]
pub struct WasmOrchardKeys {
    address: Vec<u8>,
    ivk: Vec<u8>,
}

#[wasm_bindgen]
impl WasmOrchardKeys {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Vec<u8> {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ivk(&self) -> Vec<u8> {
        self.ivk.clone()
    }
}

#[wasm_bindgen]
pub fn frozto_orchard_derive_keys(
    pub_key_package: &[u8],
    orchard_extras: &[u8],
) -> Result<WasmOrchardKeys, JsError> {
    if orchard_extras.len() != EXTRAS_LEN {
        return Err(JsError::new("orchard extras must be 64 bytes"));
    }

    let fvk_raw = froztolib::orchard::build_fvk_raw(pub_key_package, orchard_extras)
        .map_err(to_js_err)?;
    let fvk = FullViewingKey::from_bytes(&fvk_raw)
        .ok_or_else(|| JsError::new("invalid full viewing key"))?;

    let ivk = fvk.to_ivk(Scope::External);
    let addr = ivk.address_at(0u32);

    let addr_bytes = addr.to_raw_address_bytes();
    let ivk_bytes = ivk.to_bytes();

    Ok(WasmOrchardKeys {
        address: addr_bytes.to_vec(),
        ivk: ivk_bytes.to_vec(),
    })
}

#[wasm_bindgen]
pub fn frozto_orchard_try_decrypt_compact(
    ivk: &[u8],
    nullifier: &[u8],
    cmx: &[u8],
    ephemeral_key: &[u8],
    ciphertext: &[u8],
) -> Result<JsValue, JsError> {
    if ivk.len() != 64 || cmx.len() != 32 || ephemeral_key.len() != 32 || nullifier.len() != 32 {
        return Err(JsError::new("ivk must be 64 bytes, cmx/ephemeral_key/nullifier must be 32 bytes"));
    }
    if ciphertext.len() != COMPACT_NOTE_SIZE {
        return Err(JsError::new("ciphertext must be COMPACT_NOTE_SIZE bytes"));
    }

    let ivk_arr: [u8; 64] = ivk[..64].try_into().unwrap();
    let ivk_obj = IncomingViewingKey::from_bytes(&ivk_arr);
    if ivk_obj.is_none().into() {
        return Err(JsError::new("invalid ivk"));
    }
    let ivk_obj = ivk_obj.unwrap();
    let prepared = ivk_obj.prepare();

    let nf_bytes: [u8; 32] = nullifier[..32].try_into().unwrap();
    let nf = Nullifier::from_bytes(&nf_bytes);
    if nf.is_none().into() {
        return Err(JsError::new("invalid nullifier"));
    }
    let nf = nf.unwrap();

    let cmx_bytes: [u8; 32] = cmx[..32].try_into().unwrap();
    let extracted_cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
    if extracted_cmx.is_none().into() {
        return Err(JsError::new("invalid cmx"));
    }
    let extracted_cmx = extracted_cmx.unwrap();

    let epk_bytes: [u8; 32] = ephemeral_key[..32].try_into().unwrap();

    let mut enc_ct = [0u8; COMPACT_NOTE_SIZE];
    enc_ct.copy_from_slice(&ciphertext[..COMPACT_NOTE_SIZE]);

    let compact = CompactAction::from_parts(
        nf,
        extracted_cmx,
        EphemeralKeyBytes(epk_bytes),
        enc_ct,
    );

    let domain = OrchardDomain::for_compact_action(&compact);
    let result = try_compact_note_decryption(&domain, &prepared, &compact);

    match result {
        Some((note, _addr)) => Ok(JsValue::from(note.value().inner())),
        None => Ok(JsValue::NULL),
    }
}

struct FullOutput {
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

#[wasm_bindgen]
pub fn frozto_orchard_decrypt_note_full(
    ivk: &[u8],
    nullifier: &[u8],
    cmx: &[u8],
    ephemeral_key: &[u8],
    enc_ciphertext: &[u8],
) -> Result<Vec<u8>, JsError> {
    if ivk.len() != 64 || cmx.len() != 32 || ephemeral_key.len() != 32 || nullifier.len() != 32 {
        return Err(JsError::new("ivk must be 64 bytes, cmx/ephemeral_key/nullifier must be 32 bytes"));
    }
    if enc_ciphertext.len() != ENC_CIPHERTEXT_SIZE {
        return Err(JsError::new("enc_ciphertext must be ENC_CIPHERTEXT_SIZE bytes"));
    }

    let ivk_arr: [u8; 64] = ivk[..64].try_into().unwrap();
    let ivk_obj = IncomingViewingKey::from_bytes(&ivk_arr);
    if ivk_obj.is_none().into() {
        return Err(JsError::new("invalid ivk"));
    }
    let ivk_obj = ivk_obj.unwrap();
    let prepared = ivk_obj.prepare();

    let nf_bytes: [u8; 32] = nullifier[..32].try_into().unwrap();
    let nf = Nullifier::from_bytes(&nf_bytes);
    if nf.is_none().into() {
        return Err(JsError::new("invalid nullifier"));
    }
    let nf = nf.unwrap();

    let cmx_bytes: [u8; 32] = cmx[..32].try_into().unwrap();
    let extracted_cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
    if extracted_cmx.is_none().into() {
        return Err(JsError::new("invalid cmx"));
    }
    let extracted_cmx = extracted_cmx.unwrap();

    let epk_bytes: [u8; 32] = ephemeral_key[..32].try_into().unwrap();

    let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
    enc_ct.copy_from_slice(&enc_ciphertext[..ENC_CIPHERTEXT_SIZE]);

    let output = FullOutput {
        cmx: extracted_cmx,
        ephemeral_key: EphemeralKeyBytes(epk_bytes),
        enc_ciphertext: enc_ct,
    };

    let dummy_compact = CompactAction::from_parts(
        nf,
        extracted_cmx,
        EphemeralKeyBytes(epk_bytes),
        [0u8; COMPACT_NOTE_SIZE],
    );
    let domain = OrchardDomain::for_compact_action(&dummy_compact);
    let result = try_note_decryption(&domain, &prepared, &output);

    match result {
        Some((note, addr, _memo)) => {
            let rseed_bytes = note.rseed().as_bytes();
            let rho_bytes = note.rho().to_bytes();
            let mut note_data = Vec::with_capacity(107);
            note_data.extend_from_slice(addr.diversifier().as_array());
            note_data.extend_from_slice(&note.value().inner().to_le_bytes());
            note_data.extend_from_slice(rseed_bytes);
            note_data.extend_from_slice(&rho_bytes);
            Ok(note_data)
        }
        None => Err(JsError::new("decryption failed")),
    }
}

#[wasm_bindgen]
pub fn frozto_orchard_compute_nullifier(
    pub_key_package: &[u8],
    orchard_extras: &[u8],
    note_data: &[u8],
) -> Result<Vec<u8>, JsError> {
    if orchard_extras.len() != EXTRAS_LEN {
        return Err(JsError::new("orchard extras must be 64 bytes"));
    }
    if note_data.len() != 107 {
        return Err(JsError::new("note_data must be 107 bytes"));
    }

    let fvk_raw = froztolib::orchard::build_fvk_raw(pub_key_package, orchard_extras)
        .map_err(to_js_err)?;
    let fvk = FullViewingKey::from_bytes(&fvk_raw)
        .ok_or_else(|| JsError::new("invalid full viewing key"))?;

    let diversifier_bytes: [u8; 11] = note_data[..11].try_into()
        .map_err(|_| JsError::new("invalid diversifier bytes"))?;
    let diversifier = orchard::keys::Diversifier::from_bytes(diversifier_bytes);

    let value = u64::from_le_bytes(
        note_data[11..19].try_into().map_err(|_| JsError::new("invalid value bytes"))?,
    );

    let rseed_bytes: [u8; 32] = note_data[19..51].try_into()
        .map_err(|_| JsError::new("invalid rseed bytes"))?;
    let rho_bytes: [u8; 32] = note_data[51..83].try_into()
        .map_err(|_| JsError::new("invalid rho bytes"))?;

    let rho = Rho::from_bytes(&rho_bytes);
    if rho.is_none().into() {
        return Err(JsError::new("invalid rho"));
    }
    let rho = rho.unwrap();

    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho);
    if rseed.is_none().into() {
        return Err(JsError::new("invalid rseed"));
    }
    let rseed = rseed.unwrap();

    let addr = fvk.address(diversifier, Scope::External);
    let note = Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed);
    if note.is_none().into() {
        return Err(JsError::new("invalid note"));
    }
    let note = note.unwrap();

    let nf = note.nullifier(&fvk);
    Ok(nf.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_generate_extras() {
        let extras = frozto_orchard_generate_extras().unwrap();
        assert_eq!(extras.len(), 64);
    }

    #[test]
    fn test_derive_keys() {
        let results = crate::keygen::tests::run_dkg_native(3, 2);
        let pkp = &results[0].1;
        let extras = frozto_orchard_generate_extras().unwrap();
        let keys = frozto_orchard_derive_keys(pkp, &extras).unwrap();
        assert_eq!(keys.address().len(), 43);
        assert_eq!(keys.ivk().len(), 64);
    }

    #[wasm_bindgen_test]
    fn test_generate_extras_wasm() {
        test_generate_extras();
    }

    #[wasm_bindgen_test]
    fn test_derive_keys_wasm() {
        test_derive_keys();
    }
}
