use ff::{Field, PrimeField};
use group::GroupEncoding;
use sapling_crypto::{
    bundle::OutputDescription,
    constants::PROOF_GENERATION_KEY_GENERATOR,
    keys::{OutgoingViewingKey, SaplingIvk},
    note::ExtractedNoteCommitment,
    note_encryption::{
        try_sapling_compact_note_decryption, try_sapling_note_decryption,
        try_sapling_output_recovery, CompactOutputDescription, PreparedIncomingViewingKey,
        SaplingDomain, Zip212Enforcement,
    },
    value::{NoteValue, ValueCommitment},
    zip32::DiversifiableFullViewingKey,
    Diversifier, Note, Rseed,
};
use wasm_bindgen::prelude::*;
use zcash_address::unified::{self, Encoding};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};
use zcash_protocol::consensus::NetworkType;
use zeroize::Zeroize;
use crate::{to_js_err, J};

const EXTRAS_LEN: usize = 96;

fn build_dfvk_raw(pub_key_package: &[u8], sapling_extras: &[u8]) -> Result<[u8; 128], JsError> {
    if sapling_extras.len() != EXTRAS_LEN {
        return Err(JsError::new("sapling extras must be 96 bytes"));
    }

    let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(pub_key_package)
        .map_err(to_js_err)?;
    let ak_serialized = pkp.verifying_key().serialize().map_err(to_js_err)?;

    let nsk_bytes: [u8; 32] = sapling_extras[..32]
        .try_into()
        .map_err(|_| JsError::new("invalid nsk bytes"))?;
    let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
    let nsk = nsk.ok_or_else(|| JsError::new("invalid nsk scalar"))?;
    let nk: jubjub::SubgroupPoint = PROOF_GENERATION_KEY_GENERATOR * nsk;

    let mut dfvk_raw = [0u8; 128];
    dfvk_raw[..32].copy_from_slice(ak_serialized.as_ref());
    dfvk_raw[32..64].copy_from_slice(&nk.to_bytes());
    dfvk_raw[64..96].copy_from_slice(&sapling_extras[32..64]);
    dfvk_raw[96..128].copy_from_slice(&sapling_extras[64..96]);

    Ok(dfvk_raw)
}

#[wasm_bindgen]
pub fn frozt_sapling_build_dfvk(
    pub_key_package: &[u8],
    sapling_extras: &[u8],
) -> Result<Vec<u8>, JsError> {
    let dfvk_raw = build_dfvk_raw(pub_key_package, sapling_extras)?;
    Ok(dfvk_raw.to_vec())
}

#[wasm_bindgen]
pub fn frozt_sapling_generate_extras() -> Result<Vec<u8>, JsError> {
    let mut rng = rand::thread_rng();
    let mut extras = vec![0u8; EXTRAS_LEN];

    let nsk = jubjub::Fr::random(&mut rng);
    let mut nsk_repr = nsk.to_repr();
    extras[..32].copy_from_slice(&nsk_repr);
    nsk_repr.zeroize();

    rand::RngCore::fill_bytes(&mut rng, &mut extras[32..64]);
    rand::RngCore::fill_bytes(&mut rng, &mut extras[64..96]);

    Ok(extras)
}

#[wasm_bindgen]
pub struct WasmSaplingKeys {
    address: String,
    ivk: Vec<u8>,
    nk: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSaplingKeys {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ivk(&self) -> Vec<u8> {
        self.ivk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nk(&self) -> Vec<u8> {
        self.nk.clone()
    }
}

#[wasm_bindgen]
pub fn frozt_sapling_derive_keys(
    pub_key_package: &[u8],
    sapling_extras: &[u8],
) -> Result<WasmSaplingKeys, JsError> {
    if sapling_extras.len() != EXTRAS_LEN {
        return Err(JsError::new("sapling extras must be 96 bytes"));
    }

    let dfvk_raw = build_dfvk_raw(pub_key_package, sapling_extras)?;
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
        .ok_or_else(|| JsError::new("invalid diversifiable full viewing key"))?;

    let (_, addr) = dfvk.default_address();
    let hrp = bech32::Hrp::parse("zs")
        .map_err(|e| JsError::new(&format!("bech32 hrp: {}", e)))?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
        .map_err(|e| JsError::new(&format!("bech32 encode: {}", e)))?;

    let ivk = dfvk.fvk().vk.ivk();

    let nsk_bytes: [u8; 32] = sapling_extras[..32]
        .try_into()
        .map_err(|_| JsError::new("invalid nsk bytes"))?;
    let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
    let nsk = nsk.ok_or_else(|| JsError::new("invalid nsk scalar"))?;
    let nk: jubjub::SubgroupPoint = PROOF_GENERATION_KEY_GENERATOR * nsk;

    Ok(WasmSaplingKeys {
        address: encoded,
        ivk: ivk.0.to_repr().to_vec(),
        nk: nk.to_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn frozt_sapling_try_decrypt_compact(
    ivk: &[u8],
    cmu: &[u8],
    ephemeral_key: &[u8],
    ciphertext: &[u8],
    height: u64,
) -> Result<JsValue, JsError> {
    if ivk.len() != 32 || cmu.len() != 32 || ephemeral_key.len() != 32 {
        return Err(JsError::new("ivk, cmu, and ephemeral_key must be 32 bytes"));
    }
    if ciphertext.len() != COMPACT_NOTE_SIZE {
        return Err(JsError::new("ciphertext must be 52 bytes"));
    }

    let ivk_bytes: [u8; 32] = ivk[..32].try_into().unwrap();
    let ivk_scalar: Option<jubjub::Fr> = jubjub::Fr::from_repr(ivk_bytes).into();
    let ivk_scalar = ivk_scalar.ok_or_else(|| JsError::new("invalid ivk scalar"))?;
    let prepared = PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));

    let cmu_bytes: [u8; 32] = cmu[..32].try_into().unwrap();
    let extracted_cmu: Option<ExtractedNoteCommitment> =
        ExtractedNoteCommitment::from_bytes(&cmu_bytes).into();
    let extracted_cmu = extracted_cmu.ok_or_else(|| JsError::new("invalid cmu"))?;

    let epk_bytes: [u8; 32] = ephemeral_key[..32].try_into().unwrap();

    let mut enc_ct = [0u8; COMPACT_NOTE_SIZE];
    enc_ct.copy_from_slice(&ciphertext[..COMPACT_NOTE_SIZE]);

    let compact = CompactOutputDescription {
        ephemeral_key: EphemeralKeyBytes(epk_bytes),
        cmu: extracted_cmu,
        enc_ciphertext: enc_ct,
    };

    let result = try_sapling_compact_note_decryption(
        &prepared,
        &compact,
        zip212_for_height(height),
    );

    match result {
        Some((note, _addr)) => Ok(JsValue::from(note.value().inner())),
        None => Ok(JsValue::NULL),
    }
}

struct FullOutput {
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

fn zip212_for_height(height: u64) -> Zip212Enforcement {
    if height >= 1_687_104 {
        Zip212Enforcement::On
    } else if height >= 903_000 {
        Zip212Enforcement::GracePeriod
    } else {
        Zip212Enforcement::Off
    }
}

#[wasm_bindgen]
pub fn frozt_sapling_decrypt_note_full(
    ivk: &[u8],
    cmu: &[u8],
    ephemeral_key: &[u8],
    enc_ciphertext: &[u8],
    height: u64,
) -> Result<Vec<u8>, JsError> {
    if ivk.len() != 32 || cmu.len() != 32 || ephemeral_key.len() != 32 {
        return Err(JsError::new("ivk, cmu, and ephemeral_key must be 32 bytes"));
    }
    if enc_ciphertext.len() != ENC_CIPHERTEXT_SIZE {
        return Err(JsError::new("enc_ciphertext must be 580 bytes"));
    }

    let ivk_bytes: [u8; 32] = ivk[..32].try_into().unwrap();
    let ivk_scalar: Option<jubjub::Fr> = jubjub::Fr::from_repr(ivk_bytes).into();
    let ivk_scalar = ivk_scalar.ok_or_else(|| JsError::new("invalid ivk scalar"))?;
    let prepared = PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));

    let cmu_bytes: [u8; 32] = cmu[..32].try_into().unwrap();
    let extracted_cmu: Option<ExtractedNoteCommitment> =
        ExtractedNoteCommitment::from_bytes(&cmu_bytes).into();
    let extracted_cmu = extracted_cmu.ok_or_else(|| JsError::new("invalid cmu"))?;

    let epk_bytes: [u8; 32] = ephemeral_key[..32].try_into().unwrap();

    let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
    enc_ct.copy_from_slice(&enc_ciphertext[..ENC_CIPHERTEXT_SIZE]);

    let output = FullOutput {
        cmu: extracted_cmu,
        ephemeral_key: EphemeralKeyBytes(epk_bytes),
        enc_ciphertext: enc_ct,
    };

    let zip212 = zip212_for_height(height);

    let result = try_sapling_note_decryption(&prepared, &output, zip212);

    match result {
        Some((note, addr, _memo)) => {
            let rseed_bytes = match note.rseed() {
                sapling_crypto::Rseed::BeforeZip212(rcm) => rcm.to_repr(),
                sapling_crypto::Rseed::AfterZip212(rseed) => *rseed,
            };
            let mut note_data = Vec::with_capacity(51);
            note_data.extend_from_slice(&addr.diversifier().0);
            note_data.extend_from_slice(&note.value().inner().to_le_bytes());
            note_data.extend_from_slice(&rseed_bytes);
            Ok(note_data)
        }
        None => Err(JsError::new("decryption failed")),
    }
}

#[wasm_bindgen]
pub fn frozt_sapling_compute_nullifier(
    dfvk_bytes: &[u8],
    note_data: &[u8],
    position: u64,
    height: u64,
) -> Result<Vec<u8>, JsError> {
    if dfvk_bytes.len() != 128 {
        return Err(JsError::new("dfvk must be 128 bytes"));
    }
    if note_data.len() != 51 {
        return Err(JsError::new("note_data must be 51 bytes"));
    }

    let dfvk_arr: [u8; 128] = dfvk_bytes[..128].try_into()
        .map_err(|_| JsError::new("invalid dfvk bytes"))?;
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_arr)
        .ok_or_else(|| JsError::new("invalid diversifiable full viewing key"))?;

    let diversifier_bytes: [u8; 11] = note_data[..11].try_into()
        .map_err(|_| JsError::new("invalid diversifier bytes"))?;
    let diversifier = Diversifier(diversifier_bytes);

    let value = u64::from_le_bytes(
        note_data[11..19].try_into().map_err(|_| JsError::new("invalid value bytes"))?,
    );

    let rseed_bytes: [u8; 32] = note_data[19..51].try_into()
        .map_err(|_| JsError::new("invalid rseed bytes"))?;
    let zip212 = zip212_for_height(height);
    let rseed = match zip212 {
        Zip212Enforcement::Off => {
            let rcm: Option<jubjub::Fr> = jubjub::Fr::from_repr(rseed_bytes).into();
            Rseed::BeforeZip212(rcm.ok_or_else(|| JsError::new("invalid rcm scalar"))?)
        }
        _ => Rseed::AfterZip212(rseed_bytes),
    };

    let recipient = dfvk.fvk().vk.to_payment_address(diversifier)
        .ok_or_else(|| JsError::new("invalid payment address from diversifier"))?;

    let note = Note::from_parts(recipient, NoteValue::from_raw(value), rseed);

    let nf = note.nf(&dfvk.fvk().vk.nk, position);
    Ok(nf.0.to_vec())
}

#[wasm_bindgen]
pub struct WasmRecoveredOutput {
    address: String,
    value: u64,
    memo: Vec<u8>,
}

#[wasm_bindgen]
impl WasmRecoveredOutput {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[wasm_bindgen(getter)]
    pub fn memo(&self) -> Vec<u8> {
        self.memo.clone()
    }
}

#[wasm_bindgen]
pub fn frozt_sapling_try_output_recovery(
    ovk: &[u8],
    cv: &[u8],
    cmu: &[u8],
    ephemeral_key: &[u8],
    enc_ciphertext: &[u8],
    out_ciphertext: &[u8],
    height: u64,
) -> Result<JsValue, JsError> {
    if ovk.len() != 32 {
        return Err(JsError::new("ovk must be 32 bytes"));
    }
    if cv.len() != 32 || cmu.len() != 32 || ephemeral_key.len() != 32 {
        return Err(JsError::new("cv, cmu, and ephemeral_key must be 32 bytes"));
    }
    if enc_ciphertext.len() != ENC_CIPHERTEXT_SIZE {
        return Err(JsError::new("enc_ciphertext must be 580 bytes"));
    }
    if out_ciphertext.len() != OUT_CIPHERTEXT_SIZE {
        return Err(JsError::new("out_ciphertext must be 80 bytes"));
    }

    let ovk_bytes: [u8; 32] = ovk[..32].try_into().unwrap();
    let ovk = OutgoingViewingKey(ovk_bytes);

    let cv_bytes: [u8; 32] = cv[..32].try_into().unwrap();
    let cv: Option<ValueCommitment> = ValueCommitment::from_bytes_not_small_order(&cv_bytes).into();
    let cv = cv.ok_or_else(|| JsError::new("invalid cv"))?;

    let cmu_bytes: [u8; 32] = cmu[..32].try_into().unwrap();
    let extracted_cmu: Option<ExtractedNoteCommitment> =
        ExtractedNoteCommitment::from_bytes(&cmu_bytes).into();
    let extracted_cmu = extracted_cmu.ok_or_else(|| JsError::new("invalid cmu"))?;

    let epk_bytes: [u8; 32] = ephemeral_key[..32].try_into().unwrap();

    let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
    enc_ct.copy_from_slice(enc_ciphertext);

    let mut out_ct = [0u8; OUT_CIPHERTEXT_SIZE];
    out_ct.copy_from_slice(out_ciphertext);

    let output_desc = OutputDescription::from_parts(
        cv,
        extracted_cmu,
        EphemeralKeyBytes(epk_bytes),
        enc_ct,
        out_ct,
        [0u8; 192], // dummy proof, not needed for decryption
    );

    let zip212 = zip212_for_height(height);
    let result = try_sapling_output_recovery(&ovk, &output_desc, zip212);

    match result {
        Some((note, addr, memo)) => {
            let hrp = bech32::Hrp::parse("zs")
                .map_err(|e| JsError::new(&format!("bech32 hrp: {}", e)))?;
            let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
                .map_err(|e| JsError::new(&format!("bech32 encode: {}", e)))?;

            Ok(JsValue::from(WasmRecoveredOutput {
                address: encoded,
                value: note.value().inner(),
                memo: memo.to_vec(),
            }))
        }
        None => Ok(JsValue::NULL),
    }
}

/// Build a ZIP-316 Unified Address containing P2PKH (transparent) and Sapling receivers.
/// `p2pkh_hash` is the 20-byte RIPEMD160(SHA256(compressed_pubkey)) of the ECDSA key.
/// `sapling_raw_addr` is the 43-byte Sapling payment address (11-byte diversifier + 32-byte pk_d).
/// Returns the bech32m-encoded unified address string (u1...).
#[wasm_bindgen]
pub fn frozt_sapling_build_unified_address(
    p2pkh_hash: &[u8],
    sapling_raw_addr: &[u8],
) -> Result<String, JsError> {
    if p2pkh_hash.len() != 20 {
        return Err(JsError::new("p2pkh_hash must be 20 bytes"));
    }
    if sapling_raw_addr.len() != 43 {
        return Err(JsError::new("sapling_raw_addr must be 43 bytes"));
    }

    let p2pkh: [u8; 20] = p2pkh_hash.try_into().unwrap();
    let sapling: [u8; 43] = sapling_raw_addr.try_into().unwrap();

    let receivers = vec![
        unified::Receiver::P2pkh(p2pkh),
        unified::Receiver::Sapling(sapling),
    ];

    let ua = unified::Address::try_from_items(receivers)
        .map_err(|e| JsError::new(&format!("unified address: {:?}", e)))?;

    Ok(ua.encode(&NetworkType::Main))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_import;
    use wasm_bindgen_test::*;

    fn abandon_seed() -> Vec<u8> {
        hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap()
    }

    const ABANDON_ADDR: &str = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";

    fn seed_and_extras() -> (Vec<u8>, Vec<u8>) {
        let seed = abandon_seed();
        let import = key_import::tests::run_key_import_native(3, 2, &seed, 0);
        let pkp = import.results[0].1.clone();
        (pkp, import.extras)
    }

    #[test]
    fn test_generate_extras() {
        let extras = frozt_sapling_generate_extras().unwrap();
        assert_eq!(extras.len(), 96);

        let nsk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
        let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
        assert!(nsk.is_some());
    }

    #[test]
    fn test_derive_keys() {
        let (pkp, extras) = seed_and_extras();
        let keys = frozt_sapling_derive_keys(&pkp, &extras).unwrap();
        assert_eq!(keys.address(), ABANDON_ADDR);
        assert_eq!(keys.ivk().len(), 32);
        assert_eq!(keys.nk().len(), 32);

        let nsk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
        let nsk: jubjub::Fr = jubjub::Fr::from_repr(nsk_bytes).unwrap();
        let expected_nk = sapling_crypto::constants::PROOF_GENERATION_KEY_GENERATOR * nsk;
        assert_eq!(keys.nk(), expected_nk.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_generate_extras_wasm() {
        test_generate_extras();
    }

    #[wasm_bindgen_test]
    fn test_derive_keys_wasm() {
        test_derive_keys();
    }

    #[test]
    fn test_build_unified_address() {
        use zcash_address::unified::Container;

        let (pkp, extras) = seed_and_extras();
        let keys = frozt_sapling_derive_keys(&pkp, &extras).unwrap();

        let sapling_raw = bech32::decode(keys.address().as_str()).unwrap().1;
        assert_eq!(sapling_raw.len(), 43);

        let p2pkh_hash = [0x42u8; 20]; // dummy transparent hash
        let ua = frozt_sapling_build_unified_address(&p2pkh_hash, &sapling_raw).unwrap();
        assert!(ua.starts_with("u1"), "unified address should start with u1, got: {}", ua);

        let (net, decoded) = zcash_address::unified::Address::decode(&ua).unwrap();
        assert_eq!(net, zcash_protocol::consensus::NetworkType::Main);
        let items = decoded.items();
        assert_eq!(items.len(), 2);

        let has_sapling = items.iter().any(|r| matches!(r, zcash_address::unified::Receiver::Sapling(_)));
        let has_p2pkh = items.iter().any(|r| matches!(r, zcash_address::unified::Receiver::P2pkh(_)));
        assert!(has_sapling, "UA should contain Sapling receiver");
        assert!(has_p2pkh, "UA should contain P2PKH receiver");
    }

    #[wasm_bindgen_test]
    fn test_build_unified_address_wasm() {
        test_build_unified_address();
    }

}
