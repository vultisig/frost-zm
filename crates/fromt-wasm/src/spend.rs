use wasm_bindgen::prelude::*;

use fromtlib::keyshare::bundle::KeyShareBundle;
use fromtlib::monero::spend;
use fromtlib::handle::Handle;

use crate::to_js_err;

#[wasm_bindgen]
pub struct SpendPreprocessResult {
    handle_id: i32,
    preprocess: Vec<u8>,
}

#[wasm_bindgen]
impl SpendPreprocessResult {
    #[wasm_bindgen(getter)]
    pub fn handle_id(&self) -> i32 {
        self.handle_id
    }

    #[wasm_bindgen(getter)]
    pub fn preprocess(&self) -> Vec<u8> {
        self.preprocess.clone()
    }
}

#[wasm_bindgen]
pub fn fromt_spend_preprocess(
    key_share: &[u8],
    signable_tx: &[u8],
) -> Result<SpendPreprocessResult, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let keys = spend::convert_keyshare(&bundle).map_err(to_js_err)?;

    let signable = monero_wallet::send::SignableTransaction::read(&mut &signable_tx[..])
        .map_err(|e| JsValue::from_str(&format!("parse signable tx: {:?}", e)))?;

    let (sign_machine, preprocess_bytes) = spend::spend_preprocess(signable, keys)
        .map_err(to_js_err)?;

    let handle = Handle::allocate(sign_machine).map_err(to_js_err)?;
    let handle_id = unsafe { std::mem::transmute::<Handle, i32>(handle) };

    Ok(SpendPreprocessResult {
        handle_id,
        preprocess: preprocess_bytes,
    })
}

#[wasm_bindgen]
pub struct SpendSignResult {
    handle_id: i32,
    share: Vec<u8>,
}

#[wasm_bindgen]
impl SpendSignResult {
    #[wasm_bindgen(getter)]
    pub fn handle_id(&self) -> i32 {
        self.handle_id
    }

    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Vec<u8> {
        self.share.clone()
    }
}

#[wasm_bindgen]
pub fn fromt_spend_sign(
    handle_id: i32,
    preprocesses_map: &[u8],
) -> Result<SpendSignResult, JsValue> {
    use std::collections::HashMap;
    use modular_frost::Participant;

    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    let sign_machine = handle.take::<monero_wallet::send::TransactionSignMachine>()
        .map_err(to_js_err)?;

    let raw_map = fromtlib::codec::decode_u16_map(preprocesses_map).map_err(to_js_err)?;
    let mut preprocesses = HashMap::new();
    for (id, bytes) in raw_map {
        preprocesses.insert(Participant::new(id).unwrap(), bytes);
    }

    let (sig_machine, share_bytes) = spend::spend_sign(sign_machine, preprocesses)
        .map_err(to_js_err)?;

    let new_handle = Handle::allocate(sig_machine).map_err(to_js_err)?;
    let new_handle_id = unsafe { std::mem::transmute::<Handle, i32>(new_handle) };

    Ok(SpendSignResult {
        handle_id: new_handle_id,
        share: share_bytes,
    })
}

#[wasm_bindgen]
pub fn fromt_spend_complete(
    handle_id: i32,
    shares_map: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use std::collections::HashMap;
    use modular_frost::Participant;

    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    let sig_machine = handle.take::<monero_wallet::send::TransactionSignatureMachine>()
        .map_err(to_js_err)?;

    let raw_map = fromtlib::codec::decode_u16_map(shares_map).map_err(to_js_err)?;
    let mut shares = HashMap::new();
    for (id, bytes) in raw_map {
        shares.insert(Participant::new(id).unwrap(), bytes);
    }

    spend::spend_complete(sig_machine, shares).map_err(to_js_err)
}
