use wasm_bindgen::prelude::*;

use fromtlib::ceremony::key_image;
use fromtlib::handle::Handle;

use crate::to_js_err;

#[wasm_bindgen]
pub struct KeyImagePart1Result {
    handle_id: i32,
    partials: Vec<u8>,
}

#[wasm_bindgen]
impl KeyImagePart1Result {
    #[wasm_bindgen(getter)]
    pub fn handle_id(&self) -> i32 {
        self.handle_id
    }

    #[wasm_bindgen(getter)]
    pub fn partials(&self) -> Vec<u8> {
        self.partials.clone()
    }
}

#[wasm_bindgen]
pub fn fromt_key_image_part1(
    key_share: &[u8],
    outputs: &[u8],
    signer_ids: &[u8],
) -> Result<KeyImagePart1Result, JsValue> {
    if signer_ids.len() % 2 != 0 {
        return Err(JsValue::from_str("signer_ids must be pairs of u16_le bytes"));
    }
    let ids: Vec<u16> = signer_ids
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let (state, partials) =
        key_image::key_image_part1(key_share, outputs, &ids).map_err(to_js_err)?;

    let handle = Handle::allocate(state).map_err(to_js_err)?;
    let handle_id: i32 = unsafe { std::mem::transmute(handle) };

    Ok(KeyImagePart1Result {
        handle_id,
        partials,
    })
}

#[wasm_bindgen]
pub fn fromt_key_image_part2(
    handle_id: i32,
    r1_packages: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let handle: Handle = unsafe { std::mem::transmute(handle_id) };
    let state = Handle::take::<key_image::KeyImageState>(handle).map_err(to_js_err)?;

    let packages = decode_packages(r1_packages)?;

    key_image::key_image_part2(state, &packages).map_err(to_js_err)
}

fn decode_packages(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, JsValue> {
    if data.len() < 4 {
        return Err(JsValue::from_str("packages data too short"));
    }
    let count =
        u32::from_le_bytes(data[0..4].try_into().map_err(|_| JsValue::from_str("bad len"))?)
            as usize;
    let mut pos = 4;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 6 > data.len() {
            return Err(JsValue::from_str("package truncated"));
        }
        let id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let vlen =
            u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| JsValue::from_str("bad len"))?)
                as usize;
        pos += 4;
        if pos + vlen > data.len() {
            return Err(JsValue::from_str("package data truncated"));
        }
        entries.push((id, data[pos..pos + vlen].to_vec()));
        pos += vlen;
    }
    Ok(entries)
}
