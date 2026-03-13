use wasm_bindgen::prelude::*;

pub mod dkg;
pub mod sign;
pub mod reshare;
pub mod scan;
pub mod session;
pub mod spend;
pub mod key_image;

fn to_js_err<E: std::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

#[wasm_bindgen]
pub fn fromt_handle_free(handle_id: i32) -> Result<(), JsValue> {
    use fromtlib::handle::Handle;
    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    Handle::free(handle).map_err(to_js_err)
}
