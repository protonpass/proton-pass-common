use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmBoolDict(pub std::collections::HashMap<String, bool>);

#[allow(dead_code)]
pub fn vec_to_uint8_array(source: Vec<u8>) -> js_sys::Uint8Array {
    let js_res = js_sys::Uint8Array::new_with_length(source.len() as u32);
    for (idx, value) in source.into_iter().enumerate() {
        js_res.set_index(idx as u32, value);
    }

    js_res
}
