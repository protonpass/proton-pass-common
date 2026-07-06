use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize, Debug)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmConvertImageError {
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl WasmConvertImageError {
    pub fn unsupported_input_format() -> Self {
        Self {
            error_type: "UnsupportedInputFormat".to_string(),
            message: None,
        }
    }

    pub fn image(message: String) -> Self {
        Self {
            error_type: "Image".to_string(),
            message: Some(message),
        }
    }
}
