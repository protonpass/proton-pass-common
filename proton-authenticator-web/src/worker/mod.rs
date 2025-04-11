use wasm_bindgen::JsError;

mod client;
mod crypto;
mod generator;
mod import;
mod issuer;

pub type JsResult<T> = Result<T, JsError>;
