use wasm_bindgen::prelude::*;

mod common;
mod entry;
mod log;
mod worker;

#[wasm_bindgen]
pub fn library_version() -> String {
    proton_authenticator::library_version()
}
