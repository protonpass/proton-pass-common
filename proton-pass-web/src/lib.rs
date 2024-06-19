use wasm_bindgen::prelude::*;

#[cfg(feature = "web_ui")]
mod creditcard;
#[cfg(feature = "web_ui")]
mod login;
#[cfg(feature = "web_ui")]
mod ui;

#[cfg(feature = "web_worker")]
mod common;
#[cfg(feature = "web_worker")]
mod passkey;
#[cfg(feature = "web_worker")]
mod password;
#[cfg(feature = "web_worker")]
mod utils;
#[cfg(feature = "web_worker")]
mod worker;

#[wasm_bindgen]
pub fn library_version() -> String {
    proton_pass_common::library_version()
}
