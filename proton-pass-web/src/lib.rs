use wasm_bindgen::prelude::*;

mod common;

#[cfg(feature = "web_password")]
mod password;

#[cfg(feature = "web_ui")]
mod ui;

#[cfg(feature = "web_worker")]
mod worker;

#[cfg(feature = "web_username")]
mod username;

#[wasm_bindgen]
pub fn library_version() -> String {
    proton_pass_common::library_version()
}
