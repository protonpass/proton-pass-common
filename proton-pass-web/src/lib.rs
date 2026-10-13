use wasm_bindgen::prelude::*;

mod common;
#[cfg(feature = "web_cxf")]
mod cxf;
#[cfg(feature = "web_duplicate")]
mod duplicate;
#[cfg(feature = "resize-image")]
pub mod image;
#[cfg(feature = "web_duplicate")]
mod merge;
#[cfg(feature = "web_proto")]
mod proto_utils;

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

#[cfg(feature = "web_proto")]
pub use proto_utils::*;
pub use proton_pass_types::*;
