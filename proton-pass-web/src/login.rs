use proton_pass_common::login::Login;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmLogin {
    title: String,
    username: String,
    password: String,
    totp: Option<String>,
    urls: Vec<String>,
}

impl From<WasmLogin> for Login {
    fn from(value: WasmLogin) -> Self {
        Login {
            title: value.title,
            username: value.username,
            password: value.password,
            totp: value.totp,
            urls: value.urls,
        }
    }
}
