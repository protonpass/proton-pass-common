use proton_authenticator::{IssuerInfo, TOTPIssuerMapper};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmIssuerInfo {
    pub domain: String,
    pub icon_url: String,
}

impl From<IssuerInfo> for WasmIssuerInfo {
    fn from(value: IssuerInfo) -> Self {
        Self {
            domain: value.domain,
            icon_url: value.icon_url,
        }
    }
}

#[wasm_bindgen]
pub struct WasmIssuerMapper {
    inner: TOTPIssuerMapper,
}

impl Default for WasmIssuerMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmIssuerMapper {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: TOTPIssuerMapper::new(),
        }
    }

    #[wasm_bindgen]
    pub fn get_issuer_info(&self, issuer: String) -> Option<WasmIssuerInfo> {
        self.inner.lookup(&issuer).map(WasmIssuerInfo::from)
    }
}
