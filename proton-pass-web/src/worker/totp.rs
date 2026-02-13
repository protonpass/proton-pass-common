// Re-export core types with wasm bindings
pub use proton_pass_common::totp::totp::TOTP as ParsedTotp;

use proton_pass_common::totp::totp::TOTP;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TotpCode {
    pub totp: ParsedTotp,
    pub token: String,
    pub timestamp: u64,
}

#[wasm_bindgen]
pub fn generate_totp(uri: String, current_time: u64) -> Result<TotpCode, JsError> {
    let totp = TOTP::from_uri(&uri)?;
    let token = totp.generate_token(current_time)?;
    Ok(TotpCode {
        totp,
        token,
        timestamp: current_time,
    })
}
