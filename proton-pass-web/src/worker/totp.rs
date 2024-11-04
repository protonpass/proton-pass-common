use proton_pass_common::totp::{algorithm::Algorithm, totp::TOTP};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl From<Algorithm> for TotpAlgorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::SHA1 => TotpAlgorithm::SHA1,
            Algorithm::SHA256 => TotpAlgorithm::SHA256,
            Algorithm::SHA512 => TotpAlgorithm::SHA512,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ParsedTotp {
    pub label: Option<String>,
    pub secret: String,
    pub issuer: Option<String>,
    pub algorithm: Option<TotpAlgorithm>,
    pub digits: Option<u8>,
    pub period: Option<u16>,
}

impl From<TOTP> for ParsedTotp {
    fn from(value: TOTP) -> Self {
        Self {
            label: value.label,
            secret: value.secret,
            issuer: value.issuer,
            algorithm: value.algorithm.map(TotpAlgorithm::from),
            digits: value.digits,
            period: value.period,
        }
    }
}

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
        totp: totp.into(),
        token,
        timestamp: current_time,
    })
}
