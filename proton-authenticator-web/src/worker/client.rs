use crate::entry::*;
use proton_authenticator::{
    Algorithm, AuthenticatorCodeResponse, AuthenticatorEntry, AuthenticatorEntryTotpParameters,
};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

type JsResult<T> = Result<T, JsError>;

#[wasm_bindgen]
pub fn entry_from_uri(uri: String) -> JsResult<WasmAuthenticatorEntryModel> {
    let entry = AuthenticatorEntry::from_uri(&uri, None)?;
    let as_model = WasmAuthenticatorEntryModel::from(entry);
    Ok(as_model)
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorCodeResponse {
    pub current_code: String,
    pub next_code: String,
}

impl From<AuthenticatorCodeResponse> for WasmAuthenticatorCodeResponse {
    fn from(resp: AuthenticatorCodeResponse) -> Self {
        Self {
            current_code: resp.current_code,
            next_code: resp.next_code,
        }
    }
}

#[wasm_bindgen]
pub fn generate_code(model: WasmAuthenticatorEntryModel, time: u64) -> JsResult<WasmAuthenticatorCodeResponse> {
    let as_entry = model.to_entry()?;
    let res = proton_authenticator::AuthenticatorClient.generate_codes(&[as_entry], time)?;
    if let Some(first) = res.into_iter().next() {
        Ok(WasmAuthenticatorCodeResponse::from(first))
    } else {
        Err(JsError::new("Authenticator could not generate a code"))
    }
}

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
pub struct WasmAuthenticatorEntryTotpParameters {
    pub secret: String,
    pub issuer: Option<String>,
    pub period: u16,
    pub digits: u8,
    pub algorithm: TotpAlgorithm,
}

impl From<AuthenticatorEntryTotpParameters> for WasmAuthenticatorEntryTotpParameters {
    fn from(value: AuthenticatorEntryTotpParameters) -> Self {
        Self {
            secret: value.secret,
            issuer: value.issuer,
            period: value.period,
            digits: value.digits,
            algorithm: value.algorithm.into(),
        }
    }
}

#[wasm_bindgen]
pub fn get_totp_parameters(model: WasmAuthenticatorEntryModel) -> JsResult<WasmAuthenticatorEntryTotpParameters> {
    let as_entry = model.to_entry()?;
    match as_entry.get_totp_parameters() {
        Ok(params) => Ok(WasmAuthenticatorEntryTotpParameters::from(params)),
        Err(e) => Err(JsError::new(&format!("{:?}", e))),
    }
}
