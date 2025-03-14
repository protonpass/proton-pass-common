use crate::common::vec_to_uint8_array;
use crate::entry::*;
use js_sys::Uint8Array;
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
    pub entry: WasmAuthenticatorEntryModel,
}

impl From<AuthenticatorCodeResponse> for WasmAuthenticatorCodeResponse {
    fn from(resp: AuthenticatorCodeResponse) -> Self {
        Self {
            current_code: resp.current_code,
            next_code: resp.next_code,
            entry: WasmAuthenticatorEntryModel::from(resp.entry),
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

#[wasm_bindgen]
pub fn serialize_entries(models: Vec<WasmAuthenticatorEntryModel>) -> JsResult<Vec<Uint8Array>> {
    let mut serialized_entries = Vec::with_capacity(models.len());
    for model in models {
        let as_entry = model.to_entry()?;
        let serialized = as_entry.serialize()?;
        serialized_entries.push(vec_to_uint8_array(serialized));
    }

    Ok(serialized_entries)
}

#[wasm_bindgen]
pub fn deserialize_entries(serialized_entries: Vec<Uint8Array>) -> JsResult<Vec<WasmAuthenticatorEntryModel>> {
    let mut deserialized_entries = Vec::with_capacity(serialized_entries.len());
    for entry in serialized_entries {
        let entry_as_bytes = entry.to_vec();
        let as_entry = AuthenticatorEntry::deserialize(&entry_as_bytes)
            .map_err(|e| JsError::new(&format!("failed to deserialize entry: {:?}", e)))?;

        let as_model = WasmAuthenticatorEntryModel::from(as_entry);
        deserialized_entries.push(as_model);
    }

    Ok(deserialized_entries)
}
