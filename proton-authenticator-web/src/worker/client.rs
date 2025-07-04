use super::JsResult;
use crate::common::vec_to_uint8_array;
use crate::entry::*;
use js_sys::Uint8Array;
use proton_authenticator::{
    Algorithm, AuthenticatorClient, AuthenticatorCodeResponse, AuthenticatorEntry,
    AuthenticatorEntrySteamCreateParameters as CommonSteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters as CommonTotpCreateParameters, AuthenticatorEntryTotpParameters,
    AuthenticatorEntryUpdateContents as CommonUpdateContents,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn entry_from_uri(uri: String) -> JsResult<WasmAuthenticatorEntryModel> {
    let entry = AuthenticatorEntry::from_uri(&uri, None)?;
    let as_model = WasmAuthenticatorEntryModel::from(entry);
    Ok(as_model)
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntryTotpCreateParameters {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: Option<u16>,
    pub digits: Option<u8>,
    pub algorithm: Option<TotpAlgorithm>,
    pub note: Option<String>,
}

impl From<WasmAuthenticatorEntryTotpCreateParameters> for CommonTotpCreateParameters {
    fn from(entry: WasmAuthenticatorEntryTotpCreateParameters) -> Self {
        Self {
            name: entry.name,
            secret: entry.secret,
            issuer: entry.issuer,
            period: entry.period,
            digits: entry.digits,
            algorithm: entry.algorithm.map(Algorithm::from),
            note: entry.note,
        }
    }
}

#[wasm_bindgen]
pub fn new_totp_entry_from_params(
    params: WasmAuthenticatorEntryTotpCreateParameters,
) -> JsResult<WasmAuthenticatorEntryModel> {
    let mapped_params = CommonTotpCreateParameters::from(params);
    let entry = AuthenticatorEntry::new_totp_entry_from_params(mapped_params)?;
    Ok(entry.into())
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntrySteamCreateParameters {
    pub name: String,
    pub secret: String,
    pub note: Option<String>,
}

impl From<WasmAuthenticatorEntrySteamCreateParameters> for CommonSteamCreateParameters {
    fn from(entry: WasmAuthenticatorEntrySteamCreateParameters) -> Self {
        Self {
            name: entry.name,
            secret: entry.secret,
            note: entry.note,
        }
    }
}

#[wasm_bindgen]
pub fn new_steam_entry_from_params(
    params: WasmAuthenticatorEntrySteamCreateParameters,
) -> JsResult<WasmAuthenticatorEntryModel> {
    let mapped_params = CommonSteamCreateParameters::from(params);
    let entry = AuthenticatorEntry::new_steam_entry_from_params(mapped_params)?;
    Ok(entry.into())
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntryUpdateContents {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: u16,
    pub digits: u8,
    pub algorithm: TotpAlgorithm,
    pub note: Option<String>,
    pub entry_type: WasmAuthenticatorEntryType,
}

impl From<WasmAuthenticatorEntryUpdateContents> for CommonUpdateContents {
    fn from(entry: WasmAuthenticatorEntryUpdateContents) -> Self {
        Self {
            name: entry.name,
            secret: entry.secret,
            issuer: entry.issuer,
            period: entry.period,
            digits: entry.digits,
            algorithm: Algorithm::from(entry.algorithm),
            note: entry.note,
            entry_type: proton_authenticator::AuthenticatorEntryType::from(entry.entry_type),
        }
    }
}

#[wasm_bindgen]
pub fn update_entry(
    entry: WasmAuthenticatorEntryModel,
    update: WasmAuthenticatorEntryUpdateContents,
) -> JsResult<WasmAuthenticatorEntryModel> {
    let mut as_entry = entry.to_entry()?;
    let mapped_params = CommonUpdateContents::from(update);
    as_entry.update(mapped_params)?;
    Ok(as_entry.into())
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

impl From<TotpAlgorithm> for Algorithm {
    fn from(value: TotpAlgorithm) -> Self {
        match value {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntryTotpParameters {
    pub secret: String,
    pub issuer: String,
    pub period: u16,
    pub digits: u8,
    pub algorithm: TotpAlgorithm,
}

impl From<AuthenticatorEntryTotpParameters> for WasmAuthenticatorEntryTotpParameters {
    fn from(value: AuthenticatorEntryTotpParameters) -> Self {
        Self {
            secret: value.secret,
            issuer: value.issuer.unwrap_or_default(),
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
        Err(e) => Err(JsError::new(&format!("{e:?}"))),
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
            .map_err(|e| JsError::new(&format!("failed to deserialize entry: {e:?}")))?;

        let as_model = WasmAuthenticatorEntryModel::from(as_entry);
        deserialized_entries.push(as_model);
    }

    Ok(deserialized_entries)
}

#[wasm_bindgen]
pub fn export_entries(models: Vec<WasmAuthenticatorEntryModel>) -> JsResult<String> {
    let mut mapped = vec![];
    for entry in models {
        mapped.push(entry.to_entry()?);
    }
    let client = AuthenticatorClient::new();
    Ok(client.export_entries(mapped)?)
}

#[wasm_bindgen]
pub fn export_entries_with_password(models: Vec<WasmAuthenticatorEntryModel>, password: String) -> JsResult<String> {
    let mut mapped = vec![];
    for entry in models {
        mapped.push(entry.to_entry()?);
    }
    let client = AuthenticatorClient::new();
    Ok(client.export_entries_with_password(mapped, &password)?)
}
