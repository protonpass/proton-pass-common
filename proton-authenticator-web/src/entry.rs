use proton_authenticator::AuthenticatorEntry;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntryModel {
    name: String,
    uri: String,
    period: u16,
    note: Option<String>,
    entry_type: WasmAuthenticatorEntryType,
}

impl WasmAuthenticatorEntryModel {
    pub fn to_entry(&self) -> Result<AuthenticatorEntry, JsError> {
        Ok(AuthenticatorEntry::from_uri(&self.uri, self.note.clone())
            .map_err(|e| proton_authenticator::AuthenticatorError::Unknown(format!("cannot parse uri: {:?}", e)))?)
    }
}

impl From<AuthenticatorEntry> for WasmAuthenticatorEntryModel {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            name: entry.name(),
            uri: entry.uri(),
            period: entry.period(),
            note: entry.note,
            entry_type: WasmAuthenticatorEntryType::from(entry.content),
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmAuthenticatorEntryType {
    Totp,
    Steam,
}

impl From<proton_authenticator::AuthenticatorEntryContent> for WasmAuthenticatorEntryType {
    fn from(value: proton_authenticator::AuthenticatorEntryContent) -> Self {
        match value {
            proton_authenticator::AuthenticatorEntryContent::Totp(_) => WasmAuthenticatorEntryType::Totp,
            proton_authenticator::AuthenticatorEntryContent::Steam(_) => WasmAuthenticatorEntryType::Steam,
        }
    }
}
