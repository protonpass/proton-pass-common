use proton_authenticator::AuthenticatorEntry;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorEntryModel {
    id: String,
    name: String,
    uri: String,
    period: u16,
    issuer: String,
    secret: String,
    note: Option<String>,
    entry_type: WasmAuthenticatorEntryType,
}

impl WasmAuthenticatorEntryModel {
    pub fn to_entry(&self) -> Result<AuthenticatorEntry, JsError> {
        Ok(
            AuthenticatorEntry::from_uri_and_id(&self.uri, self.note.clone(), self.id.clone())
                .map_err(|e| proton_authenticator::AuthenticatorError::Unknown(format!("cannot parse uri: {:?}", e)))?,
        )
    }
}

impl From<AuthenticatorEntry> for WasmAuthenticatorEntryModel {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            name: entry.name(),
            uri: entry.uri(),
            issuer: entry.issuer(),
            period: entry.period(),
            secret: entry.secret(),
            note: entry.note,
            entry_type: WasmAuthenticatorEntryType::from(entry.content),
        }
    }
}

#[derive(Debug, Tsify, Deserialize, Serialize)]
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
