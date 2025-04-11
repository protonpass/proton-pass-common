use super::JsResult;
use crate::common::*;
use crate::entry::*;
use js_sys::Uint8Array;
use proton_authenticator::crypto::EncryptionTag;
use proton_authenticator::AuthenticatorEntry;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_key() -> Uint8Array {
    let key = proton_authenticator::crypto::generate_encryption_key();
    vec_to_uint8_array(key)
}

#[wasm_bindgen]
pub fn encrypt_entries(models: Vec<WasmAuthenticatorEntryModel>, key: Uint8Array) -> JsResult<Vec<Uint8Array>> {
    let key_as_array = key.to_vec();
    let mut encrypted_entries = Vec::with_capacity(models.len());
    for model in models {
        let as_entry = model.to_entry()?;
        let serialized = as_entry.serialize()?;
        let encrypted = proton_authenticator::crypto::encrypt(&serialized, &key_as_array, EncryptionTag::Entry)
            .map_err(|e| JsError::new(&format!("failed to encrypt entry: {:?}", e)))?;
        encrypted_entries.push(vec_to_uint8_array(encrypted));
    }

    Ok(encrypted_entries)
}

#[wasm_bindgen]
pub fn decrypt_entries(
    encrypted_entries: Vec<Uint8Array>,
    key: Uint8Array,
) -> JsResult<Vec<WasmAuthenticatorEntryModel>> {
    let key_as_array = key.to_vec();
    let mut decrypted_entries = Vec::with_capacity(encrypted_entries.len());
    for entry in encrypted_entries {
        let entry_as_bytes = entry.to_vec();
        let decrypted = proton_authenticator::crypto::decrypt(&entry_as_bytes, &key_as_array, EncryptionTag::Entry)
            .map_err(|e| JsError::new(&format!("failed to decrypt entry: {:?}", e)))?;

        let as_entry = AuthenticatorEntry::deserialize(&decrypted)
            .map_err(|e| JsError::new(&format!("failed to deserialize entry: {:?}", e)))?;

        let as_model = WasmAuthenticatorEntryModel::from(as_entry);
        decrypted_entries.push(as_model);
    }

    Ok(decrypted_entries)
}
