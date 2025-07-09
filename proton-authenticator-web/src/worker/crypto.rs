use super::JsResult;
use crate::common::*;
use crate::entry::*;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_key() -> Uint8Array {
    let key = proton_authenticator::crypto::generate_encryption_key();
    vec_to_uint8_array(key)
}

#[wasm_bindgen]
pub fn encrypt_entries(models: Vec<WasmAuthenticatorEntryModel>, key: Uint8Array) -> JsResult<Vec<Uint8Array>> {
    let key_as_array = key.to_vec();
    let mut serialized_entries = Vec::with_capacity(models.len());
    for model in models {
        let as_entry = model.to_entry()?;
        serialized_entries.push(as_entry);
    }

    let encrypted_entries = proton_authenticator::encrypt_entries(serialized_entries, key_as_array)?;

    let mut array_entries = Vec::with_capacity(encrypted_entries.len());
    for entry in encrypted_entries {
        array_entries.push(vec_to_uint8_array(entry));
    }

    Ok(array_entries)
}

#[wasm_bindgen]
pub fn decrypt_entries(
    encrypted_entries: Vec<Uint8Array>,
    key: Uint8Array,
) -> JsResult<Vec<WasmAuthenticatorEntryModel>> {
    let key_as_array = key.to_vec();
    let mut entries_to_decrypt = Vec::with_capacity(encrypted_entries.len());
    for entry in encrypted_entries {
        let entry_as_bytes = entry.to_vec();
        entries_to_decrypt.push(entry_as_bytes);
    }

    let decrypted_entries = proton_authenticator::decrypt_entries(entries_to_decrypt, key_as_array)?;

    let mut mapped_entries = Vec::with_capacity(decrypted_entries.len());
    for entry in decrypted_entries {
        mapped_entries.push(WasmAuthenticatorEntryModel::from(entry));
    }

    Ok(mapped_entries)
}
