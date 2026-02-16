// Re-export core types that now have wasm bindings
pub use proton_pass_common::sshkey::SshKeyPair as WasmSshKeyPair;

use proton_pass_common::sshkey::{
    decrypt_private_key, generate_ssh_key, validate_private_key, validate_public_key, SshKeyType,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate_public_ssh_key(key: String) -> Result<(), JsError> {
    validate_public_key(&key).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn validate_private_ssh_key(key: String) -> Result<(), JsError> {
    validate_private_key(&key).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn generate_ssh_key_pair(
    comment: String,
    key_type: SshKeyType,
    passphrase: Option<String>,
) -> Result<WasmSshKeyPair, JsError> {
    generate_ssh_key(comment, key_type, passphrase).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn decrypt_private_ssh_key(encrypted_key: String, password: String) -> Result<String, JsError> {
    decrypt_private_key(&encrypted_key, &password).map_err(|e| JsError::new(&format!("{:?}", e)))
}
