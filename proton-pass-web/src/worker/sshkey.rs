use proton_pass_common::sshkey::{
    decrypt_private_key, generate_ssh_key, validate_private_key, validate_public_key, SshKeyPair, SshKeyType,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmSshKeyType {
    RSA2048,
    RSA4096,
    Ed25519,
}

impl From<WasmSshKeyType> for SshKeyType {
    fn from(value: WasmSshKeyType) -> Self {
        match value {
            WasmSshKeyType::RSA2048 => SshKeyType::RSA2048,
            WasmSshKeyType::RSA4096 => SshKeyType::RSA4096,
            WasmSshKeyType::Ed25519 => SshKeyType::Ed25519,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmSshKeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl From<SshKeyPair> for WasmSshKeyPair {
    fn from(value: SshKeyPair) -> Self {
        Self {
            public_key: value.public_key,
            private_key: value.private_key,
        }
    }
}

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
    key_type: WasmSshKeyType,
    passphrase: Option<String>,
) -> Result<WasmSshKeyPair, JsError> {
    let ssh_key_type = SshKeyType::from(key_type);
    let result = generate_ssh_key(comment, ssh_key_type, passphrase).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(WasmSshKeyPair::from(result))
}

#[wasm_bindgen]
pub fn decrypt_private_ssh_key(encrypted_key: String, password: String) -> Result<String, JsError> {
    decrypt_private_key(&encrypted_key, &password).map_err(|e| JsError::new(&format!("{:?}", e)))
}
