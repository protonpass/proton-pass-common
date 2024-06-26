use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::common::{vec_to_uint8_array, WasmBoolDict};
use passkey::WasmCreatePasskeyData;
use passkey::{PasskeyManager, WasmGeneratePasskeyResponse, WasmResolvePasskeyChallengeResponse};

mod passkey;

#[wasm_bindgen]
pub fn twofa_domain_eligible(domain: String) -> bool {
    proton_pass_common::twofa::TwofaDomainChecker::twofa_domain_eligible(&domain)
}

#[wasm_bindgen]
pub fn twofa_domains_eligible(domains: Vec<String>) -> WasmBoolDict {
    let mut dict: HashMap<String, bool> = HashMap::new();

    for domain in domains {
        let elligible = proton_pass_common::twofa::TwofaDomainChecker::twofa_domain_eligible(&domain);
        dict.insert(domain, elligible);
    }

    WasmBoolDict(dict)
}

#[wasm_bindgen]
pub fn create_new_user_invite_signature_body(email: String, vault_key: js_sys::Uint8Array) -> js_sys::Uint8Array {
    let vault_key_as_vec = vault_key.to_vec();
    let res = proton_pass_common::invite::create_signature_body(&email, vault_key_as_vec);
    vec_to_uint8_array(res)
}

#[wasm_bindgen]
pub async fn generate_passkey(domain: String, request: String) -> Result<WasmGeneratePasskeyResponse, JsError> {
    Ok(PasskeyManager::generate_passkey(domain, request).await?)
}

#[wasm_bindgen]
pub async fn resolve_passkey_challenge(
    domain: String,
    passkey: js_sys::Uint8Array,
    request: String,
) -> Result<WasmResolvePasskeyChallengeResponse, JsError> {
    let passkey_as_vec = passkey.to_vec();
    Ok(PasskeyManager::resolve_challenge(domain, passkey_as_vec, request).await?)
}

#[wasm_bindgen]
pub fn parse_create_passkey_data(request: String) -> Result<WasmCreatePasskeyData, JsError> {
    Ok(PasskeyManager::parse_create_request(request)?)
}
