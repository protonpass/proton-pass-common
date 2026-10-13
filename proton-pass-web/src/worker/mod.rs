use std::collections::HashMap;
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

use crate::common::{WasmBoolDict, vec_to_uint8_array};
use passkey::WasmCreatePasskeyData;
use passkey::{PasskeyManager, WasmGeneratePasskeyResponse, WasmResolvePasskeyChallengeResponse};

mod passkey;
mod passkey_fetcher;
mod share;
#[cfg(feature = "experimental")]
mod sshkey;
mod totp;

#[wasm_bindgen]
pub fn twofa_domain_eligible(domain: String) -> bool {
    proton_pass_common::twofa::TwofaDomainChecker::twofa_domain_eligible(&domain)
}

#[wasm_bindgen]
pub fn twofa_domains_eligible(domains: Vec<String>) -> Result<Ts<WasmBoolDict>, JsError> {
    let mut dict: HashMap<String, bool> = HashMap::new();

    for domain in domains {
        let elligible = proton_pass_common::twofa::TwofaDomainChecker::twofa_domain_eligible(&domain);
        dict.insert(domain, elligible);
    }

    Ok(WasmBoolDict(dict).into_ts()?)
}

#[wasm_bindgen]
pub fn create_new_user_invite_signature_body(email: String, vault_key: js_sys::Uint8Array) -> js_sys::Uint8Array {
    let vault_key_as_vec = vault_key.to_vec();
    let res = proton_pass_common::invite::create_signature_body(&email, vault_key_as_vec);
    vec_to_uint8_array(res)
}

#[wasm_bindgen]
pub async fn generate_passkey(
    domain: String,
    request: String,
    allows_insecure_localhost: bool,
) -> Result<Ts<WasmGeneratePasskeyResponse>, JsError> {
    let res = PasskeyManager::generate_passkey(domain, request, allows_insecure_localhost).await?;
    Ok(res.into_ts()?)
}

#[wasm_bindgen]
pub async fn resolve_passkey_challenge(
    domain: String,
    passkey: js_sys::Uint8Array,
    request: String,
    allows_insecure_localhost: bool,
) -> Result<Ts<WasmResolvePasskeyChallengeResponse>, JsError> {
    let passkey_as_vec = passkey.to_vec();
    let res = PasskeyManager::resolve_challenge(domain, passkey_as_vec, request, allows_insecure_localhost).await?;
    Ok(res.into_ts()?)
}

#[wasm_bindgen]
pub fn parse_create_passkey_data(request: String) -> Result<Ts<WasmCreatePasskeyData>, JsError> {
    let res = PasskeyManager::parse_create_request(request)?;
    Ok(res.into_ts()?)
}
