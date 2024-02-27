use proton_pass_common::passkey::{
    generate_passkey_for_domain, parse_create_passkey_data, resolve_challenge_for_domain, PasskeyError, PasskeyResult,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

pub struct PasskeyManager {
    rt: tokio::runtime::Runtime,
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmGeneratePasskeyResponse {
    pub response: String,
    pub passkey: Vec<u8>,
    pub key_id: String,
    pub domain: String,
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub client_data_hash: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmResolvePasskeyChallengeResponse {
    pub response: String,
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmCreatePasskeyData {
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

impl PasskeyManager {
    pub fn new() -> PasskeyResult<Self> {
        match tokio::runtime::Builder::new_current_thread().build() {
            Ok(rt) => Ok(Self { rt }),
            Err(e) => Err(PasskeyError::RuntimeError(format!("Error creating runtime: {:?}", e))),
        }
    }

    pub fn generate_passkey(&self, url: String, request: String) -> PasskeyResult<WasmGeneratePasskeyResponse> {
        let res = self
            .rt
            .handle()
            .block_on(async move { generate_passkey_for_domain(&url, &request).await })?;

        let response = res.response()?;

        Ok(WasmGeneratePasskeyResponse {
            response,
            key_id: res.key_id,
            passkey: res.passkey,
            domain: res.domain,
            rp_id: res.rp_id,
            rp_name: res.rp_name,
            user_name: res.user_name,
            user_display_name: res.user_display_name,
            user_id: res.user_id,
            credential_id: res.credential_id,
            user_handle: res.user_handle,
            client_data_hash: res.client_data_hash,
            attestation_object: res.attestation_object,
        })
    }

    pub fn resolve_challenge(
        &self,
        url: String,
        passkey: Vec<u8>,
        request: String,
    ) -> PasskeyResult<WasmResolvePasskeyChallengeResponse> {
        let res = self
            .rt
            .handle()
            .block_on(async move { resolve_challenge_for_domain(&url, &passkey, &request).await })?;

        let response = res.response()?;

        Ok(WasmResolvePasskeyChallengeResponse { response })
    }

    pub fn parse_create_request(&self, request: String) -> PasskeyResult<WasmCreatePasskeyData> {
        parse_create_passkey_data(&request).map(|d| WasmCreatePasskeyData {
            rp_id: d.rp_id,
            rp_name: d.rp_name,
            user_name: d.user_name,
            user_display_name: d.user_display_name,
        })
    }
}
