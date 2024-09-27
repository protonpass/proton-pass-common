use proton_pass_common::passkey::{
    generate_passkey_for_domain, parse_create_passkey_data, resolve_challenge_for_domain, PasskeyResult,
};

use proton_pass_common::passkey_types::webauthn::{
    AuthenticatedPublicKeyCredential, AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponse,
    AuthenticatorAttachment, AuthenticatorAttestationResponse, AuthenticatorTransport, CreatedPublicKeyCredential,
    CredentialPropertiesOutput, PublicKeyCredentialType,
};

use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "kebab-case")]
pub enum WasmAuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

impl From<AuthenticatorAttachment> for WasmAuthenticatorAttachment {
    fn from(value: AuthenticatorAttachment) -> Self {
        match value {
            AuthenticatorAttachment::Platform => WasmAuthenticatorAttachment::Platform,
            AuthenticatorAttachment::CrossPlatform => WasmAuthenticatorAttachment::CrossPlatform,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "kebab-case")]
pub enum WasmPublicKeyCredentialType {
    PublicKey,
    Unknown,
}

impl From<PublicKeyCredentialType> for WasmPublicKeyCredentialType {
    fn from(value: PublicKeyCredentialType) -> Self {
        match value {
            PublicKeyCredentialType::PublicKey => WasmPublicKeyCredentialType::PublicKey,
            PublicKeyCredentialType::Unknown => WasmPublicKeyCredentialType::Unknown,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorExtensionsClientOutputs {
    #[serde(rename = "credProps")]
    pub cred_props: Option<WasmCredentialPropertiesOutput>,
}

impl From<AuthenticationExtensionsClientOutputs> for WasmAuthenticatorExtensionsClientOutputs {
    fn from(value: AuthenticationExtensionsClientOutputs) -> Self {
        Self {
            cred_props: value.cred_props.map(WasmCredentialPropertiesOutput::from),
        }
    }
}

// Keep the serde macros in sync `webauthn/extensions.rs`
#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmCredentialPropertiesOutput {
    #[serde(rename = "rk", default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,
    // #[serde(default, skip_serializing_if = "Option::is_none")]
    // pub authenticator_display_name: Option<String>,
}

impl From<CredentialPropertiesOutput> for WasmCredentialPropertiesOutput {
    fn from(value: CredentialPropertiesOutput) -> Self {
        Self {
            discoverable: value.discoverable,
            // authenticator_display_name: value.authenticator_display_name,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub public_key_algorithm: i64,
    pub attestation_object: Vec<u8>,
    pub transports: Option<Vec<WasmAuthenticatorTransport>>,
}

impl From<AuthenticatorAttestationResponse> for WasmAuthenticatorAttestationResponse {
    fn from(value: AuthenticatorAttestationResponse) -> Self {
        Self {
            client_data_json: value.client_data_json.to_vec(),
            authenticator_data: value.authenticator_data.to_vec(),
            public_key: value.public_key.map(|k| k.to_vec()),
            public_key_algorithm: value.public_key_algorithm,
            attestation_object: value.attestation_object.to_vec(),
            transports: value
                .transports
                .map(|transports| transports.into_iter().map(WasmAuthenticatorTransport::from).collect()),
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmAuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub attestation_object: Option<Vec<u8>>,
}

impl From<AuthenticatorAssertionResponse> for WasmAuthenticatorAssertionResponse {
    fn from(value: AuthenticatorAssertionResponse) -> Self {
        Self {
            client_data_json: value.client_data_json.to_vec(),
            authenticator_data: value.authenticator_data.to_vec(),
            signature: value.signature.to_vec(),
            user_handle: value.user_handle.map(|k| k.to_vec()),
            attestation_object: value.attestation_object.map(|k| k.to_vec()),
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmPublicKeyCredentialAttestation {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: WasmAuthenticatorAttestationResponse,
    pub authenticator_attachment: Option<WasmAuthenticatorAttachment>,
    pub client_extension_results: WasmAuthenticatorExtensionsClientOutputs,
    pub r#type: WasmPublicKeyCredentialType,
}

impl From<CreatedPublicKeyCredential> for WasmPublicKeyCredentialAttestation {
    fn from(value: CreatedPublicKeyCredential) -> Self {
        Self {
            id: value.id,
            raw_id: value.raw_id.to_vec(),
            response: WasmAuthenticatorAttestationResponse::from(value.response),
            authenticator_attachment: value.authenticator_attachment.map(WasmAuthenticatorAttachment::from),
            client_extension_results: WasmAuthenticatorExtensionsClientOutputs::from(value.client_extension_results),
            r#type: WasmPublicKeyCredentialType::from(value.ty),
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmPublicKeyCredentialAssertion {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: WasmAuthenticatorAssertionResponse,
    pub authenticator_attachment: Option<WasmAuthenticatorAttachment>,
    pub client_extension_results: WasmAuthenticatorExtensionsClientOutputs,
    pub r#type: WasmPublicKeyCredentialType,
}

impl From<AuthenticatedPublicKeyCredential> for WasmPublicKeyCredentialAssertion {
    fn from(value: AuthenticatedPublicKeyCredential) -> Self {
        Self {
            response: WasmAuthenticatorAssertionResponse::from(value.response),
            id: value.id,
            raw_id: value.raw_id.to_vec(),
            authenticator_attachment: value.authenticator_attachment.map(WasmAuthenticatorAttachment::from),
            client_extension_results: WasmAuthenticatorExtensionsClientOutputs::from(value.client_extension_results),
            r#type: WasmPublicKeyCredentialType::from(value.ty),
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "kebab-case")]
pub enum WasmAuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Hybrid,
    Internal,
}

impl From<AuthenticatorTransport> for WasmAuthenticatorTransport {
    fn from(value: AuthenticatorTransport) -> Self {
        match value {
            AuthenticatorTransport::Usb => WasmAuthenticatorTransport::Usb,
            AuthenticatorTransport::Nfc => WasmAuthenticatorTransport::Nfc,
            AuthenticatorTransport::Ble => WasmAuthenticatorTransport::Ble,
            AuthenticatorTransport::Hybrid => WasmAuthenticatorTransport::Hybrid,
            AuthenticatorTransport::Internal => WasmAuthenticatorTransport::Internal,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmGeneratePasskeyResponse {
    pub credential: WasmPublicKeyCredentialAttestation,
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
    pub credential: WasmPublicKeyCredentialAssertion,
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmCreatePasskeyData {
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

pub struct PasskeyManager;

impl PasskeyManager {
    pub async fn generate_passkey(url: String, request: String) -> PasskeyResult<WasmGeneratePasskeyResponse> {
        let res = generate_passkey_for_domain(&url, &request).await?;

        let credential = WasmPublicKeyCredentialAttestation::from(res.credential);

        Ok(WasmGeneratePasskeyResponse {
            credential,
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

    pub async fn resolve_challenge(
        url: String,
        passkey: Vec<u8>,
        request: String,
    ) -> PasskeyResult<WasmResolvePasskeyChallengeResponse> {
        let res = resolve_challenge_for_domain(&url, &passkey, &request).await?;

        let credential = WasmPublicKeyCredentialAssertion::from(res.response);

        Ok(WasmResolvePasskeyChallengeResponse { credential })
    }

    pub fn parse_create_request(request: String) -> PasskeyResult<WasmCreatePasskeyData> {
        parse_create_passkey_data(&request).map(|d| WasmCreatePasskeyData {
            rp_id: d.rp_id,
            rp_name: d.rp_name,
            user_name: d.user_name,
            user_display_name: d.user_display_name,
        })
    }
}
