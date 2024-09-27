use super::passkey_handling::{deserialize_passkey, get_authenticator, parse_url};
use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey::client::Client;
use passkey_types::webauthn::{
    AuthenticatedPublicKeyCredential, CredentialRequestOptions, PublicKeyCredentialRequestOptions,
};
use url::Url;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolveChallengeResponse {
    pub response: AuthenticatedPublicKeyCredential,
}

impl ResolveChallengeResponse {
    pub fn response(&self) -> PasskeyResult<String> {
        serde_json::to_string(&self.response)
            .map_err(|e| PasskeyError::SerializationError(format!("Error serializing response: {:?}", e)))
    }
}

async fn resolve_challenge(origin: Url, pk: &ProtonPassKey, request: &str) -> PasskeyResult<ResolveChallengeResponse> {
    let parsed: PublicKeyCredentialRequestOptions = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;

    let credential_request = CredentialRequestOptions { public_key: parsed };

    let authenticator = get_authenticator(Some(pk.clone()));
    let mut client = Client::new(authenticator);

    let res = client
        .authenticate(&origin, credential_request, None)
        .await
        .map_err(|e| PasskeyError::ResolveChallengeError(format!("Error authenticating: {:?}", e)))?;

    Ok(ResolveChallengeResponse { response: res })
}

pub struct AuthenticateWithPasskeyAndroidRequest {
    pub origin: String,
    pub request: String,
    pub passkey: Vec<u8>,
    pub client_data_hash: Option<Vec<u8>>,
}

pub struct AuthenticateWithPasskeyIosRequest {
    pub service_identifier: String,
    pub passkey: Vec<u8>,
    pub client_data_hash: Vec<u8>,
}

pub struct AuthenticateWithPasskeyIosResponse {
    pub user_handle: Vec<u8>,
    pub relying_party: String,
    pub signature: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub credential_id: Vec<u8>,
}

async fn resolve_challenge_for_mobile(
    request: CredentialRequestOptions,
    passkey: &[u8],
    url: &Url,
    client_data_hash: Option<Vec<u8>>,
) -> PasskeyResult<AuthenticatedPublicKeyCredential> {
    let deserialized = deserialize_passkey(passkey)?;
    let authenticator = get_authenticator(Some(deserialized));
    let mut client = Client::new(authenticator);
    let res = client
        .authenticate(url, request, client_data_hash)
        .await
        .map_err(|e| PasskeyError::ResolveChallengeError(format!("Error authenticating: {:?}", e)))?;

    Ok(res)
}

pub async fn resolve_challenge_for_ios(
    request: AuthenticateWithPasskeyIosRequest,
) -> PasskeyResult<AuthenticateWithPasskeyIosResponse> {
    let url = parse_url(&request.service_identifier)?;
    let credential_request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: Default::default(),
            timeout: None,
            rp_id: Some(request.service_identifier.clone()),
            allow_credentials: None,
            user_verification: Default::default(),
            hints: None,
            attestation: Default::default(),
            attestation_formats: None,
            extensions: None,
        },
    };

    let res = resolve_challenge_for_mobile(
        credential_request,
        &request.passkey,
        &url,
        Some(request.client_data_hash.clone()),
    )
    .await?;

    let user_handle = res.response.user_handle.map(|h| h.to_vec()).unwrap_or_default();

    let response = AuthenticateWithPasskeyIosResponse {
        user_handle,
        relying_party: request.service_identifier,
        signature: res.response.signature.to_vec(),
        client_data_hash: request.client_data_hash,
        authenticator_data: res.response.authenticator_data.to_vec(),
        credential_id: res.raw_id.to_vec(),
    };
    Ok(response)
}

pub async fn resolve_challenge_for_android(request: AuthenticateWithPasskeyAndroidRequest) -> PasskeyResult<String> {
    let parsed: PublicKeyCredentialRequestOptions = serde_json::from_str(&request.request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;

    let url = parse_url(&request.origin)?;
    let credential_request = CredentialRequestOptions { public_key: parsed };

    let res =
        resolve_challenge_for_mobile(credential_request, &request.passkey, &url, request.client_data_hash).await?;

    let string_response = serde_json::to_string(&res)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing response: {:?}", e)))?;
    Ok(string_response)
}

pub async fn resolve_challenge_for_domain(
    url: &str,
    pk: &[u8],
    request: &str,
) -> PasskeyResult<ResolveChallengeResponse> {
    let origin = parse_url(url)?;
    let deserialized = deserialize_passkey(pk)?;
    resolve_challenge(origin, &deserialized, request).await
}
