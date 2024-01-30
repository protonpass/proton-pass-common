use super::passkey_handling::{deserialize_passkey, get_authenticator};
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
    let client = Client::new(authenticator);

    let res = client
        .authenticate(&origin, credential_request, None)
        .await
        .map_err(|e| PasskeyError::ResolveChallengeError(format!("Error authenticating: {:?}", e)))?;

    Ok(ResolveChallengeResponse { response: res })
}

pub async fn resolve_challenge_for_domain(
    url: &str,
    pk: &[u8],
    request: &str,
) -> PasskeyResult<ResolveChallengeResponse> {
    let deserialized = deserialize_passkey(pk)?;
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;
    resolve_challenge(origin, &deserialized, request).await
}
