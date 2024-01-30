use passkey::{
    authenticator::{Authenticator, UserValidationMethod},
    client::Client,
};
use passkey_types::{ctap2::Aaguid, webauthn::*, Passkey};
use url::Url;

use super::{PasskeyError, PasskeyResult, ProtonPassKey};

struct MyUserValidationMethod {}

#[async_trait::async_trait]
impl UserValidationMethod for MyUserValidationMethod {
    async fn check_user_verification(&self) -> bool {
        true
    }

    async fn check_user_presence(&self) -> bool {
        true
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CreatePassKeyResponse {
    pub passkey: Vec<u8>,
    pub credential: CreatedPublicKeyCredential,
}

impl CreatePassKeyResponse {
    pub fn response(&self) -> PasskeyResult<String> {
        serde_json::to_string(&self.credential)
            .map_err(|e| PasskeyError::SerializationError(format!("Error serializing credential: {:?}", e)))
    }
}

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

fn get_authenticator(pk: Option<ProtonPassKey>) -> Authenticator<Option<Passkey>, MyUserValidationMethod> {
    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};

    let store: Option<Passkey> = pk.map(Passkey::from);
    Authenticator::new(my_aaguid, store, user_validation_method)
}

async fn generate_passkey(
    origin: Url,
    request: PublicKeyCredentialCreationOptions,
) -> PasskeyResult<CreatePassKeyResponse> {
    let authenticator = get_authenticator(None);
    let mut my_client = Client::new(authenticator);

    let request = CredentialCreationOptions { public_key: request };

    // Now create the credential.
    let my_webauthn_credential = my_client
        .register(&origin, request, None)
        .await
        .map_err(|e| PasskeyError::GenerationError(format!("failed to generate passkey: {:?}", e)))?;
    if let Some(pk) = my_client.authenticator().store() {
        let converted = ProtonPassKey::from(pk.clone());
        let serialized = rmp_serde::to_vec_named(&converted)
            .map_err(|e| PasskeyError::SerializationError(format!("Error serializing passkey: {:?}", e)))?;

        Ok(CreatePassKeyResponse {
            passkey: serialized,
            credential: my_webauthn_credential,
        })
    } else {
        Err(PasskeyError::GenerationError(
            "Passkey not stored into store".to_string(),
        ))
    }
}

pub async fn generate_passkey_for_domain(url: &str, request: &str) -> PasskeyResult<CreatePassKeyResponse> {
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;

    let parsed: PublicKeyCredentialCreationOptions = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;
    generate_passkey(origin, parsed).await
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
    let deserialized: ProtonPassKey = rmp_serde::from_slice(pk)
        .map_err(|e| PasskeyError::SerializationError(format!("Could not deserialize passkey: {:?}", e)))?;
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;
    resolve_challenge(origin, &deserialized, request).await
}
