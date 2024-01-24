use coset::iana;
use passkey::{
    authenticator::{Authenticator, UserValidationMethod},
    client::Client,
    types::{ctap2::*, rand::random_vec, webauthn::*, Bytes, Passkey},
};
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

fn get_authenticator(pk: Option<ProtonPassKey>) -> Authenticator<Option<Passkey>, MyUserValidationMethod> {
    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};

    let store: Option<Passkey> = pk.map(Passkey::from);
    Authenticator::new(my_aaguid, store, user_validation_method)
}

async fn generate_passkey(
    origin: Url,
    user_entity: PublicKeyCredentialUserEntity,
    parameters_from_rp: PublicKeyCredentialParameters,
    challenge_bytes_from_rp: Bytes,
) -> PasskeyResult<CreatePassKeyResponse> {
    let authenticator = get_authenticator(None);
    let mut my_client = Client::new(authenticator);

    let domain = if let Some(d) = origin.domain() {
        d.to_string()
    } else {
        return Err(PasskeyError::InvalidUri("Does not contain a domain".to_string()));
    };

    let request = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: None, // Leaving the ID as None means use the effective domain
                name: domain,
            },
            user: user_entity,
            challenge: challenge_bytes_from_rp,
            pub_key_cred_params: vec![parameters_from_rp],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

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

pub async fn generate_passkey_for_domain(
    url: &str,
    display_name: &str,
    challenge_bytes: Vec<u8>,
) -> PasskeyResult<CreatePassKeyResponse> {
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;
    let user_entity = PublicKeyCredentialUserEntity {
        id: random_vec(32).into(),
        display_name: display_name.to_string(),
        name: display_name.to_string(),
    };
    let parameters_from_rp = PublicKeyCredentialParameters {
        ty: PublicKeyCredentialType::PublicKey,
        alg: iana::Algorithm::ES256,
    };
    let challenge_from_rp = Bytes::from(challenge_bytes);
    generate_passkey(origin, user_entity, parameters_from_rp, challenge_from_rp).await
}

async fn resolve_challenge(
    origin: Url,
    pk: &ProtonPassKey,
    challenge_bytes: Bytes,
) -> PasskeyResult<AuthenticatedPublicKeyCredential> {
    let domain = if let Some(d) = origin.domain() {
        d.to_string()
    } else {
        return Err(PasskeyError::InvalidUri("Does not contain a domain".to_string()));
    };

    let credential_request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: challenge_bytes,
            timeout: None,
            rp_id: Some(domain),
            allow_credentials: None,
            user_verification: UserVerificationRequirement::default(),
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let authenticator = get_authenticator(Some(pk.clone()));
    let client = Client::new(authenticator);

    client
        .authenticate(&origin, credential_request, None)
        .await
        .map_err(|e| PasskeyError::ResolveChallengeError(format!("Error authenticating: {:?}", e)))
}

pub async fn resolve_challenge_for_domain(
    url: &str,
    pk: &[u8],
    challenge_bytes: Vec<u8>,
) -> PasskeyResult<AuthenticatedPublicKeyCredential> {
    let deserialized: ProtonPassKey = rmp_serde::from_slice(pk)
        .map_err(|e| PasskeyError::SerializationError(format!("Could not deserialize passkey: {:?}", e)))?;
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;
    let challenge_bytes = Bytes::from(challenge_bytes);
    resolve_challenge(origin, &deserialized, challenge_bytes).await
}
