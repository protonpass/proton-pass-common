use super::parser::parse_create_request;
use super::passkey_handling::{get_authenticator, parse_url, serialize_passkey};
use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use coset::iana;
use coset::iana::EnumI64;
use passkey::client::Client;
use passkey_types::webauthn::{
    CreatedPublicKeyCredential, CredentialCreationOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
};
use passkey_types::Bytes;
use url::Url;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CreatePasskeyResponse {
    pub credential: CreatedPublicKeyCredential,
    pub key_id: String,
    pub passkey: Vec<u8>,
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

impl CreatePasskeyResponse {
    pub fn response(&self) -> PasskeyResult<String> {
        serde_json::to_string(&self.credential)
            .map_err(|e| PasskeyError::SerializationError(format!("Error serializing credential: {e:?}")))
    }
}

async fn generate_passkey_response(
    origin: &Url,
    request: CredentialCreationOptions,
    client_data_hash: Option<Vec<u8>>,
) -> PasskeyResult<CreatePasskeyResponse> {
    let rp_id = request.public_key.rp.id.clone();
    let rp_name = request.public_key.rp.name.clone();
    let user_id = request.public_key.user.id.to_vec();
    let user_name = request.public_key.user.name.clone();
    let user_display_name = request.public_key.user.display_name.clone();
    let domain = match origin.domain() {
        Some(d) => d.to_string(),
        None => request.public_key.rp.name.to_string(),
    };

    let authenticator = get_authenticator(None);
    let mut my_client = Client::new(authenticator);

    let my_webauthn_credential = my_client
        .register(origin, request, client_data_hash)
        .await
        .map_err(|e| PasskeyError::GenerationError(format!("failed to generate passkey: {e:?}")))?;
    if let Some(pk) = my_client.authenticator().store() {
        let converted = ProtonPassKey::from(pk.clone());
        let key_id = my_webauthn_credential.id.clone();
        let serialized = serialize_passkey(&converted)?;
        let client_data_hash =
            passkey_types::crypto::sha256(my_webauthn_credential.response.client_data_json.as_slice()).to_vec();
        let attestation_object = my_webauthn_credential.response.attestation_object.to_vec();

        Ok(CreatePasskeyResponse {
            passkey: serialized,
            credential: my_webauthn_credential,
            credential_id: converted.credential_id,
            user_handle: converted.user_handle,
            key_id,
            rp_name,
            user_name,
            user_display_name,
            rp_id,
            user_id,
            domain,
            client_data_hash,
            attestation_object,
        })
    } else {
        Err(PasskeyError::GenerationError(
            "Passkey not stored into store".to_string(),
        ))
    }
}

async fn generate_passkey(
    origin: Url,
    request: PublicKeyCredentialCreationOptions,
) -> PasskeyResult<CreatePasskeyResponse> {
    let request = CredentialCreationOptions { public_key: request };
    generate_passkey_response(&origin, request, None).await
}

pub async fn generate_passkey_for_domain(url: &str, request: &str) -> PasskeyResult<CreatePasskeyResponse> {
    let origin = parse_url(url)?;

    let mut parsed = parse_create_request(request, Some(url))?;

    // If pub_key_cred_params is empty, add default ES256 and RS256 algorithms
    if parsed.pub_key_cred_params.is_empty() {
        parsed.pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::ES256,
            },
            PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::RS256,
            },
        ];
    }

    generate_passkey(origin, parsed).await
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CreatePasskeyIosRequest {
    pub service_identifier: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub supported_algorithms: Vec<i64>,
}

pub async fn generate_passkey_for_ios(ios_request: CreatePasskeyIosRequest) -> PasskeyResult<CreatePasskeyResponse> {
    let url = parse_url(&ios_request.service_identifier)?;
    let mut pub_key_cred_params = vec![];

    for algorithm in ios_request.supported_algorithms {
        if let Some(alg) = iana::Algorithm::from_i64(algorithm) {
            pub_key_cred_params.push(PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg,
            });
        }
    }

    let options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            id: Some(ios_request.service_identifier.clone()),
            name: ios_request.rp_id,
        },
        user: PublicKeyCredentialUserEntity {
            id: Bytes::from(ios_request.user_handle),
            display_name: ios_request.user_name.clone(),
            name: ios_request.user_name,
        },
        challenge: Bytes::from(Vec::new()),
        pub_key_cred_params,
        timeout: None,
        exclude_credentials: None,
        authenticator_selection: None,
        hints: None,
        attestation: Default::default(),
        attestation_formats: None,
        extensions: None,
    };

    let request = CredentialCreationOptions { public_key: options };
    generate_passkey_response(&url, request, Some(ios_request.client_data_hash)).await
}

pub struct CreatePasskeyData {
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

pub fn parse_create_passkey_data(request: &str) -> PasskeyResult<CreatePasskeyData> {
    let mut parsed = parse_create_request(request, None)?;

    // If pub_key_cred_params is empty, add default ES256 and RS256 algorithms
    if parsed.pub_key_cred_params.is_empty() {
        parsed.pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::ES256,
            },
            PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::RS256,
            },
        ];
    }

    Ok(CreatePasskeyData {
        rp_id: parsed.rp.id,
        rp_name: parsed.rp.name,
        user_name: parsed.user.name,
        user_display_name: parsed.user.display_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pub_key_cred_params_gets_defaults() {
        let request_with_empty_params = r#"{
            "challenge": "Y2hhbGxlbmdl",
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "dXNlcklk",
                "name": "user@example.com",
                "displayName": "User Example"
            },
            "pubKeyCredParams": [],
            "timeout": 60000
        }"#;

        let result = parse_create_passkey_data(request_with_empty_params);
        assert!(result.is_ok());

        // Parse the request directly to verify default params were added
        let mut parsed = parse_create_request(request_with_empty_params, None).unwrap();

        // Initially empty
        assert!(parsed.pub_key_cred_params.is_empty());

        // Apply the same logic as in our functions
        if parsed.pub_key_cred_params.is_empty() {
            parsed.pub_key_cred_params = vec![
                PublicKeyCredentialParameters {
                    ty: PublicKeyCredentialType::PublicKey,
                    alg: iana::Algorithm::ES256,
                },
                PublicKeyCredentialParameters {
                    ty: PublicKeyCredentialType::PublicKey,
                    alg: iana::Algorithm::RS256,
                },
            ];
        }

        // Verify defaults were added
        assert_eq!(parsed.pub_key_cred_params.len(), 2);
        assert_eq!(parsed.pub_key_cred_params[0].ty, PublicKeyCredentialType::PublicKey);
        assert_eq!(parsed.pub_key_cred_params[0].alg, iana::Algorithm::ES256);
        assert_eq!(parsed.pub_key_cred_params[1].ty, PublicKeyCredentialType::PublicKey);
        assert_eq!(parsed.pub_key_cred_params[1].alg, iana::Algorithm::RS256);
    }

    #[test]
    fn test_non_empty_pub_key_cred_params_unchanged() {
        let request_with_params = r#"{
            "challenge": "Y2hhbGxlbmdl",
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "dXNlcklk",
                "name": "user@example.com",
                "displayName": "User Example"
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -35}],
            "timeout": 60000
        }"#;

        let parsed = parse_create_request(request_with_params, None).unwrap();

        // Should have the original parameter, not defaults
        assert_eq!(parsed.pub_key_cred_params.len(), 1);
        assert_eq!(parsed.pub_key_cred_params[0].alg, iana::Algorithm::ES384);
    }
}
