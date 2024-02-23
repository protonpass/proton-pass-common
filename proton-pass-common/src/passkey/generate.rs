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
pub struct CreatePassKeyResponse {
    pub credential: CreatedPublicKeyCredential,
    pub key_id: String,
    pub passkey: Vec<u8>,
    pub domain: String,
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
}

impl CreatePassKeyResponse {
    pub fn response(&self) -> PasskeyResult<String> {
        serde_json::to_string(&self.credential)
            .map_err(|e| PasskeyError::SerializationError(format!("Error serializing credential: {:?}", e)))
    }
}

fn vec_to_hex(vec: &[u8]) -> String {
    let mut output = String::new();
    for byte in vec {
        output.push_str(&format!("{:02X}", byte))
    }
    output
}

async fn generate_passkey(
    origin: Url,
    request: PublicKeyCredentialCreationOptions,
) -> PasskeyResult<CreatePassKeyResponse> {
    let authenticator = get_authenticator(None);
    let mut my_client = Client::new(authenticator);

    let request = CredentialCreationOptions { public_key: request };

    let domain = match origin.domain() {
        Some(d) => d.to_string(),
        None => request.public_key.rp.name.to_string(),
    };
    let rp_id = request.public_key.rp.id.clone();
    let rp_name = request.public_key.rp.name.clone();
    let user_id = request.public_key.user.id.to_vec();
    let user_name = request.public_key.user.name.clone();
    let user_display_name = request.public_key.user.display_name.clone();

    // Now create the credential.
    let my_webauthn_credential = my_client
        .register(&origin, request, None)
        .await
        .map_err(|e| PasskeyError::GenerationError(format!("failed to generate passkey: {:?}", e)))?;
    if let Some(pk) = my_client.authenticator().store() {
        let converted = ProtonPassKey::from(pk.clone());
        let key_id = vec_to_hex(&converted.credential_id);
        let serialized = serialize_passkey(&converted)?;

        Ok(CreatePassKeyResponse {
            passkey: serialized,
            credential: my_webauthn_credential,
            key_id,
            rp_name,
            user_name,
            user_display_name,
            rp_id,
            user_id,
            domain,
        })
    } else {
        Err(PasskeyError::GenerationError(
            "Passkey not stored into store".to_string(),
        ))
    }
}

pub async fn generate_passkey_for_domain(url: &str, request: &str) -> PasskeyResult<CreatePassKeyResponse> {
    let origin = parse_url(url)?;

    let parsed: PublicKeyCredentialCreationOptions = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CreatePasskeyIosResponseData {
    pub relying_party: String,
    pub client_data_hash: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CreatePasskeyIosResponse {
    pub key_id: String,
    pub passkey: Vec<u8>,
    pub domain: String,
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
    pub ios_data: CreatePasskeyIosResponseData,
}

pub async fn generate_passkey_for_ios(ios_request: CreatePasskeyIosRequest) -> PasskeyResult<CreatePasskeyIosResponse> {
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

    let authenticator = get_authenticator(None);
    let mut my_client = Client::new(authenticator);

    let request = CredentialCreationOptions { public_key: options };

    let domain = match url.domain() {
        Some(d) => d.to_string(),
        None => request.public_key.rp.name.to_string(),
    };
    let rp_id = request.public_key.rp.id.clone();
    let rp_name = request.public_key.rp.name.clone();
    let user_id = request.public_key.user.id.to_vec();
    let user_name = request.public_key.user.name.clone();
    let user_display_name = request.public_key.user.display_name.clone();

    // Now create the credential.
    let my_webauthn_credential = my_client
        .register(&url, request, Some(ios_request.client_data_hash))
        .await
        .map_err(|e| PasskeyError::GenerationError(format!("failed to generate passkey: {:?}", e)))?;
    if let Some(pk) = my_client.authenticator().store() {
        let converted = ProtonPassKey::from(pk.clone());
        let key_id = vec_to_hex(&converted.credential_id);
        let serialized = serialize_passkey(&converted)?;

        let ios_data = CreatePasskeyIosResponseData {
            relying_party: rp_name.clone(),
            credential_id: my_webauthn_credential.raw_id.to_vec(),
            attestation_object: my_webauthn_credential.response.attestation_object.to_vec(),
            client_data_hash: passkey_types::crypto::sha256(
                my_webauthn_credential.response.client_data_json.as_slice(),
            )
            .to_vec(),
        };
        Ok(CreatePasskeyIosResponse {
            passkey: serialized,
            key_id,
            rp_name,
            user_name,
            user_display_name,
            rp_id,
            user_id,
            domain,
            ios_data,
        })
    } else {
        Err(PasskeyError::GenerationError(
            "Passkey not stored into store".to_string(),
        ))
    }
}

pub struct CreatePasskeyData {
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

pub fn parse_create_passkey_data(request: &str) -> PasskeyResult<CreatePasskeyData> {
    let parsed: PublicKeyCredentialCreationOptions = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;

    Ok(CreatePasskeyData {
        rp_id: parsed.rp.id,
        rp_name: parsed.rp.name,
        user_name: parsed.user.name,
        user_display_name: parsed.user.display_name,
    })
}
