use super::passkey_handling::{get_authenticator, serialize_passkey};
use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey::client::Client;
use passkey_types::webauthn::{
    CreatedPublicKeyCredential, CredentialCreationOptions, PublicKeyCredentialCreationOptions,
};
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
    let origin = Url::parse(url).map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?;

    let parsed: PublicKeyCredentialCreationOptions = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;
    generate_passkey(origin, parsed).await
}
