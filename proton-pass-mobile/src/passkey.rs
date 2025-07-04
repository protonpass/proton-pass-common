use proton_pass_common::passkey::{
    generate_passkey_for_domain, generate_passkey_for_ios, parse_create_passkey_data, resolve_challenge_for_android,
    resolve_challenge_for_ios,
};
pub use proton_pass_common::passkey::{
    AuthenticateWithPasskeyAndroidRequest as CommonAuthenticateWithPasskeyAndroidRequest,
    AuthenticateWithPasskeyIosRequest as CommonAuthenticateWithPasskeyIosRequest,
    AuthenticateWithPasskeyIosResponse as CommonAuthenticateWithPasskeyIosResponse,
    CreatePasskeyIosRequest as CommonCreatePasskeyIosRequest, PasskeyError as CommonPasskeyError,
};

pub struct AuthenticateWithPasskeyAndroidRequest {
    pub origin: String,
    pub request: String,
    pub passkey: Vec<u8>,
    pub client_data_hash: Option<Vec<u8>>,
}

impl From<AuthenticateWithPasskeyAndroidRequest> for CommonAuthenticateWithPasskeyAndroidRequest {
    fn from(other: AuthenticateWithPasskeyAndroidRequest) -> Self {
        Self {
            origin: other.origin,
            request: other.request,
            passkey: other.passkey,
            client_data_hash: other.client_data_hash,
        }
    }
}

pub struct AuthenticateWithPasskeyIosRequest {
    pub service_identifier: String,
    pub passkey: Vec<u8>,
    pub client_data_hash: Vec<u8>,
}

impl From<AuthenticateWithPasskeyIosRequest> for CommonAuthenticateWithPasskeyIosRequest {
    fn from(other: AuthenticateWithPasskeyIosRequest) -> Self {
        Self {
            service_identifier: other.service_identifier,
            passkey: other.passkey,
            client_data_hash: other.client_data_hash,
        }
    }
}

pub struct AuthenticateWithPasskeyIosResponse {
    pub user_handle: Vec<u8>,
    pub relying_party: String,
    pub signature: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub credential_id: Vec<u8>,
}

impl From<CommonAuthenticateWithPasskeyIosResponse> for AuthenticateWithPasskeyIosResponse {
    fn from(other: CommonAuthenticateWithPasskeyIosResponse) -> Self {
        Self {
            user_handle: other.user_handle,
            relying_party: other.relying_party,
            signature: other.signature,
            client_data_hash: other.client_data_hash,
            authenticator_data: other.authenticator_data,
            credential_id: other.credential_id,
        }
    }
}

pub struct CreatePasskeyIosRequest {
    pub service_identifier: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub supported_algorithms: Vec<i64>,
}

impl From<CreatePasskeyIosRequest> for CommonCreatePasskeyIosRequest {
    fn from(other: CreatePasskeyIosRequest) -> Self {
        Self {
            service_identifier: other.service_identifier,
            rp_id: other.rp_id,
            user_name: other.user_name,
            user_handle: other.user_handle,
            client_data_hash: other.client_data_hash,
            supported_algorithms: other.supported_algorithms,
        }
    }
}

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum PasskeyError {
    InvalidUri(String),
    RuntimeError(String),
    GenerationError(String),
    ResolveChallengeError(String),
    SerializationError(String),
}

impl From<CommonPasskeyError> for PasskeyError {
    fn from(e: CommonPasskeyError) -> Self {
        match e {
            CommonPasskeyError::InvalidUri(s) => Self::InvalidUri(s),
            CommonPasskeyError::RuntimeError(s) => Self::RuntimeError(s),
            CommonPasskeyError::GenerationError(s) => Self::GenerationError(s),
            CommonPasskeyError::ResolveChallengeError(s) => Self::ResolveChallengeError(s),
            CommonPasskeyError::SerializationError(s) => Self::SerializationError(s),
        }
    }
}

type PasskeyResult<T> = Result<T, PasskeyError>;

pub struct CreatePasskeyResponse {
    pub response: String,
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
}

pub struct CreatePasskeyIosResponse {
    pub key_id: String,
    pub passkey: Vec<u8>,
    pub domain: String,
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub attestation_object: Vec<u8>,
}

pub struct CreatePasskeyData {
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

pub struct PasskeyManager {
    rt: tokio::runtime::Runtime,
}

impl PasskeyManager {
    pub fn new() -> PasskeyResult<Self> {
        match tokio::runtime::Builder::new_current_thread().build() {
            Ok(rt) => Ok(Self { rt }),
            Err(e) => Err(PasskeyError::RuntimeError(format!("Error creating runtime: {e:?}"))),
        }
    }

    pub fn generate_passkey(&self, url: String, request: String) -> PasskeyResult<CreatePasskeyResponse> {
        self.rt.handle().block_on(async move {
            match generate_passkey_for_domain(&url, &request).await {
                Ok(r) => match r.response() {
                    Ok(response) => Ok(CreatePasskeyResponse {
                        response,
                        key_id: r.key_id,
                        passkey: r.passkey,
                        domain: r.domain,
                        rp_id: r.rp_id,
                        rp_name: r.rp_name,
                        user_name: r.user_name,
                        user_display_name: r.user_display_name,
                        user_id: r.user_id,
                        credential_id: r.credential_id,
                        user_handle: r.user_handle,
                    }),
                    Err(e) => {
                        println!("Error in generate_passkey: {e:?}");
                        Err(PasskeyError::from(e))
                    }
                },
                Err(e) => {
                    println!("Error in generate_passkey: {e:?}");
                    Err(PasskeyError::from(e))
                }
            }
        })
    }

    pub fn generate_ios_passkey(&self, request: CreatePasskeyIosRequest) -> PasskeyResult<CreatePasskeyIosResponse> {
        self.rt.handle().block_on(async move {
            match generate_passkey_for_ios(CommonCreatePasskeyIosRequest::from(request)).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    println!("Error in generate_passkey_for_ios: {e:?}");
                    Err(PasskeyError::from(e))
                }
            }
            .map(|r| CreatePasskeyIosResponse {
                key_id: r.key_id,
                passkey: r.passkey,
                domain: r.domain,
                rp_id: r.rp_id,
                rp_name: r.rp_name,
                user_name: r.user_name,
                user_display_name: r.user_display_name,
                user_id: r.user_id,
                credential_id: r.credential_id,
                client_data_hash: r.client_data_hash,
                user_handle: r.user_handle,
                attestation_object: r.attestation_object,
            })
        })
    }

    pub fn resolve_challenge_for_android(
        &self,
        request: AuthenticateWithPasskeyAndroidRequest,
    ) -> PasskeyResult<String> {
        self.rt.handle().block_on(async move {
            match resolve_challenge_for_android(CommonAuthenticateWithPasskeyAndroidRequest::from(request)).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    println!("Error in resolve_challenge_for_android: {e:?}");
                    Err(PasskeyError::from(e))
                }
            }
        })
    }

    pub fn resolve_challenge_for_ios(
        &self,
        request: AuthenticateWithPasskeyIosRequest,
    ) -> PasskeyResult<AuthenticateWithPasskeyIosResponse> {
        self.rt.handle().block_on(async move {
            match resolve_challenge_for_ios(CommonAuthenticateWithPasskeyIosRequest::from(request)).await {
                Ok(r) => Ok(AuthenticateWithPasskeyIosResponse::from(r)),
                Err(e) => {
                    println!("Error in generate_passkey_for_ios: {e:?}");
                    Err(PasskeyError::from(e))
                }
            }
        })
    }

    pub fn parse_create_request(&self, request: String) -> PasskeyResult<CreatePasskeyData> {
        match parse_create_passkey_data(&request) {
            Ok(d) => Ok(CreatePasskeyData {
                rp_id: d.rp_id,
                rp_name: d.rp_name,
                user_name: d.user_name,
                user_display_name: d.user_display_name,
            }),
            Err(e) => {
                println!("Error in parse_create_passkey_data: {e:?}");
                Err(PasskeyError::from(e))
            }
        }
    }
}
