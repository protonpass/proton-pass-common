use proton_pass_common::passkey::{
    generate_passkey_for_domain, generate_passkey_for_ios, parse_create_passkey_data, resolve_challenge_for_android,
    resolve_challenge_for_ios, PasskeyResult,
};
pub use proton_pass_common::passkey::{
    AuthenticateWithPasskeyAndroidRequest, AuthenticateWithPasskeyIosRequest, AuthenticateWithPasskeyIosResponse,
    CreatePasskeyIosRequest, PasskeyError,
};

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
            Err(e) => Err(PasskeyError::RuntimeError(format!("Error creating runtime: {:?}", e))),
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
                        println!("Error in generate_passkey: {:?}", e);
                        Err(e)
                    }
                },
                Err(e) => {
                    println!("Error in generate_passkey: {:?}", e);
                    Err(e)
                }
            }
        })
    }

    pub fn generate_ios_passkey(&self, request: CreatePasskeyIosRequest) -> PasskeyResult<CreatePasskeyIosResponse> {
        self.rt.handle().block_on(async move {
            match generate_passkey_for_ios(request).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    println!("Error in generate_passkey_for_ios: {:?}", e);
                    Err(e)
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
            match resolve_challenge_for_android(request).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    println!("Error in resolve_challenge_for_android: {:?}", e);
                    Err(e)
                }
            }
        })
    }

    pub fn resolve_challenge_for_ios(
        &self,
        request: AuthenticateWithPasskeyIosRequest,
    ) -> PasskeyResult<AuthenticateWithPasskeyIosResponse> {
        self.rt.handle().block_on(async move {
            match resolve_challenge_for_ios(request).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    println!("Error in generate_passkey_for_ios: {:?}", e);
                    Err(e)
                }
            }
        })
    }

    pub fn parse_create_request(&self, request: String) -> PasskeyResult<CreatePasskeyData> {
        parse_create_passkey_data(&request).map(|d| CreatePasskeyData {
            rp_id: d.rp_id,
            rp_name: d.rp_name,
            user_name: d.user_name,
            user_display_name: d.user_display_name,
        })
    }
}
