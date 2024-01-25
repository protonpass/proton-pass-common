pub use proton_pass_common::passkey::PasskeyError;
use proton_pass_common::passkey::{generate_passkey_for_domain, resolve_challenge_for_domain, PasskeyResult};

pub struct CreatePasskeyResponse {
    pub passkey: Vec<u8>,
    pub response: String,
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
                        passkey: r.passkey,
                        response,
                    }),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        })
    }

    pub fn resolve_challenge(&self, url: String, passkey: Vec<u8>, challenge_bytes: Vec<u8>) -> PasskeyResult<()> {
        self.rt.handle().block_on(async move {
            resolve_challenge_for_domain(&url, &passkey, challenge_bytes)
                .await
                .map(|_| ())
        })
    }
}
