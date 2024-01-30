use proton_pass_common::passkey::{
    generate_passkey_for_domain, resolve_challenge_for_domain, CreatePassKeyResponse, PasskeyError, PasskeyResult,
    ResolveChallengeResponse,
};

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

    pub fn generate_passkey(&self, url: String, request: String) -> PasskeyResult<CreatePassKeyResponse> {
        self.rt
            .handle()
            .block_on(async move { generate_passkey_for_domain(&url, &request).await })
    }

    pub fn resolve_challenge(
        &self,
        url: String,
        passkey: Vec<u8>,
        request: String,
    ) -> PasskeyResult<ResolveChallengeResponse> {
        self.rt
            .handle()
            .block_on(async move { resolve_challenge_for_domain(&url, &passkey, &request).await })
    }
}
