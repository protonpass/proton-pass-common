use crate::AuthenticatorEntry;

pub mod aegis;
pub mod bitwarden;
pub mod ente;
pub mod google;
pub mod lastpass;
pub mod pass;
pub mod proton_authenticator;
pub mod twofas;

#[derive(Clone, Debug)]
pub struct ImportError {
    pub context: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ImportResult {
    pub entries: Vec<AuthenticatorEntry>,
    pub errors: Vec<ImportError>,
}

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum ThirdPartyImportError {
    BadContent,
    BadPassword,
    MissingPassword,
    DecryptionFailed,
}
