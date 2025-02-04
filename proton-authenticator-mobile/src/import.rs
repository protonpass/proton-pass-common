use crate::{AuthenticatorEntryModel, AuthenticatorError};
use proton_authenticator::ThirdPartyImportError;

type ImportResult = Result<AuthenticatorImportResult, AuthenticatorImportException>;

pub struct AuthenticatorImportError {
    pub context: String,
    pub message: String,
}

#[derive(Debug, proton_pass_derive::Error)]
pub enum AuthenticatorImportException {
    BadContent,
    BadPassword,
    MissingPassword,
    DecryptionFailed,
}

impl From<ThirdPartyImportError> for AuthenticatorImportException {
    fn from(err: ThirdPartyImportError) -> Self {
        match err {
            ThirdPartyImportError::BadContent => Self::BadContent,
            ThirdPartyImportError::BadPassword => Self::BadPassword,
            ThirdPartyImportError::MissingPassword => Self::MissingPassword,
            ThirdPartyImportError::DecryptionFailed => Self::DecryptionFailed,
        }
    }
}

impl From<proton_authenticator::ImportError> for AuthenticatorImportError {
    fn from(err: proton_authenticator::ImportError) -> Self {
        Self {
            context: err.context,
            message: err.message,
        }
    }
}

impl From<ThirdPartyImportError> for AuthenticatorError {
    fn from(err: ThirdPartyImportError) -> Self {
        Self {
            e: proton_authenticator::AuthenticatorError::Import(err),
        }
    }
}

pub struct AuthenticatorImportResult {
    pub entries: Vec<AuthenticatorEntryModel>,
    pub errors: Vec<AuthenticatorImportError>,
}

impl From<proton_authenticator::ImportResult> for AuthenticatorImportResult {
    fn from(result: proton_authenticator::ImportResult) -> Self {
        Self {
            entries: result.entries.into_iter().map(AuthenticatorEntryModel::from).collect(),
            errors: result.errors.into_iter().map(AuthenticatorImportError::from).collect(),
        }
    }
}

pub struct AuthenticatorImporter;

impl AuthenticatorImporter {
    pub fn new() -> AuthenticatorImporter {
        Self
    }

    pub fn import_from_aegis_json(&self, contents: String, password: Option<String>) -> ImportResult {
        let res = proton_authenticator::parse_aegis_json(&contents, password).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_aegis_txt(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_aegis_txt(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_bitwarden_json(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_bitwarden_json(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_bitwarden_csv(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_bitwarden_csv(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_ente_txt(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_ente_txt(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_google_qr(&self, contents: String) -> ImportResult {
        let res =
            proton_authenticator::parse_google_authenticator_totp(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_lastpass_json(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_lastpass_json(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_proton_authenticator(&self, contents: String) -> ImportResult {
        let res = proton_authenticator::parse_proton_authenticator_export(&contents)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_2fas(&self, contents: String, password: Option<String>) -> ImportResult {
        let res = proton_authenticator::parse_2fas_file(&contents, password).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }
}
