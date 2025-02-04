use crate::{AuthenticatorEntryModel, AuthenticatorError};
use proton_authenticator::ThirdPartyImportError;

pub struct AuthenticatorImportError {
    pub context: String,
    pub message: String,
}

impl From<proton_authenticator::ImportError> for AuthenticatorImportError {
    fn from(err: proton_authenticator::ImportError) -> Self {
        Self {
            context: err.context,
            message: err.message,
        }
    }
}

impl From<proton_authenticator::ThirdPartyImportError> for AuthenticatorError {
    fn from(err: proton_authenticator::ThirdPartyImportError) -> Self {
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

    pub fn import_from_aegis_json(
        &self,
        contents: String,
        password: Option<String>,
    ) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_aegis_json(&contents, password).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_aegis_txt(&self, contents: String) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_aegis_txt(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_bitwarden_json(
        &self,
        contents: String,
    ) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_bitwarden_json(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_bitwarden_csv(&self, contents: String) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_bitwarden_csv(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_ente_txt(&self, contents: String) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_ente_txt(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_google_qr(&self, contents: String) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res =
            proton_authenticator::parse_google_authenticator_totp(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_lastpass_json(&self, contents: String) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_lastpass_json(&contents).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_proton_authenticator(
        &self,
        contents: String,
    ) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_proton_authenticator_export(&contents)?;
        Ok(AuthenticatorImportResult::from(res))
    }

    pub fn import_from_2fas(
        &self,
        contents: String,
        password: Option<String>,
    ) -> Result<AuthenticatorImportResult, AuthenticatorError> {
        let res = proton_authenticator::parse_2fas_file(&contents, password).map_err(ThirdPartyImportError::from)?;
        Ok(AuthenticatorImportResult::from(res))
    }
}
