use crate::parser::ImportResult;
use crate::{AuthenticatorError, ThirdPartyImportError};

pub fn parse_proton_authenticator_export(input: &str) -> Result<ImportResult, ThirdPartyImportError> {
    crate::entry::import_authenticator_entries(input).map_err(|e| match e {
        AuthenticatorError::Import(e) => e,
        _ => {
            warn!("Error importing from ProtonAuthenticator export: {e:?}");
            ThirdPartyImportError::BadContent
        }
    })
}

pub fn parse_proton_authenticator_export_with_password(
    input: &str,
    password: &str,
) -> Result<ImportResult, ThirdPartyImportError> {
    crate::entry::import_entries_with_password(input, password).map_err(|e| match e {
        AuthenticatorError::Import(e) => e,
        _ => {
            warn!("Error importing from ProtonAuthenticator export: {e:?}");
            ThirdPartyImportError::BadContent
        }
    })
}
