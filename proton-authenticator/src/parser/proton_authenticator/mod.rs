use crate::parser::ImportResult;
use crate::ThirdPartyImportError;

pub fn parse_proton_authenticator_export(input: &str) -> Result<ImportResult, ThirdPartyImportError> {
    crate::entry::import_authenticator_entries(input).map_err(|_| ThirdPartyImportError::BadContent)
}
