use crate::parser::ImportResult;
use crate::AuthenticatorError;

pub fn parse_proton_authenticator_export(input: &str) -> Result<ImportResult, AuthenticatorError> {
    crate::entry::import_authenticator_entries(input)
}
