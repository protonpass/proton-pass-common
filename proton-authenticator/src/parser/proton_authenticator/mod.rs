use crate::{AuthenticatorEntry, AuthenticatorError};

pub fn parse_proton_authenticator_export(
    input: &str,
    fail_on_error: bool,
) -> Result<Vec<AuthenticatorEntry>, AuthenticatorError> {
    crate::entry::import_authenticator_entries(input, fail_on_error)
}
