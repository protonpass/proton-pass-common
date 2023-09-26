use proton_pass_common::alias_prefix::AliasPrefixError;
use proton_pass_common::login::{Login, LoginError};

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_pass_common::library_version()
}

pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}

pub fn validate_alias_prefix(prefix: String) -> Result<(), AliasPrefixError> {
    proton_pass_common::alias_prefix::validate_alias_prefix(&prefix)
}

pub fn is_login_valid(login: Login) -> Result<(), LoginError> {
    proton_pass_common::login::validate_login(login)
}
