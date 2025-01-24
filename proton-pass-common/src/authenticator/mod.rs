use crate::totp::totp::TOTP;

pub mod parser;

#[derive(Clone, Debug)]
pub struct AuthenticatorEntry {
    pub totp: TOTP,
}

pub use parser::google::parse_google_authenticator_totp;
