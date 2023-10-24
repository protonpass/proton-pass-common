pub use proton_pass_common::totp::error::TOTPError;
use proton_pass_common::totp::sanitizer::{uri_for_editing, uri_for_saving};
pub use proton_pass_common::totp::totp::TOTP;

pub struct TotpUriParser;
pub struct TotpUriSanitizer;

pub type TOTPAlgorithm = proton_pass_common::totp::algorithm::Algorithm;

impl TotpUriParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, uri_string: String) -> Result<TOTP, TOTPError> {
        TOTP::from_uri(uri_string.as_str())
    }
}

impl TotpUriSanitizer {
    pub fn new() -> Self {
        Self
    }

    pub fn uri_for_editing(&self, original_uri: String) -> String {
        uri_for_editing(original_uri.as_str())
    }

    pub fn uri_for_saving(&self, original_uri: String, edited_uri: String) -> Result<String, TOTPError> {
        uri_for_saving(original_uri.as_str(), edited_uri.as_str())
    }
}

pub struct TotpTokenGenerator;

impl TotpTokenGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_current_token(&self, totp: TOTP, current_time: u64) -> Result<String, TOTPError> {
        totp.generate_current_token(current_time)
    }

    pub fn generate_current_token_from_secret(&self, secret: String, current_time: u64) -> Result<String, TOTPError> {
        let totp = TOTP {
            label: None,
            secret,
            issuer: None,
            algorithm: None,
            digits: None,
            period: None,
        };
        totp.generate_current_token(current_time)
    }
}
