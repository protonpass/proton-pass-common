use crate::totp::algorithm::Algorithm;
use crate::totp::algorithm::Algorithm::SHA1;
use crate::totp::components::TOTPComponents;

pub const DEFAULT_ALGORITHM: Algorithm = SHA1;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u16 = 30;

/// Take an original URI string and convert it to a string for user to edit.
///
/// - Original URI is invalid or has custom params
///   => Return the URI as-is
///
/// - Original URI has default params (missing optional params or params with default values)
///   => Return only the secret
pub fn uri_for_editing(original_uri: &str) -> String {
    let original_uri_string = original_uri.to_string();
    let components;
    if let Ok(value) = TOTPComponents::from_uri(original_uri) {
        components = value
    } else {
        return original_uri_string;
    }

    if components.has_default_params() {
        return original_uri_string;
    }

    components.secret
}

impl TOTPComponents {
    fn has_default_params(&self) -> bool {
        let default_algorithm = match &self.algorithm {
            Some(value) => *value == DEFAULT_ALGORITHM,
            _ => true,
        };

        let default_digits = match &self.digits {
            Some(value) => *value == DEFAULT_DIGITS,
            _ => true,
        };

        let default_period = match &self.period {
            Some(value) => *value == DEFAULT_PERIOD,
            _ => true,
        };

        default_algorithm && default_digits && default_period
    }
}