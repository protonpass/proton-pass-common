use crate::error::TOTPError;
use crate::totp::TOTP;
use url::Url;

/// Take an original URI string and convert it to a string for user to edit.
///
/// - Original URI is invalid or has custom params
///   => Return the URI as-is
///
/// - Original URI has default params (missing optional params or params with default values)
///   => Return only the secret
pub fn uri_for_editing(original_uri: &str) -> String {
    let components;
    if let Ok(value) = TOTP::from_uri(original_uri) {
        components = value
    } else {
        return original_uri.to_string();
    }

    if components.has_default_params() {
        return components.secret;
    }

    original_uri.to_string()
}

/// Sanitize the user input URI before saving.
///
/// - Invalid
///   => Treat as secret, sanitize and add default params
///
/// - Valid with no params
///   => Add default params
///
/// - Valid with default params
///   => Return as-is
///
/// - Valid with custom params
///   => Return as-is
pub fn uri_for_saving(original_uri: &str, edited_uri: &str) -> Result<String, TOTPError> {
    let trimmed_edited_uri = edited_uri.trim();

    if trimmed_edited_uri.is_empty() {
        return Ok("".to_string());
    }

    let (original_label, original_issuer) = match TOTP::from_uri(original_uri) {
        Ok(original_totp) => (original_totp.label, original_totp.issuer),
        _ => (None, None),
    };

    let edited_totp: Option<TOTP> = match TOTP::from_uri(trimmed_edited_uri) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            match error {
                TOTPError::EmptySecret => Ok(None),
                _ => {
                    if Url::parse(trimmed_edited_uri).is_ok() {
                        Err(TOTPError::NotTotpUri)
                    } else {
                        // Invalid URI
                        // => treat as secret, sanitize and add default params
                        let sanitized_secret = sanitize_secret(trimmed_edited_uri);
                        Ok(Some(TOTP {
                            label: None,
                            secret: sanitized_secret,
                            issuer: None,
                            algorithm: None,
                            digits: None,
                            period: None,
                        }))
                    }
                }
            }
        }
    }?;

    if let Some(edited_totp) = edited_totp {
        Ok(edited_totp.to_uri(original_label, original_issuer))
    } else {
        Ok("".to_string())
    }
}

pub fn sanitize_secret(secret: &str) -> String {
    secret.replace([' ', '-', '_'], "")
}
