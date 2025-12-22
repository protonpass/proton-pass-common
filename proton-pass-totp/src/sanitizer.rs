use crate::error::TOTPError;
use crate::totp::TOTP;
use url::Url;

/// Converts a TOTP URI or secret to a human-readable format for display purposes.
///
/// * Valid TOTP URI with default parameters => returns just the secret
/// * Valid TOTP URI with custom parameters => returns the full URI
/// * Invalid input => returns the input unchanged
pub fn human_readable_otp(uri_or_secret: &str) -> String {
    let components;
    if let Ok(value) = TOTP::from_uri(uri_or_secret) {
        components = value
    } else {
        return uri_or_secret.to_string();
    }

    if components.has_default_params() {
        return components.secret;
    }

    uri_or_secret.to_string()
}

/// Sanitizes and normalizes TOTP URI or secret input for consistent storage.
///
/// * Empty input => returns empty string
/// * Invalid URI => treats as secret, sanitizes and creates URI with default parameters
/// * Valid TOTP URI => returns normalized URI with default parameters filled in
/// * Valid non-TOTP URL => returns error
pub fn sanitize_otp(uri_or_secret: &str, label: Option<String>, issuer: Option<String>) -> Result<String, TOTPError> {
    let uri_or_secret = uri_or_secret.trim();

    if uri_or_secret.is_empty() {
        return Ok("".to_string());
    }

    let parsed_otp: Option<TOTP> = match TOTP::from_uri(uri_or_secret) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            match error {
                TOTPError::EmptySecret => Ok(None),
                _ => {
                    if Url::parse(uri_or_secret).is_ok() {
                        Err(TOTPError::NotTotpUri)
                    } else {
                        // Invalid URI => treat as secret, sanitize and add default params
                        let sanitized_secret = sanitize_secret(uri_or_secret);
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

    if let Some(parsed_otp) = parsed_otp {
        Ok(parsed_otp.to_uri(label, issuer))
    } else {
        Ok("".to_string())
    }
}

/// Sanitizes a raw secret string by removing spaces, dashes, underscores,
/// trailing '=' padding, and converts to uppercase.
pub fn sanitize_secret(secret: &str) -> String {
    secret
        .replace([' ', '-', '_'], "")
        .trim_end_matches('=')
        .to_ascii_uppercase()
}
