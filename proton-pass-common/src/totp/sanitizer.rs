use crate::totp::totp::{
    DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD, OTP_SCHEME, QUERY_ALGORITHM, QUERY_DIGITS, QUERY_ISSUER,
    QUERY_PERIOD, QUERY_SECRET, TOTP, TOTP_HOST,
};
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
pub fn uri_for_saving(original_uri: &str, edited_uri: &str) -> String {
    let (original_label, original_issuer) = match TOTP::from_uri(original_uri) {
        Ok(components) => (components.label, components.issuer),
        _ => (None, None),
    };

    let trimmed_uri = edited_uri.trim();

    let components = match TOTP::from_uri(trimmed_uri) {
        Ok(value) => value,
        _ => {
            // Invalid URI
            // => treat as secret, sanitize and add default params
            let sanitized_secret = trimmed_uri.replace(' ', "");
            TOTP {
                label: None,
                secret: sanitized_secret,
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
        }
    };

    let base_uri = format!("{}://{}/", OTP_SCHEME, TOTP_HOST);

    let mut uri = match Url::parse(&base_uri) {
        Ok(value) => value,
        _ => panic!(
            "Should be able to create Url struct with scheme {} and host {}",
            OTP_SCHEME, TOTP_HOST
        ),
    };

    // Add label path
    if let Some(edited_label) = components.label {
        uri.set_path(edited_label.as_str());
    } else if let Some(original_label) = original_label {
        uri.set_path(original_label.as_str());
    }

    // Set secret query
    uri.query_pairs_mut().append_pair(QUERY_SECRET, &components.secret);

    // Set issuer query
    if let Some(edited_issuer) = components.issuer {
        uri.query_pairs_mut().append_pair(QUERY_ISSUER, edited_issuer.as_str());
    } else if let Some(original_issuer) = original_issuer {
        uri.query_pairs_mut()
            .append_pair(QUERY_ISSUER, original_issuer.as_str());
    }

    // Set algorithm query
    let algorithm = match components.algorithm {
        Some(entered_algorithm) => entered_algorithm,
        _ => DEFAULT_ALGORITHM,
    };
    uri.query_pairs_mut().append_pair(QUERY_ALGORITHM, algorithm.value());

    // Set digits
    let digits = match components.digits {
        Some(entered_digits) => entered_digits,
        _ => DEFAULT_DIGITS,
    };
    uri.query_pairs_mut().append_pair(QUERY_DIGITS, &format!("{}", digits));

    // Set period
    let period = match components.period {
        Some(entered_period) => entered_period,
        _ => DEFAULT_PERIOD,
    };
    uri.query_pairs_mut().append_pair(QUERY_PERIOD, &format!("{}", period));

    uri.as_str().to_string()
}
