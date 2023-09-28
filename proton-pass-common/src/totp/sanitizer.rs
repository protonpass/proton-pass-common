use crate::totp::components::{
    TOTPComponents, DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD, OTP_SCHEME, QUERY_ALGORITHM, QUERY_DIGITS,
    QUERY_PERIOD, QUERY_SECRET, TOTP_HOST,
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
    let original_uri_string = original_uri.to_string();
    let components;
    if let Ok(value) = TOTPComponents::from_uri(original_uri) {
        components = value
    } else {
        return original_uri_string;
    }

    if components.has_default_params() {
        return components.secret;
    }

    original_uri_string
}

/// Sanitize the user input URI before saving.
///
/// - Invalid
///   => Return as-is
///
/// - Valid with no params
///   => Add default params
///
/// - Valid with default params
///   => Return as-is
///
/// - Valid with custom params
///   => Return as-is
pub fn uri_for_saving(edited_uri: &str) -> String {
    let edited_uri_string = edited_uri.to_string();

    let components;
    if let Ok(value) = TOTPComponents::from_uri(edited_uri) {
        components = value
    } else {
        // Invalid URI => return as-is
        return edited_uri_string;
    }

    let base_uri = format!("{}://{}/", OTP_SCHEME, TOTP_HOST);
    let mut uri;
    if let Ok(value) = Url::parse(&base_uri) {
        uri = value
    } else {
        return edited_uri_string;
    }

    // Add label path
    if let Some(label) = components.label {
        uri.set_path(label.as_str());
    }

    // Set secret query
    uri.query_pairs_mut().append_pair(QUERY_SECRET, &components.secret);

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
