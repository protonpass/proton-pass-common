use crate::passkey::utils::transform_byte_array;
use crate::passkey::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey_types::webauthn::PublicKeyCredentialRequestOptions;
use serde_json::Value;

fn sanitize_challenge(request: &str) -> PasskeyResult<String> {
    let mut parsed: Value = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {e:?}")))?;

    if let Some(obj) = parsed.as_object_mut() {
        if let Some(challenge) = obj.get("challenge") {
            let transformed = transform_byte_array(challenge.clone());
            obj.insert("challenge".to_string(), transformed);
            return Ok(serde_json::to_string(&parsed).unwrap_or(request.to_string()));
        }
    }

    Ok(request.to_string())
}

pub fn parse_authenticate_request(request: &str) -> PasskeyResult<PublicKeyCredentialRequestOptions> {
    parse_authenticate_request_with_passkey(request, None)
}

pub fn parse_authenticate_request_with_passkey(
    request: &str,
    passkey: Option<&ProtonPassKey>,
) -> PasskeyResult<PublicKeyCredentialRequestOptions> {
    let adapted = adapt_request_with_prf_to_passkey(request, passkey)?;
    let parsed = match serde_json::from_str(&adapted) {
        Ok(request) => Ok(request),
        Err(_) => match sanitize_challenge(&adapted) {
            Ok(sanitized) => match serde_json::from_str(&sanitized) {
                Ok(request) => Ok(request),
                Err(e) => Err(PasskeyError::SerializationError(format!(
                    "Error parsing request: {e:?}"
                ))),
            },
            Err(e) => Err(PasskeyError::SerializationError(format!(
                "Error parsing request: {e:?}"
            ))),
        },
    }?;

    Ok(parsed)
}

// In order to adapt to some authentication requests containing PRF while their creation requests
// didn't, if the authentication request contains PRF and the passkey doesn't support PRF, strip the
// PRF extension (if it matches the domains we know that have this issue)
fn adapt_request_with_prf_to_passkey(request: &str, passkey: Option<&ProtonPassKey>) -> PasskeyResult<String> {
    let passkey = match passkey {
        Some(p) => p,
        None => return Ok(request.to_string()),
    };

    // Check if the request contains the PRF extension
    if let Ok(mut value) = serde_json::from_str::<Value>(request) {
        // Check if the request is for one of the domains we know about
        let rp_id = value.get("rpId").and_then(|v| v.as_str()).unwrap_or_default();
        if should_perform_prf_sanitizing(rp_id) {
            if let Some(extensions) = value.get_mut("extensions") {
                if let Some(ext_obj) = extensions.as_object_mut() {
                    if ext_obj.contains_key("prf") && passkey.extensions.hmac_secret.is_none() {
                        // Request contains PRF and passkey doesn't have it. Strip it
                        ext_obj.remove("prf");

                        return Ok(serde_json::to_string(&value).unwrap_or(request.to_string()));
                    }
                }
            }
        }
    }

    Ok(request.to_string())
}

fn should_perform_prf_sanitizing(rp_id: &str) -> bool {
    rp_id.contains("google")
}

#[cfg(test)]
mod tests {
    use super::*;

    mod coinbase {
        use super::*;

        #[test]
        fn can_parse_coinbase_request() {
            let input = r#"
            {"rpId": "coinbase.com", "challenge": {"0": 53,"1": 17,"2": 82,"3": 110,"4": 183,"5": 25,"6": 190,"7": 231,"8": 180,"9": 65,"10": 216,"11": 45,"12": 67,"13": 110,"14": 44,"15": 82,"16": 238,"17": 235,"18": 78,"19": 42,"20": 209,"21": 148,"22": 144,"23": 98,"24": 175,"25": 50,"26": 192,"27": 171,"28": 113,"29": 209,"30": 146,"31": 149},"allowCredentials": [],"userVerification": "preferred"}
            "#;

            let res = parse_authenticate_request(input).expect("should be able to parse");
            let as_bytes = res.challenge.to_vec();
            assert_eq!(
                vec![
                    53, 17, 82, 110, 183, 25, 190, 231, 180, 65, 216, 45, 67, 110, 44, 82, 238, 235, 78, 42, 209, 148,
                    144, 98, 175, 50, 192, 171, 113, 209, 146, 149
                ],
                as_bytes
            );
        }
    }
}
