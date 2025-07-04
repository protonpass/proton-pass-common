use crate::passkey::utils::transform_byte_array;
use crate::passkey::{PasskeyError, PasskeyResult};
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
    match serde_json::from_str(request) {
        Ok(request) => Ok(request),
        Err(_) => match sanitize_challenge(request) {
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
    }
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
