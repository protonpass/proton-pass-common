use super::PasskeySanitizer;
use serde_json::Value;

/// Ebay has the following special cases:
/// 1. Sends the algorithm as a string instead of a number. We convert it to a number.
/// 2. Sends a -1 algorithm while is not defined in the spec. We remove it.
pub struct EbaySanitizer;

impl PasskeySanitizer for EbaySanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.map_or(false, |u| u.contains("ebay."));
        url_matches || request.contains("ebay.")
    }

    fn sanitize(&self, request: &str) -> String {
        let parsed: Value = match serde_json::from_str(request) {
            Ok(v) => v,
            Err(_) => return request.to_string(),
        };
        let obj = match parsed {
            Value::Object(o) => o,
            _ => return request.to_string(),
        };

        let pub_key_cred_params = match obj.get("pubKeyCredParams") {
            Some(Value::Array(arr)) => arr,
            _ => return request.to_string(),
        };

        if pub_key_cred_params.is_empty() {
            return request.to_string();
        }

        let mut new_params = Vec::new();
        for param in pub_key_cred_params {
            let p_obj = match param {
                Value::Object(m) => m,
                _ => continue,
            };

            let int_val = match p_obj.get("alg") {
                Some(Value::String(s)) => match s.parse::<i64>() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
                Some(Value::Number(v)) => match v.as_i64() {
                    Some(v) => v,
                    None => continue,
                },
                _ => continue,
            };

            // Invalid algorithm sent by Ebay
            if int_val == -1 {
                continue;
            }

            let mut new_param = p_obj.clone();
            new_param.insert("alg".to_string(), Value::from(int_val));
            new_params.push(Value::Object(new_param));
        }

        let mut editable = obj.clone();
        editable.insert("pubKeyCredParams".to_string(), Value::Array(new_params));
        serde_json::to_string(&Value::Object(editable)).unwrap_or(request.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_web_request() {
        let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},"challenge":"MHFHazVISkJNamZrVXlwaWYtUGQ3eFJRb3lvVEk1VFZZdEZXdHQ3VERRay5NVGN6TXpnek9ETXdNekF5T1EuY21saWJIY3pkV3h4Ym0wLmdCUENVM1BrZVNZLUZnWWhueXRQWkxVRkU4aG5UQVpkVjZrMDNFY1FYalU","excludeCredentials":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-36,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},{"alg":-39,"type":"public-key"},{"alg":-1,"type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0","name":"test@email.com"}}
        "#.trim();
        let expected = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},"challenge":"MHFHazVISkJNamZrVXlwaWYtUGQ3eFJRb3lvVEk1VFZZdEZXdHQ3VERRay5NVGN6TXpnek9ETXdNekF5T1EuY21saWJIY3pkV3h4Ym0wLmdCUENVM1BrZVNZLUZnWWhueXRQWkxVRkU4aG5UQVpkVjZrMDNFY1FYalU","excludeCredentials":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-36,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},{"alg":-39,"type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0","name":"test@email.com"}}
        "#.trim();

        let res = EbaySanitizer.sanitize(input);
        assert_eq!(expected, res);
    }

    #[test]
    fn sanitize_android_request() {
        let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required"},"challenge":"Y3loVFRSWTN5QmxYRzVuazRucVVlNF9udExmVnVmdTlSeWJac3NCR2wtRS5NVGN6TXpnME1ETTVPVFUzTXcuY21saWJIY3pkV3h4Ym0wLmo2V2VWWWEyZ0dHT0wzVU1POGZJNU1KbzROSU1CR3oxZG5XdVpPSllxcm8\u003d","pubKeyCredParams":[{"alg":"-7","type":"public-key"},{"alg":"-35","type":"public-key"},{"alg":"-36","type":"public-key"},{"alg":"-257","type":"public-key"},{"alg":"-258","type":"public-key"},{"alg":"-259","type":"public-key"},{"alg":"-37","type":"public-key"},{"alg":"-38","type":"public-key"},{"alg":"-39","type":"public-key"},{"alg":"-1","type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0\u003d","name":"test@email.com"}}
        "#.trim();
        let expected = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required"},"challenge":"Y3loVFRSWTN5QmxYRzVuazRucVVlNF9udExmVnVmdTlSeWJac3NCR2wtRS5NVGN6TXpnME1ETTVPVFUzTXcuY21saWJIY3pkV3h4Ym0wLmo2V2VWWWEyZ0dHT0wzVU1POGZJNU1KbzROSU1CR3oxZG5XdVpPSllxcm8=","pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-36,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},{"alg":-39,"type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0=","name":"test@email.com"}}
        "#.trim();

        let res = EbaySanitizer.sanitize(input);
        assert_eq!(expected, res);
    }
}
