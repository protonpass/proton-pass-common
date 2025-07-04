use crate::passkey::{PasskeyError, PasskeyResult};
use passkey_types::webauthn::PublicKeyCredentialCreationOptions;
use sanitize::{sanitize_request, PasskeySanitizer};

mod cvs;
mod ebay;
mod equal_sign;
mod paypal;
mod sanitize;
mod swissid;

fn parse(request: &str) -> PasskeyResult<PublicKeyCredentialCreationOptions> {
    serde_json::from_str(request).map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {e:?}")))
}

fn try_fix_request(request: &str) -> PasskeyResult<String> {
    let mut json_value: serde_json::Value = serde_json::from_str(request)
        .map_err(|e| PasskeyError::SerializationError(format!("Error parsing JSON for fixing: {e:?}")))?;

    fix_json_value(&mut json_value);

    serde_json::to_string(&json_value)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing fixed JSON: {e:?}")))
}

fn fix_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                fix_json_value(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                fix_json_value(v);
            }
        }
        serde_json::Value::String(s) => match s.as_str() {
            "true" => *value = serde_json::Value::Bool(true),
            "false" => *value = serde_json::Value::Bool(false),
            "null" => *value = serde_json::Value::Null,
            _ => {}
        },
        _ => {}
    }
}

pub fn parse_create_request(request: &str, url: Option<&str>) -> PasskeyResult<PublicKeyCredentialCreationOptions> {
    match parse(request) {
        Ok(parsed) => Ok(parsed),
        Err(_) => {
            let sanitized = sanitize_request(request, url);

            // Try to fix the sanitized request
            match try_fix_request(&sanitized) {
                Ok(fixed) => {
                    // Try to parse the fixed version first
                    match parse(&fixed) {
                        Ok(parsed) => Ok(parsed),
                        Err(_) => {
                            // If fixed version fails, fall back to sanitized version
                            parse(&sanitized)
                        }
                    }
                }
                Err(_) => {
                    // If fixing fails, fall back to sanitized version
                    parse(&sanitized)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod cvs {
        use super::*;
        #[test]
        fn parse_web_create_request() {
            let input = r#"
        {"challenge":"xAFfbNsKOBYWfYUIl74gRB6ysFU=","rp":{"id":"www.cvs.com","name":"www"},"user":{"id":"lh+lAkVkuW9spaCshyR6NWzoMGnRJLPexB/kGdjtx+uVXf2GoQn6X3dnYTo/mAuGFMpgYy3QZ21T2J///106Pw==","name":"test@email.com","displayName":"Test User"},"pubKeyCredParams":[{"type":"public-key","alg":"-36"},{"type":"public-key","alg":"-35"},{"type":"public-key","alg":"-7"},{"type":"public-key","alg":"-8"},{"type":"public-key","alg":"-259"},{"type":"public-key","alg":"-258"},{"type":"public-key","alg":"-257"}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":"true","userVerification":"required"},"timeout":"180000","attestation":"direct","excludeCredentials":[]}
        "#.trim();

            let raw_parse = parse(input);
            assert!(raw_parse.is_err());

            let parsed = parse_create_request(input, Some("www.cvs.com"));
            assert!(parsed.is_ok());
        }

        #[test]
        fn parse_android_create_request() {
            let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},"challenge":"34aA3CTmf39a0lbhBvlX_yWweyM","excludeCredentials":[],"pubKeyCredParams":[{"alg":-36,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-7,"type":"public-key"},{"alg":-8,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"www.cvs.com","name":"www"},"user":{"displayName":"Test User","id":"lh-lAkVkuW9spaCshyR6NWzoMGnRJLPexB_kGdjtx-uVXf2GoQn6X3dnYTo_mAuGFMpgYy3QZ21T2J___106Pw==","name":"test@email.com"}}
        "#.trim();

            let parsed = parse_create_request(input, Some("www.cvs.com"));
            assert!(parsed.is_ok());
        }
    }

    mod ebay {
        use super::*;

        #[test]
        fn parse_web_create_request() {
            let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},"challenge":"MHFHazVISkJNamZrVXlwaWYtUGQ3eFJRb3lvVEk1VFZZdEZXdHQ3VERRay5NVGN6TXpnek9ETXdNekF5T1EuY21saWJIY3pkV3h4Ym0wLmdCUENVM1BrZVNZLUZnWWhueXRQWkxVRkU4aG5UQVpkVjZrMDNFY1FYalU","excludeCredentials":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-36,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},{"alg":-39,"type":"public-key"},{"alg":-1,"type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0","name":"test@email.com"}}
        "#.trim();
            let raw_parse = parse(input);
            assert!(raw_parse.is_err());

            let parsed = parse_create_request(input, Some("ebay.com"));
            assert!(parsed.is_ok());
        }

        #[test]
        fn parse_android_create_request() {
            let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required"},"challenge":"Y3loVFRSWTN5QmxYRzVuazRucVVlNF9udExmVnVmdTlSeWJac3NCR2wtRS5NVGN6TXpnME1ETTVPVFUzTXcuY21saWJIY3pkV3h4Ym0wLmo2V2VWWWEyZ0dHT0wzVU1POGZJNU1KbzROSU1CR3oxZG5XdVpPSllxcm8\u003d","pubKeyCredParams":[{"alg":"-7","type":"public-key"},{"alg":"-35","type":"public-key"},{"alg":"-36","type":"public-key"},{"alg":"-257","type":"public-key"},{"alg":"-258","type":"public-key"},{"alg":"-259","type":"public-key"},{"alg":"-37","type":"public-key"},{"alg":"-38","type":"public-key"},{"alg":"-39","type":"public-key"},{"alg":"-1","type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0\u003d","name":"test@email.com"}}
        "#.trim();
            let raw_parse = parse(input);
            assert!(raw_parse.is_err());

            let parsed = parse_create_request(input, Some("ebay.com"));
            assert!(parsed.is_ok());
        }
    }

    mod paypal {
        use super::*;
        #[test]
        fn parse_web_create_request() {
            let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"preferred","userVerification":"required"},"challenge":"MjAyNC0xMi0xMFQxMzo1NzoxMVpbQkAzOTc4M2RkNg","excludeCredentials":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"www.paypal.com","name":"PayPal"},"user":{"displayName":"My Test User","id":"AWVyCjDzEGF3ZgY1HGIiYJBmKDdlZMJhNzcxOPQmRzI4SjY4TTUzOVA1WDhjXYc4ZTg0YTk3NDc1MjUwMGE3NQ","name":"test@email.com"}}
        "#.trim();

            let parsed = parse_create_request(input, Some("paypal.com"));
            assert!(parsed.is_ok());
        }

        #[test]
        fn parse_android_create_request() {
            let input = r#"
        {"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"residentKey":"required","userVerification":"required"},"challenge":"MjAyNC0xMi0xMFQxNDowMTo0NVpbQkAxY2U2MmMyMQ\u003d\u003d","attestation":"none","user":{"id":"AWVyCjDzEGF3ZgY1HGIiYJBmKDdlZMJhNzcxOPQmRzI4SjY4TTUzOVA1WDhjXYc4ZTg0YTk3NDc1MjUwMGE3NQ\u003d\u003d","name":"test@email.com","displayName":"test@email.com"},"timeout":1800000.0,"rp":{"id":"www.paypal.com","name":"PayPal"}}
        "#.trim();

            let parsed = parse_create_request(input, Some("paypal.com"));
            assert!(parsed.is_ok());
        }
    }

    mod swissid {
        use super::*;
        #[test]
        fn parse_web_create_request() {
            let input = r#"
        {"challenge":{"0":103,"1":-58,"2":-87,"3":-100,"4":-24,"5":102,"6":39,"7":-80,"8":91,"9":-105,"10":-100,"11":32,"12":1,"13":-92,"14":-100,"15":-8,"16":-48,"17":34,"18":36,"19":102,"20":110,"21":-28,"22":14,"23":-72,"24":-52,"25":-31,"26":56,"27":-32,"28":-34,"29":75,"30":51,"31":-74},"rp":{"name":"login.swissid.ch"},"user":{"id":{"0":89,"1":15,"2":28,"3":30,"4":41,"5":52,"6":64,"7":73,"8":85,"9":97,"10":101,"11":113,"12":121,"13":115,"14":52,"15":51,"16":52,"17":102,"18":45,"19":56,"20":56,"21":57,"22":54,"23":45,"24":53,"25":52,"26":57,"27":102,"28":50,"29":55,"30":97,"31":98,"32":56,"33":98,"34":56,"35":48},"name":"test@email.com","displayName":"test@email.com"},"pubKeyCredParams":[{"type":"public-key","alg":-257},{"type":"public-key","alg":-7}],"attestation":"indirect","timeout":60000,"authenticatorSelection":{"userVerification":"required","authenticatorAttachment":"platform","requireResidentKey":false}}
        "#.trim();

            let raw_parse = parse(input);
            assert!(raw_parse.is_err());

            let parsed = parse_create_request(input, Some("swissid.ch"));
            assert!(parsed.is_ok());
        }
    }
}
