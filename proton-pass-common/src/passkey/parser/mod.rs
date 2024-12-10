use crate::passkey::{PasskeyError, PasskeyResult};
use passkey_types::webauthn::PublicKeyCredentialCreationOptions;
use sanitize::{sanitize_request, PasskeySanitizer};

mod cvs;
mod ebay;
mod equal_sign;
mod paypal;
mod sanitize;

pub fn parse_create_request(request: &str, url: Option<&str>) -> PasskeyResult<PublicKeyCredentialCreationOptions> {
    match serde_json::from_str(request) {
        Ok(parsed) => Ok(parsed),
        Err(_) => {
            let sanitized = sanitize_request(request, url);
            let parsed: PublicKeyCredentialCreationOptions = serde_json::from_str(&sanitized)
                .map_err(|e| PasskeyError::SerializationError(format!("Error parsing request: {:?}", e)))?;
            Ok(parsed)
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

            let parsed = parse_create_request(input, Some("ebay.com"));
            assert!(parsed.is_ok());
        }

        #[test]
        fn parse_android_create_request() {
            let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required"},"challenge":"Y3loVFRSWTN5QmxYRzVuazRucVVlNF9udExmVnVmdTlSeWJac3NCR2wtRS5NVGN6TXpnME1ETTVPVFUzTXcuY21saWJIY3pkV3h4Ym0wLmo2V2VWWWEyZ0dHT0wzVU1POGZJNU1KbzROSU1CR3oxZG5XdVpPSllxcm8\u003d","pubKeyCredParams":[{"alg":"-7","type":"public-key"},{"alg":"-35","type":"public-key"},{"alg":"-36","type":"public-key"},{"alg":"-257","type":"public-key"},{"alg":"-258","type":"public-key"},{"alg":"-259","type":"public-key"},{"alg":"-37","type":"public-key"},{"alg":"-38","type":"public-key"},{"alg":"-39","type":"public-key"},{"alg":"-1","type":"public-key"}],"rp":{"id":"ebay.es","name":"ebay.es"},"user":{"displayName":"test@email.com","id":"abcdeFghWZxbm0\u003d","name":"test@email.com"}}
        "#.trim();
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
}
