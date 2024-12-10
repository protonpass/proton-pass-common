use super::PasskeySanitizer;
use serde_json::Value;

pub struct CvsSanitizer;

impl PasskeySanitizer for CvsSanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.map_or(false, |u| u.contains("cvs.com"));
        url_matches || request.contains("cvs.com")
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

        let authenticator_selection = match obj.get("authenticatorSelection") {
            Some(Value::Object(o)) => o,
            _ => return request.to_string(),
        };

        let requires_resident_key = match authenticator_selection.get("requireResidentKey") {
            Some(Value::String(value)) => match value.parse::<bool>() {
                Ok(v) => v,
                Err(_) => return request.to_string(),
            },
            _ => return request.to_string(),
        };

        let mut editable_authenticator_selection = authenticator_selection.clone();
        editable_authenticator_selection.insert("requireResidentKey".to_string(), Value::Bool(requires_resident_key));

        let mut editable_root_obj = obj.clone();
        editable_root_obj.insert(
            "authenticatorSelection".to_string(),
            Value::Object(editable_authenticator_selection),
        );
        serde_json::to_string(&Value::Object(editable_root_obj)).unwrap_or(request.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_web_request() {
        let input = r#"
        {"challenge":"xAFfbNsKOBYWfYUIl74gRB6ysFU=","rp":{"id":"www.cvs.com","name":"www"},"user":{"id":"lh+lAkVkuW9spaCshyR6NWzoMGnRJLPexB/kGdjtx+uVXf2GoQn6X3dnYTo/mAuGFMpgYy3QZ21T2J///106Pw==","name":"test@email.com","displayName":"Test User"},"pubKeyCredParams":[{"type":"public-key","alg":"-36"},{"type":"public-key","alg":"-35"},{"type":"public-key","alg":"-7"},{"type":"public-key","alg":"-8"},{"type":"public-key","alg":"-259"},{"type":"public-key","alg":"-258"},{"type":"public-key","alg":"-257"}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":"true","userVerification":"required"},"timeout":"180000","attestation":"direct","excludeCredentials":[]}
        "#.trim();
        let expected = r#"
        {"challenge":"xAFfbNsKOBYWfYUIl74gRB6ysFU=","rp":{"id":"www.cvs.com","name":"www"},"user":{"id":"lh+lAkVkuW9spaCshyR6NWzoMGnRJLPexB/kGdjtx+uVXf2GoQn6X3dnYTo/mAuGFMpgYy3QZ21T2J///106Pw==","name":"test@email.com","displayName":"Test User"},"pubKeyCredParams":[{"type":"public-key","alg":"-36"},{"type":"public-key","alg":"-35"},{"type":"public-key","alg":"-7"},{"type":"public-key","alg":"-8"},{"type":"public-key","alg":"-259"},{"type":"public-key","alg":"-258"},{"type":"public-key","alg":"-257"}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required"},"timeout":"180000","attestation":"direct","excludeCredentials":[]}
        "#.trim();

        let res = CvsSanitizer.sanitize(input);
        assert_eq!(expected, res);
    }

    #[test]
    fn sanitize_android_request() {
        let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},"challenge":"34aA3CTmf39a0lbhBvlX_yWweyM","excludeCredentials":[],"pubKeyCredParams":[{"alg":-36,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-7,"type":"public-key"},{"alg":-8,"type":"public-key"},{"alg":-259,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"www.cvs.com","name":"www"},"user":{"displayName":"Test User","id":"lh-lAkVkuW9spaCshyR6NWzoMGnRJLPexB_kGdjtx-uVXf2GoQn6X3dnYTo_mAuGFMpgYy3QZ21T2J___106Pw==","name":"test@email.com"}}
        "#.trim();

        let res = CvsSanitizer.sanitize(input);
        assert_eq!(input, res);
    }
}
