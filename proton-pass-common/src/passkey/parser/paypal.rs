use super::PasskeySanitizer;
use serde_json::Value;

pub struct PaypalSanitizer;

impl PasskeySanitizer for PaypalSanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.map_or(false, |u| u.contains("paypal."));
        url_matches || request.contains("paypal.")
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

        if let Some(timeout) = obj.get("timeout") {
            if let Some(num) = timeout.as_f64() {
                let mut editable = obj.clone();
                editable.insert("timeout".to_string(), Value::from(num as i64));
                return serde_json::to_string(&Value::Object(editable)).unwrap_or(request.to_string());
            }
        }

        request.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_web_request() {
        let input = r#"
        {"attestation":"direct","authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"preferred","userVerification":"required"},"challenge":"MjAyNC0xMi0xMFQxMzo1NzoxMVpbQkAzOTc4M2RkNg","excludeCredentials":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"www.paypal.com","name":"PayPal"},"user":{"displayName":"My Test User","id":"AWVyCjDzEGF3ZgY1HGIiYJBmKDdlZMJhNzcxOPQmRzI4SjY4TTUzOVA1WDhjXYc4ZTg0YTk3NDc1MjUwMGE3NQ","name":"test@email.com"}}
        "#.trim();
        let res = PaypalSanitizer.sanitize(input);
        assert_eq!(input, res);
    }

    #[test]
    fn sanitize_android_request() {
        let input = r#"
        {"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"residentKey":"required","userVerification":"required"},"challenge":"MjAyNC0xMi0xMFQxNDowMTo0NVpbQkAxY2U2MmMyMQ\u003d\u003d","attestation":"none","user":{"id":"AWVyCjDzEGF3ZgY1HGIiYJBmKDdlZMJhNzcxOPQmRzI4SjY4TTUzOVA1WDhjXYc4ZTg0YTk3NDc1MjUwMGE3NQ\u003d\u003d","name":"test@email.com","displayName":"test@email.com"},"timeout":1800000.0,"rp":{"id":"www.paypal.com","name":"PayPal"}}
        "#.trim();

        let expected = r#"
        {"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"residentKey":"required","userVerification":"required"},"challenge":"MjAyNC0xMi0xMFQxNDowMTo0NVpbQkAxY2U2MmMyMQ==","attestation":"none","user":{"id":"AWVyCjDzEGF3ZgY1HGIiYJBmKDdlZMJhNzcxOPQmRzI4SjY4TTUzOVA1WDhjXYc4ZTg0YTk3NDc1MjUwMGE3NQ==","name":"test@email.com","displayName":"test@email.com"},"timeout":1800000,"rp":{"id":"www.paypal.com","name":"PayPal"}}
        "#.trim();

        let res = PaypalSanitizer.sanitize(input);
        assert_eq!(expected, res);
    }
}
