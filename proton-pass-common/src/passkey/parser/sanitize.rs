use super::{cvs, ebay, equal_sign, paypal, swissid};

pub trait PasskeySanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool;
    fn sanitize(&self, request: &str) -> String;
}

lazy_static::lazy_static! {
    static ref SANITIZERS: Vec<Box<dyn PasskeySanitizer + Send + Sync>> = vec![
        Box::new(equal_sign::EqualSignSanitizer),
        Box::new(paypal::PaypalSanitizer),
        Box::new(ebay::EbaySanitizer),
        Box::new(cvs::CvsSanitizer),
        Box::new(swissid::SwissIdSanitizer)
    ];
}

pub fn sanitize_request(request: &str, url: Option<&str>) -> String {
    let mut content = request.to_string();
    for sanitizer in SANITIZERS.iter() {
        if sanitizer.should_sanitize(url, &content) {
            content = sanitizer.sanitize(&content);
        }
    }
    content
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_sanitize_empty_request() {
        assert_eq!("", sanitize_request("", None));
    }

    #[test]
    fn test_sanitize_leaves_correct_request_as_is() {
        let input = r#"
        {"attestation":"none","authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},"challenge":"qEb-L-3-cp65J8-VJlZACfzVeB98j2AUY-JexPTBiqBrLyec9XozWpy3SHo84UTtEAztuUVuRCwg0aF9zaE1JA","excludeCredentials":[],"extensions":{"credProps":true},"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"protonpass.github.io","name":"protonpass.github.io"},"user":{"displayName":"test","id":"Y21WeVpYSmw","name":"test"}}
        "#;
        let sanitized = sanitize_request(input, None);
        assert_eq!(sanitized, input);
    }
}
