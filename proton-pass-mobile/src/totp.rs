pub struct TotpUriSanitizer;

impl TotpUriSanitizer {
    pub fn new() -> Self {
        Self
    }

    pub fn uri_for_editing(&self, original_uri: &str) -> String {
        proton_pass_common::totp::sanitizer::uri_for_editing(original_uri)
    }

    pub fn uri_for_saving(&self, original_uri: &str, edited_uri: &str) -> String {
        proton_pass_common::totp::sanitizer::uri_for_saving(original_uri, edited_uri)
    }
}
