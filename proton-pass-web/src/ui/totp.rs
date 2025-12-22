use proton_pass_common::totp::sanitizer;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sanitize_otp(uri_or_secret: String, label: Option<String>, issuer: Option<String>) -> Result<String, JsError> {
    Ok(sanitizer::sanitize_otp(&uri_or_secret, label, issuer)?)
}

#[wasm_bindgen]
pub fn human_readable_otp(uri_or_secret: String) -> String {
    sanitizer::human_readable_otp(&uri_or_secret)
}
