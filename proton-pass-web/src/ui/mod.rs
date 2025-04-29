use crate::ui::file::WasmFileGroup;
use crate::ui::wifi::WasmWifiSecurity;
use creditcard::*;
use login::WasmLogin;
use proton_pass_common::file::{get_file_group_from_mime_type, get_mime_type_from_content, sanitize_name};
use proton_pass_common::wifi::generate_wifi_uri;
use wasm_bindgen::prelude::*;

mod creditcard;
mod file;
mod login;
mod wifi;

#[wasm_bindgen]
pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}

#[wasm_bindgen]
pub fn validate_alias_prefix(prefix: String) -> Result<(), JsError> {
    match proton_pass_common::alias_prefix::validate_alias_prefix(&prefix) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[wasm_bindgen]
pub fn validate_login_obj(login: WasmLogin) -> Result<(), JsError> {
    match proton_pass_common::login::validate_login(login.into()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[wasm_bindgen]
pub fn get_root_domain(input: String) -> Result<String, JsError> {
    Ok(proton_pass_common::domain::get_root_domain(&input)?)
}

#[wasm_bindgen]
pub fn get_domain(input: String) -> Result<String, JsError> {
    Ok(proton_pass_common::domain::get_domain(&input)?)
}

#[wasm_bindgen]
pub fn detect_credit_card_type(card_number: String) -> WasmCreditCardType {
    let detector = CreditCardDetector::default();
    let detected = detector.detect(&card_number);
    detected.into()
}

#[wasm_bindgen]
pub fn file_group_from_mime_type(mime_type: String) -> WasmFileGroup {
    WasmFileGroup::from(get_file_group_from_mime_type(&mime_type))
}

#[wasm_bindgen]
pub fn mime_type_from_content(content: js_sys::Uint8Array) -> String {
    let as_vec = content.to_vec();
    get_mime_type_from_content(&as_vec)
}

#[wasm_bindgen]
pub fn sanitize_filename(name: String, windows: bool) -> String {
    sanitize_name(&name, windows)
}

#[wasm_bindgen]
pub fn generate_wifi_svg_qr_code(
    ssid: String,
    password: String,
    security: WasmWifiSecurity,
) -> Result<String, JsError> {
    let uri = generate_wifi_uri(&ssid, &password, security.into()).map_err(|e| JsError::from(e))?;
    generate_svg_qr_code(uri)
}

#[wasm_bindgen]
pub fn generate_svg_qr_code(value: String) -> Result<String, JsError> {
    proton_pass_common::qr::generate_svg_qr_code(&value).map_err(|e| e.into())
}
