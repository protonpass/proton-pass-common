use proton_pass_common;
use wasm_bindgen::prelude::*;

use crate::creditcard::{CreditCardDetector, WasmCreditCardType};
use crate::login::WasmLogin;

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
