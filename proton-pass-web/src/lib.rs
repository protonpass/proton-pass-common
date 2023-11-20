mod common;
mod creditcard;
mod login;
mod password;
mod utils;

use proton_pass_common::password::{get_generator, PassphraseConfig, RandomPasswordConfig};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn library_version() -> String {
    proton_pass_common::library_version()
}

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
pub fn generate_password(config: WasmRandomPasswordConfig) -> Result<String, JsError> {
    let mut generator = get_generator();
    let cfg: RandomPasswordConfig = config.into();
    generator.generate_random(&cfg).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn random_words(word_count: u32) -> Result<ExportedStringVec, JsError> {
    let mut generator = get_generator();
    generator
        .random_words(word_count as usize)
        .map(|words| {
            let as_string_value: Vec<StringValue> = words.into_iter().map(|w| StringValue { value: w }).collect();
            ExportedStringVec(as_string_value)
        })
        .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn generate_passphrase(words: ExportedStringVec, config: WasmPassphraseConfig) -> Result<String, JsError> {
    let strings: Vec<String> = words.0.into_iter().map(|v| v.value).collect();
    let mut generator = get_generator();
    let cfg: PassphraseConfig = config.into();

    generator
        .generate_passphrase_from_words(strings, &cfg)
        .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn generate_random_passphrase(config: WasmPassphraseConfig) -> Result<String, JsError> {
    let mut generator = get_generator();
    let cfg: PassphraseConfig = config.into();

    generator.generate_passphrase(&cfg).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn check_password_score(password: String) -> WasmPasswordScore {
    proton_pass_common::password::check_score(&password).into()
}

#[wasm_bindgen]
pub fn create_new_user_invite_signature_body(email: String, vault_key: js_sys::Uint8Array) -> js_sys::Uint8Array {
    let vault_key_as_vec = vault_key.to_vec();
    let res = proton_pass_common::invite::create_signature_body(&email, vault_key_as_vec);
    utils::vec_to_uint8_array(res)
}

#[wasm_bindgen]
pub fn detect_credit_card_type(card_number: String) -> WasmCreditCardType {
    let detector = creditcard::CreditCardDetector::default();
    let detected = detector.detect(&card_number);
    detected.into()
}

pub use common::{ExportedStringVec, StringValue};
pub use creditcard::WasmCreditCardType;
pub use login::WasmLogin;
pub use password::{WasmPassphraseConfig, WasmPasswordScore, WasmRandomPasswordConfig};
pub use utils::set_panic_hook;
