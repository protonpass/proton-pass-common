mod common;
mod login;
mod password;
mod utils;

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
    let cfg: proton_pass_common::password::random_generator::RandomPasswordConfig = config.into();
    match cfg.generate() {
        Ok(s) => Ok(s),
        Err(e) => Err(e.into()),
    }
}

#[wasm_bindgen]
pub fn random_word(word_count: u32) -> ExportedStringVec {
    let words = proton_pass_common::password::passphrase_generator::random_words(word_count);
    let as_string_value: Vec<StringValue> = words.into_iter().map(|w| StringValue { value: w }).collect();
    ExportedStringVec(as_string_value)
}

#[wasm_bindgen]
pub fn generate_passphrase(words: ExportedStringVec, config: WasmPassphraseConfig) -> String {
    let strings: Vec<String> = words.0.into_iter().map(|v| v.value).collect();
    let cfg: proton_pass_common::password::passphrase_generator::PassphraseConfig = config.into();
    cfg.generate(strings)
}

#[wasm_bindgen]
pub fn check_password_score(password: String) -> WasmPasswordScore {
    proton_pass_common::password::scorer::check_score(&password).into()
}

pub use common::{ExportedStringVec, StringValue};
pub use login::WasmLogin;
pub use password::{WasmPassphraseConfig, WasmPasswordScore, WasmRandomPasswordConfig};
pub use utils::set_panic_hook;
