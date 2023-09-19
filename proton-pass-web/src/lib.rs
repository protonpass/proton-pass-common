mod utils;

pub use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

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
pub fn validate_login_obj(login: proton_pass_common::login::Login) -> Result<(), JsError> {
    match proton_pass_common::login::validate_login(login) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
