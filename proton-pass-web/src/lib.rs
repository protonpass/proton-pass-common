mod utils;

use proton_pass_common::alias_prefix::AliasPrefixError;
pub use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}

#[derive(Debug)]
pub enum WebAliasPrefixError {
    TwoConsecutiveDots,
    InvalidCharacter,
    DotAtTheEnd,
    PrefixTooLong,
    PrefixEmpty,
}

impl From<AliasPrefixError> for WebAliasPrefixError {
    fn from(value: AliasPrefixError) -> Self {
        match value {
            AliasPrefixError::TwoConsecutiveDots => WebAliasPrefixError::TwoConsecutiveDots,
            AliasPrefixError::InvalidCharacter => WebAliasPrefixError::InvalidCharacter,
            AliasPrefixError::DotAtTheEnd => WebAliasPrefixError::DotAtTheEnd,
            AliasPrefixError::PrefixTooLong => WebAliasPrefixError::PrefixTooLong,
            AliasPrefixError::PrefixEmpty => WebAliasPrefixError::PrefixEmpty,
        }
    }
}

impl From<WebAliasPrefixError> for JsValue {
    fn from(error: WebAliasPrefixError) -> JsValue {
        JsValue::from_str(&format!("{:?}", error))
    }
}

#[wasm_bindgen]
pub fn validate_alias_prefix(prefix: String) -> Result<(), WebAliasPrefixError> {
    match proton_pass_common::alias_prefix::validate_alias_prefix(&prefix) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
