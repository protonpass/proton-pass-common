mod utils;

pub use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::is_email_valid(&email)
}
