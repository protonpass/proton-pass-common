use wasm_bindgen::prelude::*;

use proton_pass_common::username::UsernameGeneratorConfig;

#[wasm_bindgen]
pub fn generate_username(config: UsernameGeneratorConfig) -> Result<String, JsError> {
    let mut generator = proton_pass_common::username::get_generator();
    generator.generate_username(&config).map_err(|e| e.into())
}
