use password::{
    WasmPassphraseConfig, WasmPasswordScore, WasmPasswordScoreList, WasmPasswordScoreResult, WasmRandomPasswordConfig,
};
use proton_pass_common::password::{get_generator, PassphraseConfig, RandomPasswordConfig};
use wasm_bindgen::prelude::*;

mod password;

#[wasm_bindgen]
pub fn generate_password(config: WasmRandomPasswordConfig) -> Result<String, JsError> {
    let mut generator = get_generator();
    let cfg: RandomPasswordConfig = config.into();
    generator.generate_random(&cfg).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn random_words(word_count: u32) -> Result<Vec<String>, JsError> {
    let mut generator = get_generator();
    generator.random_words(word_count as usize).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn generate_passphrase(words: Vec<String>, config: WasmPassphraseConfig) -> Result<String, JsError> {
    let mut generator = get_generator();
    let cfg: PassphraseConfig = config.into();

    generator
        .generate_passphrase_from_words(words, &cfg)
        .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn generate_random_passphrase(config: WasmPassphraseConfig) -> Result<String, JsError> {
    let mut generator = get_generator();
    let cfg: PassphraseConfig = config.into();

    generator.generate_passphrase(&cfg).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn analyze_password(password: String) -> WasmPasswordScoreResult {
    proton_pass_common::password::check_score(&password).into()
}

#[wasm_bindgen]
pub fn check_password_score(password: String) -> WasmPasswordScore {
    proton_pass_common::password::check_score(&password)
        .password_score
        .into()
}

#[wasm_bindgen]
pub fn check_password_scores(passwords: Vec<String>) -> WasmPasswordScoreList {
    WasmPasswordScoreList(
        passwords
            .iter()
            .map(|password| {
                proton_pass_common::password::check_score(password)
                    .password_score
                    .into()
            })
            .collect(),
    )
}

#[wasm_bindgen]
pub fn calculate_password_score(password: String) -> f64 {
    proton_pass_common::password::numeric_score(&password)
}
