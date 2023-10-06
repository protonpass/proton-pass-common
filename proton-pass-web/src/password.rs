pub use proton_pass_common::password::{
    PassphraseConfig, PasswordGeneratorError, PasswordScore, RandomPasswordConfig, WordSeparator,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct WasmRandomPasswordConfig {
    length: u32,
    numbers: bool,
    uppercase_letters: bool,
    symbols: bool,
}

impl From<WasmRandomPasswordConfig> for RandomPasswordConfig {
    fn from(value: WasmRandomPasswordConfig) -> Self {
        Self {
            length: value.length,
            numbers: value.numbers,
            uppercase_letters: value.uppercase_letters,
            symbols: value.symbols,
        }
    }
}

#[wasm_bindgen]
pub enum WasmWordSeparator {
    Hyphens,
    Spaces,
    Periods,
    Commas,
    Underscores,
    Numbers,
    NumbersAndSymbols,
}

impl From<WasmWordSeparator> for WordSeparator {
    fn from(value: WasmWordSeparator) -> Self {
        match value {
            WasmWordSeparator::Hyphens => WordSeparator::Hyphens,
            WasmWordSeparator::Spaces => WordSeparator::Spaces,
            WasmWordSeparator::Periods => WordSeparator::Periods,
            WasmWordSeparator::Commas => WordSeparator::Commas,
            WasmWordSeparator::Underscores => WordSeparator::Underscores,
            WasmWordSeparator::Numbers => WordSeparator::Numbers,
            WasmWordSeparator::NumbersAndSymbols => WordSeparator::NumbersAndSymbols,
        }
    }
}

#[wasm_bindgen]
pub struct WasmPassphraseConfig {
    separator: WasmWordSeparator,
    capitalise: bool,
    include_numbers: bool,
    count: u32,
}

impl From<WasmPassphraseConfig> for PassphraseConfig {
    fn from(value: WasmPassphraseConfig) -> Self {
        Self {
            separator: value.separator.into(),
            capitalise: value.capitalise,
            include_numbers: value.include_numbers,
            count: value.count,
        }
    }
}

#[wasm_bindgen]
pub enum WasmPasswordScore {
    VeryDangerous,
    Dangerous,
    VeryWeak,
    Weak,
    Good,
    Strong,
    VeryStrong,
    Invulnerable,
}

impl From<PasswordScore> for WasmPasswordScore {
    fn from(value: PasswordScore) -> Self {
        match value {
            PasswordScore::VeryDangerous => WasmPasswordScore::VeryDangerous,
            PasswordScore::Dangerous => WasmPasswordScore::Dangerous,
            PasswordScore::VeryWeak => WasmPasswordScore::VeryWeak,
            PasswordScore::Weak => WasmPasswordScore::Weak,
            PasswordScore::Good => WasmPasswordScore::Good,
            PasswordScore::Strong => WasmPasswordScore::Strong,
            PasswordScore::VeryStrong => WasmPasswordScore::VeryStrong,
            PasswordScore::Invulnerable => WasmPasswordScore::Invulnerable,
        }
    }
}
