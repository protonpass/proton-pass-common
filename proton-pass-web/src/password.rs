use crate::password::WasmWordSeparator::{Commas, Hyphens, Numbers, NumbersAndSymbols, Periods, Spaces, Underscores};
use proton_pass_common::password::passphrase_generator::{PassphraseConfig, WordSeparator};
use proton_pass_common::password::random_generator::RandomPasswordConfig;
use proton_pass_common::password::scorer::PasswordScore;
use proton_pass_common::password::scorer::PasswordScore::{
    Dangerous, Good, Invulnerable, Strong, VeryDangerous, VeryStrong, VeryWeak, Weak,
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
            Hyphens => WordSeparator::Hyphens,
            Spaces => WordSeparator::Spaces,
            Periods => WordSeparator::Periods,
            Commas => WordSeparator::Commas,
            Underscores => WordSeparator::Underscores,
            Numbers => WordSeparator::Numbers,
            NumbersAndSymbols => WordSeparator::NumbersAndSymbols,
        }
    }
}

#[wasm_bindgen]
pub struct WasmPassphraseConfig {
    separator: WasmWordSeparator,
    capitalise: bool,
    include_numbers: bool,
}

impl From<WasmPassphraseConfig> for PassphraseConfig {
    fn from(value: WasmPassphraseConfig) -> Self {
        Self {
            separator: value.separator.into(),
            capitalise: value.capitalise,
            include_numbers: value.include_numbers,
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
            VeryDangerous => WasmPasswordScore::VeryDangerous,
            Dangerous => WasmPasswordScore::Dangerous,
            VeryWeak => WasmPasswordScore::VeryWeak,
            Weak => WasmPasswordScore::Weak,
            Good => WasmPasswordScore::Good,
            Strong => WasmPasswordScore::Strong,
            VeryStrong => WasmPasswordScore::VeryStrong,
            Invulnerable => WasmPasswordScore::Invulnerable,
        }
    }
}
