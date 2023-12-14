pub use proton_pass_common::password::{
    PassphraseConfig, PasswordGeneratorError, PasswordScore, RandomPasswordConfig, WordSeparator,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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
