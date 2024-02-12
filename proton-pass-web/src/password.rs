pub use proton_pass_common::password::{PassphraseConfig, PasswordScore, RandomPasswordConfig, WordSeparator};
use proton_pass_common::password::{PasswordPenalty, PasswordScoreResult};
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
    Vulnerable,
    Weak,
    Strong,
}

impl From<PasswordScore> for WasmPasswordScore {
    fn from(value: PasswordScore) -> Self {
        match value {
            PasswordScore::Vulnerable => WasmPasswordScore::Vulnerable,
            PasswordScore::Weak => WasmPasswordScore::Weak,
            PasswordScore::Strong => WasmPasswordScore::Strong,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmPasswordPenalty {
    NoLowercase,
    NoUppercase,
    NoNumbers,
    NoSymbols,
    Short,
    Consecutive,
    Progressive,
    ContainsCommonPassword,
}

impl From<PasswordPenalty> for WasmPasswordPenalty {
    fn from(value: PasswordPenalty) -> Self {
        match value {
            PasswordPenalty::NoLowercase => WasmPasswordPenalty::NoLowercase,
            PasswordPenalty::NoUppercase => WasmPasswordPenalty::NoUppercase,
            PasswordPenalty::NoNumbers => WasmPasswordPenalty::NoNumbers,
            PasswordPenalty::NoSymbols => WasmPasswordPenalty::NoSymbols,
            PasswordPenalty::Short => WasmPasswordPenalty::Short,
            PasswordPenalty::Consecutive => WasmPasswordPenalty::Consecutive,
            PasswordPenalty::Progressive => WasmPasswordPenalty::Progressive,
            PasswordPenalty::ContainsCommonPassword => WasmPasswordPenalty::ContainsCommonPassword,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmPasswordScoreResult {
    pub numeric_score: f64,
    pub password_score: WasmPasswordScore,
    pub penalties: Vec<WasmPasswordPenalty>,
}

impl From<PasswordScoreResult> for WasmPasswordScoreResult {
    fn from(value: PasswordScoreResult) -> Self {
        Self {
            numeric_score: value.numeric_score,
            password_score: value.password_score.into(),
            penalties: value.penalties.into_iter().map(WasmPasswordPenalty::from).collect(),
        }
    }
}
