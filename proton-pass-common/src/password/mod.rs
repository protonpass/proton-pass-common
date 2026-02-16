mod analyzer;
mod password_generator;
mod scorer;

use password_generator::PasswordGenerator;
#[cfg(feature = "wasm")]
use proton_pass_derive::ffi_type;
use proton_pass_derive::Error;
use rand::{rng, rngs::ThreadRng};
pub use scorer::*;

type ProductionPasswordGenerator = PasswordGenerator<ThreadRng>;

#[derive(Debug, Error)]
pub enum PasswordGeneratorError {
    FailToGenerate(String),
}

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug)]
pub struct RandomPasswordConfig {
    pub length: u32,
    pub numbers: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
}

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug)]
pub struct PassphraseConfig {
    pub separator: WordSeparator,
    pub capitalise: bool,
    pub include_numbers: bool,
    pub count: u32,
}

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug)]
pub enum WordSeparator {
    Hyphens,
    Spaces,
    Periods,
    Commas,
    Underscores,
    Numbers,
    NumbersAndSymbols,
}

impl WordSeparator {
    pub fn all() -> Vec<WordSeparator> {
        vec![
            WordSeparator::Hyphens,
            WordSeparator::Spaces,
            WordSeparator::Periods,
            WordSeparator::Commas,
            WordSeparator::Underscores,
            WordSeparator::Numbers,
            WordSeparator::NumbersAndSymbols,
        ]
    }
}

pub fn get_generator() -> ProductionPasswordGenerator {
    PasswordGenerator::new(rng())
}
