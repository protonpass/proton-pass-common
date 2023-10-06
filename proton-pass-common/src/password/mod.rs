mod password_generator;
mod scorer;

use password_generator::PasswordGenerator;
use proton_pass_derive::Error;
use rand::{rngs::ThreadRng, thread_rng};
pub use scorer::{check_score, PasswordScore};

type ProductionPasswordGenerator = PasswordGenerator<ThreadRng>;

#[derive(Debug, Error)]
pub enum PasswordGeneratorError {
    FailToGenerate(String),
}

pub struct RandomPasswordConfig {
    pub length: u32,
    pub numbers: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
}

pub struct PassphraseConfig {
    pub separator: WordSeparator,
    pub capitalise: bool,
    pub include_numbers: bool,
    pub count: u32,
}

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
    PasswordGenerator::new(thread_rng())
}
