pub use proton_pass_common::password::error::PasswordGeneratorError;
pub use proton_pass_common::password::passphrase_generator::WordSeparator;
pub use proton_pass_common::password::passphrase_generator::{random_words, PassphraseConfig};
pub use proton_pass_common::password::random_generator::RandomPasswordConfig;

pub struct RandomPasswordGenerator;

impl RandomPasswordGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(&self, config: RandomPasswordConfig) -> Result<String, PasswordGeneratorError> {
        config.generate()
    }
}

pub struct PassphraseGenerator;

impl PassphraseGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn random_words(&self, word_count: u32) -> Vec<String> {
        random_words(word_count)
    }

    pub fn generate_passphrase(&self, words: Vec<String>, config: PassphraseConfig) -> String {
        config.generate(words)
    }
}
