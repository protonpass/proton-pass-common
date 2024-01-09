pub use proton_pass_common::password::{
    check_score, get_generator, PassphraseConfig, PasswordGeneratorError, PasswordPenalty, PasswordScore,
    PasswordScoreResult, RandomPasswordConfig, WordSeparator,
};

type Result<T> = std::result::Result<T, PasswordGeneratorError>;

pub struct RandomPasswordGenerator;

impl RandomPasswordGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(&self, config: RandomPasswordConfig) -> Result<String> {
        let mut generator = get_generator();
        generator.generate_random(&config)
    }
}

pub struct PassphraseGenerator;

impl PassphraseGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn random_words(&self, word_count: u32) -> Result<Vec<String>> {
        let mut generator = get_generator();
        generator.random_words(word_count as usize)
    }

    pub fn generate_passphrase(&self, words: Vec<String>, config: PassphraseConfig) -> Result<String> {
        let mut generator = get_generator();
        generator.generate_passphrase_from_words(words, &config)
    }

    pub fn generate_random_passphrase(&self, config: PassphraseConfig) -> Result<String> {
        let mut generator = get_generator();
        generator.generate_passphrase(&config)
    }
}

pub struct PasswordScorer;

impl PasswordScorer {
    pub fn new() -> Self {
        Self
    }

    pub fn check_score(&self, password: String) -> PasswordScore {
        check_score(&password).password_score
    }

    pub fn score_password(&self, password: String) -> PasswordScoreResult {
        check_score(&password)
    }
}
