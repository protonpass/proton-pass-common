use proton_pass_common::password::{
    PassphraseConfig as CommonPassphraseConfig, PasswordGeneratorError as CommonPasswordGeneratorError,
    PasswordPenalty as CommonPasswordPenalty, PasswordScore as CommonPasswordScore,
    PasswordScoreResult as CommonPasswordScoreResult, RandomPasswordConfig as CommonRandomPasswordConfig,
    WordSeparator as CommonWordSeparator,
};

use proton_pass_common::password::{check_score, get_generator};

// START MAPPING TYPES
#[derive(Debug, proton_pass_derive::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PasswordGeneratorError {
    FailToGenerate(String),
}

impl From<CommonPasswordGeneratorError> for PasswordGeneratorError {
    fn from(e: CommonPasswordGeneratorError) -> Self {
        match e {
            CommonPasswordGeneratorError::FailToGenerate(e) => PasswordGeneratorError::FailToGenerate(e),
        }
    }
}

type Result<T> = std::result::Result<T, PasswordGeneratorError>;

#[derive(uniffi::Record)]
pub struct PassphraseConfig {
    pub separator: WordSeparator,
    pub capitalise: bool,
    pub include_numbers: bool,
    pub count: u32,
}

impl From<PassphraseConfig> for CommonPassphraseConfig {
    fn from(other: PassphraseConfig) -> Self {
        Self {
            separator: other.separator.into(),
            capitalise: other.capitalise,
            include_numbers: other.include_numbers,
            count: other.count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordPenalty {
    NoLowercase,
    NoUppercase,
    NoNumbers,
    NoSymbols,
    Short,
    Consecutive,
    Progressive,
    ContainsCommonPassword,
    ShortWordList,
}

impl From<CommonPasswordPenalty> for PasswordPenalty {
    fn from(other: CommonPasswordPenalty) -> Self {
        match other {
            CommonPasswordPenalty::NoLowercase => Self::NoLowercase,
            CommonPasswordPenalty::NoUppercase => Self::NoUppercase,
            CommonPasswordPenalty::NoNumbers => Self::NoNumbers,
            CommonPasswordPenalty::NoSymbols => Self::NoSymbols,
            CommonPasswordPenalty::Short => Self::Short,
            CommonPasswordPenalty::Consecutive => Self::Consecutive,
            CommonPasswordPenalty::Progressive => Self::Progressive,
            CommonPasswordPenalty::ContainsCommonPassword => Self::ContainsCommonPassword,
            CommonPasswordPenalty::ShortWordList => Self::ShortWordList,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordScore {
    Vulnerable,
    Weak,
    Strong,
}

impl From<CommonPasswordScore> for PasswordScore {
    fn from(other: CommonPasswordScore) -> Self {
        match other {
            CommonPasswordScore::Vulnerable => Self::Vulnerable,
            CommonPasswordScore::Weak => Self::Weak,
            CommonPasswordScore::Strong => Self::Strong,
        }
    }
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PasswordScoreResult {
    pub numeric_score: f64,
    pub password_score: PasswordScore,
    pub penalties: Vec<PasswordPenalty>,
}

impl From<CommonPasswordScoreResult> for PasswordScoreResult {
    fn from(other: CommonPasswordScoreResult) -> Self {
        Self {
            numeric_score: other.numeric_score,
            password_score: other.password_score.into(),
            penalties: other.penalties.into_iter().map(PasswordPenalty::from).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct RandomPasswordConfig {
    pub length: u32,
    pub numbers: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
}

impl From<RandomPasswordConfig> for CommonRandomPasswordConfig {
    fn from(other: RandomPasswordConfig) -> Self {
        Self {
            length: other.length,
            numbers: other.numbers,
            uppercase_letters: other.uppercase_letters,
            symbols: other.symbols,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum WordSeparator {
    Hyphens,
    Spaces,
    Periods,
    Commas,
    Underscores,
    Numbers,
    NumbersAndSymbols,
}

impl From<WordSeparator> for CommonWordSeparator {
    fn from(other: WordSeparator) -> Self {
        match other {
            WordSeparator::Hyphens => CommonWordSeparator::Hyphens,
            WordSeparator::Spaces => CommonWordSeparator::Spaces,
            WordSeparator::Periods => CommonWordSeparator::Periods,
            WordSeparator::Commas => CommonWordSeparator::Commas,
            WordSeparator::Underscores => CommonWordSeparator::Underscores,
            WordSeparator::Numbers => CommonWordSeparator::Numbers,
            WordSeparator::NumbersAndSymbols => CommonWordSeparator::NumbersAndSymbols,
        }
    }
}

// END MAPPING TYPES

#[derive(uniffi::Object)]
pub struct RandomPasswordGenerator;

#[uniffi::export]
impl RandomPasswordGenerator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn generate(&self, config: RandomPasswordConfig) -> Result<String> {
        let mut generator = get_generator();
        Ok(generator.generate_random(&CommonRandomPasswordConfig::from(config))?)
    }
}

#[derive(uniffi::Object)]
pub struct PassphraseGenerator;

#[uniffi::export]
impl PassphraseGenerator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn random_words(&self, word_count: u32) -> Result<Vec<String>> {
        let mut generator = get_generator();
        Ok(generator.random_words(word_count as usize)?)
    }

    pub fn generate_passphrase(&self, words: Vec<String>, config: PassphraseConfig) -> Result<String> {
        let mut generator = get_generator();
        Ok(generator.generate_passphrase_from_words(words, &CommonPassphraseConfig::from(config))?)
    }

    pub fn generate_random_passphrase(&self, config: PassphraseConfig) -> Result<String> {
        let mut generator = get_generator();
        Ok(generator.generate_passphrase(&CommonPassphraseConfig::from(config))?)
    }
}

#[derive(uniffi::Object)]
pub struct PasswordScorer;

#[uniffi::export]
impl PasswordScorer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn check_score(&self, password: String) -> PasswordScore {
        PasswordScore::from(check_score(&password).password_score)
    }

    pub fn score_password(&self, password: String) -> PasswordScoreResult {
        PasswordScoreResult::from(check_score(&password))
    }
}
