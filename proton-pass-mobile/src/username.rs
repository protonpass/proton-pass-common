use proton_pass_common::string_modifiers::WordSeparator as CommonWordSeparator;
use proton_pass_common::username::{
    get_generator, UsernameGeneratorConfig as CommonUsernameGeneratorConfig,
    UsernameGeneratorError as CommonUsernameGeneratorError, WordTypes as CommonWordTypes,
};

use super::password::WordSeparator;

#[derive(Debug, proton_pass_derive::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UsernameGeneratorError {
    FailToGenerate(String),
}

impl From<CommonUsernameGeneratorError> for UsernameGeneratorError {
    fn from(e: CommonUsernameGeneratorError) -> Self {
        match e {
            CommonUsernameGeneratorError::FailToGenerate(msg) => UsernameGeneratorError::FailToGenerate(msg),
        }
    }
}

type Result<T> = std::result::Result<T, UsernameGeneratorError>;

#[derive(uniffi::Record)]
pub struct WordTypes {
    pub adjectives: bool,
    pub nouns: bool,
    pub verbs: bool,
}

impl From<WordTypes> for CommonWordTypes {
    fn from(other: WordTypes) -> Self {
        Self {
            adjectives: other.adjectives,
            nouns: other.nouns,
            verbs: other.verbs,
        }
    }
}

#[derive(uniffi::Record)]
pub struct UsernameGeneratorConfig {
    pub word_count: u32,
    pub include_numbers: bool,
    pub capitalise: bool,
    pub separator: Option<WordSeparator>,
    pub leetspeak: bool,
    pub word_types: WordTypes,
}

impl From<UsernameGeneratorConfig> for CommonUsernameGeneratorConfig {
    fn from(other: UsernameGeneratorConfig) -> Self {
        Self {
            word_count: other.word_count,
            include_numbers: other.include_numbers,
            capitalise: other.capitalise,
            separator: other.separator.map(CommonWordSeparator::from),
            leetspeak: other.leetspeak,
            word_types: CommonWordTypes::from(other.word_types),
        }
    }
}

#[derive(uniffi::Object)]
pub struct UsernameGenerator;

#[uniffi::export]
impl UsernameGenerator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn generate(&self, config: UsernameGeneratorConfig) -> Result<String> {
        let mut generator = get_generator();
        Ok(generator.generate_username(&CommonUsernameGeneratorConfig::from(config))?)
    }
}
