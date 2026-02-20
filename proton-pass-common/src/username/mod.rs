mod username_generator;

pub use crate::string_modifiers::WordSeparator;
use proton_pass_derive::Error;
use rand::{rng, rngs::ThreadRng};
use username_generator::UsernameGenerator;
#[cfg(feature = "wasm")]
use proton_pass_derive::ffi_type;

type ProductionUsernameGenerator = UsernameGenerator<ThreadRng>;

#[derive(Debug, Error)]
pub enum UsernameGeneratorError {
    FailToGenerate(String),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WordType {
    Adjective,
    Noun,
    Verb,
}

#[cfg_attr(feature = "wasm", ffi_type(web_name = "WasmUsernameGeneratorConfig"))]
pub struct UsernameGeneratorConfig {
    pub word_count: u32,
    pub include_numbers: bool,
    pub capitalise: bool,
    pub separator: Option<WordSeparator>,
    pub leetspeak: bool,
    pub word_types: WordTypes,
}


#[cfg_attr(feature = "wasm", ffi_type(web_name = "WasmWordTypes"))]
pub struct WordTypes {
    pub adjectives: bool,
    pub nouns: bool,
    pub verbs: bool,
}

impl WordTypes {
    pub fn all() -> Self {
        Self {
            adjectives: true,
            nouns: true,
            verbs: true,
        }
    }

    pub fn any_selected(&self) -> bool {
        self.adjectives || self.nouns || self.verbs
    }

    pub(crate) fn to_pattern(&self) -> Vec<WordType> {
        let mut pattern = Vec::new();

        if self.adjectives {
            pattern.push(WordType::Adjective);
        }
        if self.nouns {
            pattern.push(WordType::Noun);
        }
        if self.verbs {
            pattern.push(WordType::Verb);
        }

        pattern
    }
}

pub fn get_generator() -> ProductionUsernameGenerator {
    UsernameGenerator::new(rng())
}
