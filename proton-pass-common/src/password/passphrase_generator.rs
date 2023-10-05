use crate::utils::{get_random_index, uppercase_first_letter};
use passwords::PasswordGenerator;
use rand::{thread_rng, Rng};
use std::cmp::max;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
include!(concat!(env!("OUT_DIR"), "/wordlists.rs"));

const MIN_WORD_COUNT: u32 = 1;

#[derive(Debug)]
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
    fn value(&self) -> String {
        match self {
            WordSeparator::Hyphens => "-".to_string(),
            WordSeparator::Spaces => " ".to_string(),
            WordSeparator::Periods => ".".to_string(),
            WordSeparator::Commas => ",".to_string(),
            WordSeparator::Underscores => "_".to_string(),
            WordSeparator::Numbers => PasswordGenerator {
                length: 1,
                numbers: true,
                lowercase_letters: false,
                uppercase_letters: false,
                symbols: false,
                spaces: false,
                exclude_similar_characters: false,
                strict: false,
            }
            .generate_one()
            .unwrap_or("1".to_string()),
            WordSeparator::NumbersAndSymbols => PasswordGenerator {
                length: 1,
                numbers: true,
                lowercase_letters: false,
                uppercase_letters: false,
                symbols: true,
                spaces: false,
                exclude_similar_characters: false,
                strict: false,
            }
            .generate_one()
            .unwrap_or("1".to_string()),
        }
    }
}

#[derive(Debug)]
pub struct PassphraseConfig {
    pub separator: WordSeparator,
    pub capitalise: bool,
    pub include_numbers: bool,
}

impl PassphraseConfig {
    pub fn new(separator: WordSeparator, capitalise: bool, include_numbers: bool) -> Self {
        Self {
            separator,
            capitalise,
            include_numbers,
        }
    }

    pub fn generate(&self, words: Vec<String>) -> String {
        let mut words = if self.capitalise {
            words.iter().map(|w| uppercase_first_letter(w)).collect::<Vec<String>>()
        } else {
            words.clone()
        };

        if self.include_numbers {
            if let Some(index) = get_random_index(&words) {
                let mut rng = rand::thread_rng();
                words[index] += &rng.gen_range(0..=9).to_string();
            }
        }

        let mut passphrase: String = "".to_string();

        for (index, word) in words.iter().enumerate() {
            passphrase += word;
            if index != words.len() - 1 {
                passphrase += &self.separator.value();
            }
        }

        passphrase
    }
}

pub fn random_words(word_count: u32) -> Vec<String> {
    let mut words: Vec<String> = vec![];
    let mut rng = thread_rng();
    let wordlist_len = EFF_LARGE_WORDLIST.len();
    for _i in 0..max(MIN_WORD_COUNT, word_count) {
        let random = EFF_LARGE_WORDLIST[rng.gen_range(0..wordlist_len)];
        words.push(random.to_string());
    }
    words
}
