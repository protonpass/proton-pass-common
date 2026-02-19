use crate::string_modifiers;
use crate::username::WordType;

use super::{UsernameGeneratorConfig, UsernameGeneratorError};
use rand::Rng;

// Import username-specific wordlists
include!(concat!(env!("OUT_DIR"), "/username_wordlists.rs"));

type Result<T> = std::result::Result<T, UsernameGeneratorError>;

pub struct UsernameGenerator<T>
where
    T: Rng,
{
    rng: T,
}

impl<T> UsernameGenerator<T>
where
    T: Rng,
{
    pub fn new(rng: T) -> Self {
        Self { rng }
    }

    pub fn generate_username(&mut self, config: &UsernameGeneratorConfig) -> Result<String> {
        if config.word_count == 0 {
            return Ok(String::new());
        }

        if !config.word_types.any_selected() {
            return Err(UsernameGeneratorError::FailToGenerate(
                "At least one word type must be selected".to_string(),
            ));
        }

        let pattern = config.word_types.to_pattern();
        let words: Vec<String> = self.get_words(config.word_count as usize, &pattern)?;

        self.generate_username_from_words(words, config)
    }

    fn generate_username_from_words(&mut self, words: Vec<String>, config: &UsernameGeneratorConfig) -> Result<String> {
        let mut processed_words = Vec::new();
        for word in words {
            let mut processed = word;

            if config.capitalise {
                processed = string_modifiers::capitalize(processed);
            }

            if config.leetspeak {
                processed = string_modifiers::to_leetspeak(processed);
            }

            processed_words.push(processed);
        }

        let mut result = match processed_words.len() {
            0 => String::new(),
            1 => processed_words[0].clone(),
            _ => {
                if let Some(sep_type) = config.separator.as_ref() {
                    let sep = string_modifiers::get_separator(&mut self.rng, sep_type);
                    processed_words.join(&sep)
                } else {
                    processed_words.join("")
                }
            }
        };

        if config.include_numbers {
            let number = self.rng.random_range(0..=9);
            let at_beginning = self.rng.random_range(0..2) == 0;

            if at_beginning {
                result = format!("{}{}", number, result);
            } else {
                result = format!("{}{}", result, number);
            }
        }

        Ok(result)
    }

    fn get_words(&mut self, count: usize, pattern: &[WordType]) -> Result<Vec<String>> {
        let mut words = Vec::new();

        for i in 0..count {
            let word = self.get_word_of_type(pattern[i % pattern.len()])?;
            words.push(word);
        }

        Ok(words)
    }

    fn get_word_of_type(&mut self, word_type: WordType) -> Result<String> {
        let list = match word_type {
            WordType::Adjective => ADJECTIVES_LIST,
            WordType::Noun => NOUNS_LIST,
            WordType::Verb => VERBS_LIST,
        };

        if list.is_empty() {
            return Err(UsernameGeneratorError::FailToGenerate(format!(
                "{:?} wordlist is empty",
                word_type
            )));
        }
        let idx = self.rng.random_range(0..list.len());
        Ok(list[idx].to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::username::{WordSeparator, WordTypes};
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    const SEED: u64 = 12345;

    fn seeded_rng() -> impl Rng {
        StdRng::seed_from_u64(SEED)
    }

    #[test]
    fn generate_simple_username_from_nouns() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 2,
            include_numbers: false,
            capitalise: false,
            separator: None,
            leetspeak: false,
            word_types: WordTypes::all(),
        };

        let result = generator.generate_username(&config).unwrap();

        assert!(!result.is_empty());
        assert!(result.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn generate_username_with_capitalization() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 2,
            include_numbers: false,
            capitalise: true,
            separator: None,
            leetspeak: false,
            word_types: WordTypes::all(),
        };

        let result = generator.generate_username(&config).unwrap();

        assert!(!result.is_empty());
        assert!(result.chars().any(|c| c.is_uppercase()));
    }

    #[test]
    fn generate_empty_username() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 0,
            include_numbers: false,
            capitalise: false,
            separator: None,
            leetspeak: false,
            word_types: WordTypes::all(),
        };

        let result = generator.generate_username(&config).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn generate_username_with_adjective_noun_pattern() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 4,
            include_numbers: false,
            capitalise: false,
            separator: Some(WordSeparator::Hyphens),
            leetspeak: false,
            word_types: WordTypes {
                adjectives: true,
                nouns: true,
                verbs: false,
            },
        };

        let result = generator.generate_username(&config).unwrap();

        assert!(!result.is_empty());
        let word_count = result.split('-').count();
        assert_eq!(word_count, 4);
    }

    #[test]
    fn generate_username_with_leetspeak() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 2,
            include_numbers: false,
            capitalise: false,
            separator: None,
            leetspeak: true,
            word_types: WordTypes::all(),
        };

        let cases = [
            (vec!["leet".to_string()], "l337"),
            (vec!["test".to_string()], "7357"),
            (vec!["awesome".to_string()], "4w350m3"),
            (vec!["zebra".to_string(), "goat".to_string()], "238r46047"),
        ];

        for (words, expected) in cases {
            let result = generator.generate_username_from_words(words, &config).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn generate_username_with_numbers() {
        let mut generator = UsernameGenerator::new(seeded_rng());
        let config = UsernameGeneratorConfig {
            word_count: 2,
            include_numbers: true,
            capitalise: false,
            separator: None,
            leetspeak: false,
            word_types: WordTypes::all(),
        };

        let words = vec!["hello".to_string(), "world".to_string()];
        let result = generator.generate_username_from_words(words, &config).unwrap();

        let first_char = result.chars().next().unwrap();
        let last_char = result.chars().last().unwrap();
        assert!(
            first_char.is_numeric() || last_char.is_numeric(),
            "Expected number at beginning or end, got: {}",
            result
        );
        assert_eq!(result.len(), "helloworld".len() + 1);
    }
}
