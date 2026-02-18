use super::{PassphraseConfig, PasswordGeneratorError, RandomPasswordConfig, WordSeparator};
use crate::string_modifiers;
use rand::Rng;

include!(concat!(env!("OUT_DIR"), "/wordlists.rs"));

const LOWERCASE_LETTERS: &str = "abcdefghjkmnpqrstuvwxyz";
const CAPITAL_LETTERS: &str = "ABCDEFGHJKMNPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*";

type Result<T> = std::result::Result<T, PasswordGeneratorError>;

pub struct PasswordGenerator<T>
where
    T: Rng,
{
    rng: T,
}

impl<T> PasswordGenerator<T>
where
    T: Rng,
{
    pub fn new(rng: T) -> Self {
        Self { rng }
    }

    pub fn random_words(&mut self, count: usize) -> Result<Vec<String>> {
        let mut res = Vec::new();

        for _ in 0..count {
            res.push(self.get_word()?);
        }

        Ok(res)
    }

    pub fn generate_passphrase_from_words(&mut self, words: Vec<String>, spec: &PassphraseConfig) -> Result<String> {
        let mut res = String::new();

        for (idx, word) in words.into_iter().enumerate() {
            if idx > 0 {
                let separator = string_modifiers::get_separator(&mut self.rng, &spec.separator);
                res.push_str(&separator);
            }

            let word = if spec.capitalise {
                string_modifiers::capitalize(word)
            } else {
                word
            };
            res.push_str(&word);

            if spec.include_numbers {
                let number = self.get_char(NUMBERS)?;
                res.push(number);
            }
        }

        Ok(res)
    }

    pub fn generate_random(&mut self, spec: &RandomPasswordConfig) -> Result<String> {
        if spec.length == 0 {
            return Ok("".to_string());
        }

        let dictionary = get_dictionary(spec);
        match spec.length {
            // We don't allow to generate passwords with less than 3, so we will just do a
            // best-effort policy here
            1..=3 => {
                let mut password = String::new();
                for _ in 0..spec.length {
                    password.push(self.get_char(&dictionary)?);
                }
                Ok(password)
            }
            _ => {
                let mut password = String::new();
                for _ in 0..spec.length - 3 {
                    password.push(self.get_char(&dictionary)?);
                }

                if spec.uppercase_letters && !contains_capital_letters(&password) {
                    password.push(self.get_char(CAPITAL_LETTERS)?);
                } else {
                    password.push(self.get_char(&dictionary)?);
                }

                if spec.numbers && !contains_numbers(&password) {
                    password.push(self.get_char(NUMBERS)?);
                } else {
                    password.push(self.get_char(&dictionary)?);
                }

                if spec.symbols && !contains_symbols(&password) {
                    password.push(self.get_char(SYMBOLS)?);
                } else {
                    password.push(self.get_char(&dictionary)?);
                }

                Ok(password)
            }
        }
    }

    pub fn generate_passphrase(&mut self, spec: &PassphraseConfig) -> Result<String> {
        if spec.count == 0 {
            return Ok("".to_string());
        }

        let mut words = Vec::new();
        for _ in 0..spec.count {
            let word = self.get_word()?;
            let word = if spec.capitalise {
                string_modifiers::capitalize(word)
            } else {
                word
            };

            let word = if spec.include_numbers {
                let number = self.rng.random_range(0..=9);
                format!("{word}{number}")
            } else {
                word
            };

            words.push(word);
        }

        self.join_with_separator(words, &spec.separator)
    }

    fn get_char(&mut self, dictionary: &str) -> Result<char> {
        let range = 0..dictionary.len();
        let idx = self.rng.random_range(range);
        let char: char = dictionary
            .chars()
            .nth(idx)
            .ok_or_else(|| PasswordGeneratorError::FailToGenerate("Could not get char from dictionary".to_string()))?;
        Ok(char)
    }

    fn get_word(&mut self) -> Result<String> {
        let range = 0..EFF_LARGE_WORDLIST.len();
        let idx = self.rng.random_range(range);
        let word = EFF_LARGE_WORDLIST
            .get(idx)
            .ok_or_else(|| PasswordGeneratorError::FailToGenerate("Could not get word from wordlist".to_string()))?;
        Ok(word.to_string())
    }

    fn join_with_separator(&mut self, words: Vec<String>, separator: &WordSeparator) -> Result<String> {
        let mut res = String::new();
        for (idx, word) in words.into_iter().enumerate() {
            if idx == 0 {
                res.push_str(&word);
            } else {
                let separator = string_modifiers::get_separator(&mut self.rng, separator);
                res.push_str(&separator);
                res.push_str(&word);
            }
        }
        Ok(res)
    }
}

fn contains_capital_letters(haystack: &str) -> bool {
    contains_list(CAPITAL_LETTERS, haystack)
}

fn contains_numbers(haystack: &str) -> bool {
    contains_list(NUMBERS, haystack)
}

fn contains_symbols(haystack: &str) -> bool {
    contains_list(SYMBOLS, haystack)
}

fn contains_list(list: &str, haystack: &str) -> bool {
    haystack.chars().any(|c| list.contains(c))
}

fn get_dictionary(spec: &RandomPasswordConfig) -> String {
    let mut dict = LOWERCASE_LETTERS.to_string();
    if spec.uppercase_letters {
        dict.push_str(CAPITAL_LETTERS);
    }
    if spec.numbers {
        dict.push_str(NUMBERS);
    }
    if spec.symbols {
        dict.push_str(SYMBOLS);
    }
    dict
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    const SEED: u64 = 7539514682;

    fn seeded_rng() -> impl Rng {
        StdRng::seed_from_u64(SEED)
    }

    mod random {
        use super::*;

        #[test]
        fn generate_empty_password() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 0,
                    numbers: false,
                    uppercase_letters: false,
                    symbols: false,
                })
                .unwrap();
            assert!(res.is_empty());
        }

        #[test]
        fn generate_password_with_numbers() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 5,
                    numbers: true,
                    uppercase_letters: false,
                    symbols: false,
                })
                .unwrap();

            assert_eq!("91d8n", res);
        }

        #[test]
        fn generate_password_with_uppercase() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 5,
                    numbers: false,
                    uppercase_letters: true,
                    symbols: false,
                })
                .unwrap();

            assert_eq!("ZMeXt", res);
        }

        #[test]
        fn generate_password_with_symbols() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 5,
                    numbers: false,
                    uppercase_letters: false,
                    symbols: true,
                })
                .unwrap();

            assert_eq!("*zd&n", res);
        }

        #[test]
        fn generate_password_with_all() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 5,
                    numbers: true,
                    uppercase_letters: true,
                    symbols: true,
                })
                .unwrap();

            assert_eq!("*0C%z", res);
        }

        #[test]
        fn generate_password_with_length_4_contains_everything() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_random(&RandomPasswordConfig {
                    length: 4,
                    numbers: true,
                    uppercase_letters: true,
                    symbols: true,
                })
                .unwrap();

            assert_eq!("*T0%", res);
        }
    }

    mod passphrase {
        use super::*;

        #[test]
        fn generate_empty_passphrase() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase(&PassphraseConfig {
                    separator: WordSeparator::Hyphens,
                    capitalise: false,
                    include_numbers: false,
                    count: 0,
                })
                .unwrap();
            assert!(res.is_empty());
        }

        #[test]
        fn generate_one_word_contains_no_separator() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase(&PassphraseConfig {
                    separator: WordSeparator::Hyphens,
                    capitalise: false,
                    include_numbers: false,
                    count: 1,
                })
                .unwrap();
            assert_eq!("wireless", res);
        }

        #[test]
        fn generate_two_word_contains_separator() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase(&PassphraseConfig {
                    separator: WordSeparator::Hyphens,
                    capitalise: false,
                    include_numbers: false,
                    count: 2,
                })
                .unwrap();
            assert_eq!("wireless-scrambled", res);
        }

        #[test]
        fn capitalise() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase(&PassphraseConfig {
                    separator: WordSeparator::Hyphens,
                    capitalise: true,
                    include_numbers: false,
                    count: 2,
                })
                .unwrap();
            assert_eq!("Wireless-Scrambled", res);
        }

        #[test]
        fn include_numbers() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase(&PassphraseConfig {
                    separator: WordSeparator::Hyphens,
                    capitalise: true,
                    include_numbers: true,
                    count: 2,
                })
                .unwrap();
            assert_eq!("Wireless7-Bungee9", res);
        }
    }

    mod passphrase_from_words {
        use super::*;

        #[test]
        fn with_empty_vec() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let res = generator
                .generate_passphrase_from_words(
                    vec![],
                    &PassphraseConfig {
                        separator: WordSeparator::Hyphens,
                        capitalise: false,
                        include_numbers: false,
                        count: 0,
                    },
                )
                .unwrap();
            assert!(res.is_empty());
        }

        #[test]
        fn respects_word_order() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let word_1 = "lorem";
            let word_2 = "ipsum";
            let word_3 = "dolor";
            let words = vec![word_1.to_string(), word_2.to_string(), word_3.to_string()];
            let res = generator
                .generate_passphrase_from_words(
                    words,
                    &PassphraseConfig {
                        separator: WordSeparator::Hyphens,
                        capitalise: false,
                        include_numbers: false,
                        count: 0,
                    },
                )
                .unwrap();

            assert_eq!("lorem-ipsum-dolor", res);
        }

        #[test]
        fn respects_word_separator() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let word_1 = "lorem";
            let word_2 = "ipsum";
            let word_3 = "dolor";
            let words = vec![word_1.to_string(), word_2.to_string(), word_3.to_string()];
            let res = generator
                .generate_passphrase_from_words(
                    words,
                    &PassphraseConfig {
                        separator: WordSeparator::Underscores,
                        capitalise: false,
                        include_numbers: false,
                        count: 0,
                    },
                )
                .unwrap();

            assert_eq!("lorem_ipsum_dolor", res);
        }

        #[test]
        fn respects_add_number() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let word_1 = "lorem";
            let word_2 = "ipsum";
            let word_3 = "dolor";
            let words = vec![word_1.to_string(), word_2.to_string(), word_3.to_string()];
            let res = generator
                .generate_passphrase_from_words(
                    words,
                    &PassphraseConfig {
                        separator: WordSeparator::Underscores,
                        capitalise: false,
                        include_numbers: true,
                        count: 0,
                    },
                )
                .unwrap();

            assert_eq!("lorem9_ipsum7_dolor0", res);
        }

        #[test]
        fn respects_capitalise() {
            let mut generator = PasswordGenerator::new(seeded_rng());
            let word_1 = "lorem";
            let word_2 = "ipsum";
            let word_3 = "dolor";
            let words = vec![word_1.to_string(), word_2.to_string(), word_3.to_string()];
            let res = generator
                .generate_passphrase_from_words(
                    words,
                    &PassphraseConfig {
                        separator: WordSeparator::Underscores,
                        capitalise: true,
                        include_numbers: false,
                        count: 0,
                    },
                )
                .unwrap();

            assert_eq!("Lorem_Ipsum_Dolor", res);
        }
    }
}
