use super::analyzer::analyze;
#[cfg(feature = "wasm")]
use proton_pass_derive::ffi_type;
use regex_lite::Regex;

include!(concat!(env!("OUT_DIR"), "/common_passwords.rs"));

const SEPARATOR_SYMBOLS: &str = "[-,._@ ]";

lazy_static::lazy_static! {
    static ref WORDLIST_PASSPRHASE_REGEX : Regex = build_passphrase_regex();
    static ref WORDLIST_PASSPHRASE_SEPARATOR_REGEX : Regex = build_passphrase_separator_regex();
}

fn build_passphrase_regex() -> Regex {
    let separator = format!("(?:\\d|{SEPARATOR_SYMBOLS}|\\d{SEPARATOR_SYMBOLS})");
    let regex_str = format!("^([A-Z]?[a-z]{{1,9}}{separator})+([A-Z]?[a-z]{{1,9}})?$");
    Regex::new(&regex_str).unwrap()
}

fn build_passphrase_separator_regex() -> Regex {
    let separator_regex = format!("(?:\\d|{SEPARATOR_SYMBOLS}|\\d{SEPARATOR_SYMBOLS})");
    Regex::new(&separator_regex).unwrap()
}

const VULNERABLE_MAX_SCORE: f64 = 60.;
const WEAK_MAX_SCORE: f64 = 90.;

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordScore {
    Vulnerable,
    Weak,
    Strong,
}

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[cfg_attr(feature = "wasm", ffi_type)]
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordScoreResult {
    pub numeric_score: f64,
    pub password_score: PasswordScore,
    pub penalties: Vec<PasswordPenalty>,
}

fn score_password(password: &str) -> f64 {
    let analyzed_password = analyze(password);
    let length_minus_other_chars = analyzed_password.length() - analyzed_password.other_characters_count();
    let (max_score, return_original_score) = match length_minus_other_chars {
        0 => (0f64, false),
        1 => (2f64, false),
        2 => (5f64, false),
        3 => (9f64, false),
        4 => (16f64, false),
        5 => (24f64, false),
        6 => (30f64, false),
        7 => (45f64, false),
        8 => (51f64, false),
        9 => (60f64, false),
        10 => (69f64, false),
        11 => (75f64, false),
        12 => (80f64, false),
        13 => (86f64, false),
        14 => (91f64, false),
        15 => (95f64, false),
        16 => (100f64, false),
        _ => (100f64, true),
    };

    let initial_max_score = max_score;

    let mut score = max_score;

    if score > 0f64 {
        if analyzed_password.spaces_count() >= 1 {
            score += analyzed_password.spaces_count() as f64;
        }

        if analyzed_password.numbers_count() == 0 {
            score -= max_score * 0.05;
        }

        if analyzed_password.lowercase_letters_count() == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.uppercase_letters_count() == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.lowercase_letters_count() >= 1 && analyzed_password.uppercase_letters_count() >= 1 {
            score += 1f64;
        }
        if analyzed_password.symbols_count() >= 1 {
            score += 1f64;
        }

        // Penalties
        if analyzed_password.symbols_count() == 0 {
            score -= max_score * 0.2;
        }

        let is_considered_strong = match analyzed_password.length() {
            s if (0..13).contains(&s) => false,
            s if (13..20).contains(&s) => analyzed_password.symbols_count() > 0,
            _ => true,
        };

        if !is_considered_strong {
            if analyzed_password.numbers_count() == 0 {
                score -= max_score * 0.1;
            }

            if analyzed_password.uppercase_letters_count() == 0 {
                score -= max_score * 0.1;
            }
        }

        // Final adjustments
        if analyzed_password.consecutive_count() > 0 {
            score -=
                max_score * (analyzed_password.consecutive_count() as f64 / analyzed_password.length() as f64 / 5f64);
        }

        if analyzed_password.progressive_count() > 0 {
            score -=
                max_score * (analyzed_password.progressive_count() as f64 / analyzed_password.length() as f64 / 5f64);
        }

        score -=
            max_score * (analyzed_password.non_consecutive_count() as f64 / analyzed_password.length() as f64 / 10f64);
    }

    score = score.clamp(0f64, max_score);

    score += analyzed_password.other_characters_count() as f64 * 20f64;

    if score > 100f64 {
        score = 100f64;
    }

    if return_original_score {
        initial_max_score
    } else {
        score
    }
}

fn penalties_password(password: &str) -> Vec<PasswordPenalty> {
    let analyzed_password = analyze(password);
    let mut penalties = vec![];

    if analyzed_password.numbers_count() == 0 {
        penalties.push(PasswordPenalty::NoNumbers);
    }

    if analyzed_password.lowercase_letters_count() == 0 {
        penalties.push(PasswordPenalty::NoLowercase);
    }
    if analyzed_password.uppercase_letters_count() == 0 {
        penalties.push(PasswordPenalty::NoUppercase);
    }

    // Penalties
    if analyzed_password.symbols_count() == 0 {
        penalties.push(PasswordPenalty::NoSymbols);
    }

    if (0..13).contains(&analyzed_password.length()) {
        penalties.push(PasswordPenalty::Short);
    }

    // Final adjustments
    if analyzed_password.consecutive_count() > 0 {
        penalties.push(PasswordPenalty::Consecutive);
    }

    if analyzed_password.progressive_count() > 0 {
        penalties.push(PasswordPenalty::Progressive);
    }

    penalties
}

fn password_without_common(password: &str) -> (String, bool) {
    let password_as_lowercase = password.to_lowercase();
    for common_password in COMMON_PASSWORDS {
        if password_as_lowercase.contains(common_password) {
            // Create a case-insensitive regex pattern
            let pattern = match Regex::new(&format!("(?i){common_password}")) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Use the replace method to perform case-insensitive replacement
            let result = pattern.replace_all(password, "");
            return (result.to_string(), true);
        }
    }

    (password.to_string(), false)
}

fn inner_score_password(password: &str) -> PasswordScoreResult {
    let (password_without_common, has_replaced) = password_without_common(password);

    let mut penalties = vec![];
    if has_replaced {
        penalties.push(PasswordPenalty::ContainsCommonPassword);
    }

    let score = score_password(&password_without_common);
    let scoring_penalties = penalties_password(password);
    penalties.extend(scoring_penalties);

    let final_score = if WORDLIST_PASSPRHASE_REGEX.is_match(password) {
        let groups = WORDLIST_PASSPHRASE_SEPARATOR_REGEX.split(password);
        let clean_groups: Vec<&str> = groups.filter(|str| !str.is_empty()).collect();
        match clean_groups.len() {
            1 | 2 => {
                penalties.push(PasswordPenalty::ShortWordList);
                score.min(VULNERABLE_MAX_SCORE - 1.)
            }
            3 => {
                penalties.push(PasswordPenalty::ShortWordList);
                score.min(WEAK_MAX_SCORE - 1.)
            }
            _ => score,
        }
    } else {
        score
    };

    PasswordScoreResult {
        numeric_score: final_score,
        password_score: password_score(final_score),
        penalties,
    }
}

pub fn numeric_score(password: &str) -> f64 {
    let score = inner_score_password(password);
    score.numeric_score
}

pub fn check_score(password: &str) -> PasswordScoreResult {
    inner_score_password(password)
}

pub fn password_score(score: f64) -> PasswordScore {
    match score {
        s if s <= VULNERABLE_MAX_SCORE => PasswordScore::Vulnerable,
        s if (VULNERABLE_MAX_SCORE..WEAK_MAX_SCORE).contains(&s) => PasswordScore::Weak,
        _ => PasswordScore::Strong,
    }
}
