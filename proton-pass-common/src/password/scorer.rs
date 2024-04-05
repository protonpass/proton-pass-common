use passwords::analyzer::analyze;
use regex::Regex;

include!(concat!(env!("OUT_DIR"), "/common_passwords.rs"));

const SEPARATOR_SYMBOLS: &str = "[-,._@ ]";

lazy_static::lazy_static! {
    static ref WORDLIST_PASSPRHASE_REGEX : Regex = build_passphrase_regex();
    static ref WORDLIST_PASSPHRASE_SEPARATOR_REGEX : Regex = build_passphrase_separator_regex();
}

fn build_passphrase_regex() -> Regex {
    let separator = format!("(?:\\d|{}|\\d{})", SEPARATOR_SYMBOLS, SEPARATOR_SYMBOLS);
    let regex_str = format!("^([A-Z]?[a-z]{{1,9}}{})+$", separator);
    Regex::new(&regex_str).unwrap()
}

fn build_passphrase_separator_regex() -> Regex {
    let separator_regex = format!("(?:\\d|{}|\\d{})", SEPARATOR_SYMBOLS, SEPARATOR_SYMBOLS);
    Regex::new(&separator_regex).unwrap()
}

const VULNERABLE_MAX_SCORE: f64 = 60.;
const WEAK_MAX_SCORE: f64 = 90.;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordScore {
    Vulnerable,
    Weak,
    Strong,
}

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

#[derive(Clone, Debug, PartialEq)]
pub struct PasswordScoreResult {
    pub numeric_score: f64,
    pub password_score: PasswordScore,
    pub penalties: Vec<PasswordPenalty>,
}

fn score_password(password: &str) -> (f64, Vec<PasswordPenalty>) {
    let analyzed_password = analyze(password);
    let max_score = match analyzed_password.length() - analyzed_password.other_characters_count() {
        0 => 0f64,
        1 => 2f64,
        2 => 5f64,
        3 => 9f64,
        4 => 16f64,
        5 => 24f64,
        6 => 30f64,
        7 => 45f64,
        8 => 51f64,
        9 => 60f64,
        10 => 69f64,
        11 => 75f64,
        12 => 80f64,
        13 => 86f64,
        14 => 91f64,
        15 => 95f64,
        16 => 100f64,
        _ => return (100f64, vec![]),
    };

    let mut penalties = vec![];
    let mut score = max_score;

    if score > 0f64 {
        if analyzed_password.spaces_count() >= 1 {
            score += analyzed_password.spaces_count() as f64;
        }

        if analyzed_password.numbers_count() == 0 {
            score -= max_score * 0.05;
            penalties.push(PasswordPenalty::NoNumbers);
        }

        if analyzed_password.lowercase_letters_count() == 0 {
            score -= max_score * 0.1;
            penalties.push(PasswordPenalty::NoLowercase);
        }
        if analyzed_password.uppercase_letters_count() == 0 {
            score -= max_score * 0.1;
            penalties.push(PasswordPenalty::NoUppercase);
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
            penalties.push(PasswordPenalty::NoSymbols);
        }

        let is_considered_strong = match analyzed_password.length() {
            s if (0..13).contains(&s) => {
                penalties.push(PasswordPenalty::Short);
                false
            }
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
            penalties.push(PasswordPenalty::Consecutive);
        }

        if analyzed_password.progressive_count() > 0 {
            score -=
                max_score * (analyzed_password.progressive_count() as f64 / analyzed_password.length() as f64 / 5f64);
            penalties.push(PasswordPenalty::Progressive);
        }

        score -=
            max_score * (analyzed_password.non_consecutive_count() as f64 / analyzed_password.length() as f64 / 10f64);
    }

    score = score.clamp(0f64, max_score);

    score += analyzed_password.other_characters_count() as f64 * 20f64;

    if score > 100f64 {
        score = 100f64;
    }

    (score, penalties)
}

fn password_without_common(password: &str) -> (String, bool) {
    let password_as_lowercase = password.to_lowercase();
    for common_password in COMMON_PASSWORDS {
        if password_as_lowercase.contains(common_password) {
            // Create a case-insensitive regex pattern
            let pattern = match Regex::new(&format!("(?i){}", common_password)) {
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

    let (score, scoring_penalties) = score_password(&password_without_common);
    penalties.extend(scoring_penalties);

    let final_score = if WORDLIST_PASSPRHASE_REGEX.is_match(password) {
        let groups = WORDLIST_PASSPHRASE_SEPARATOR_REGEX.split(password);
        let clean_groups: Vec<&str> = groups.filter(|str| !str.is_empty()).collect();
        match clean_groups.len() {
            1 | 2 => {
                penalties.push(PasswordPenalty::ShortWordList);
                score.min(VULNERABLE_MAX_SCORE - 1.)
            }
            3 | 4 => {
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
