use passwords::analyzer::analyze;

include!(concat!(env!("OUT_DIR"), "/common_passwords.rs"));

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordScore {
    Vulnerable,
    Weak,
    Strong,
}

fn score_password(password: &str) -> f64 {
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
        _ => (100 + analyzed_password.length() - 16) as f64,
    };

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
        score -= max_score * (analyzed_password.consecutive_count() as f64 / analyzed_password.length() as f64 / 5f64);

        score -= max_score * (analyzed_password.progressive_count() as f64 / analyzed_password.length() as f64 / 5f64);

        score -=
            max_score * (analyzed_password.non_consecutive_count() as f64 / analyzed_password.length() as f64 / 10f64);
    }

    score = score.clamp(0f64, max_score);

    score += analyzed_password.other_characters_count() as f64 * 20f64;

    if score > 100f64 {
        score = 100f64;
    }

    score
}

fn password_without_common(password: &str) -> String {
    let password_as_lowercase = password.to_lowercase();
    for common_password in COMMON_PASSWORDS {
        if password_as_lowercase.contains(common_password) {
            // Create a case-insensitive regex pattern
            let pattern = match regex::Regex::new(&format!("(?i){}", common_password)) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Use the replace method to perform case-insensitive replacement
            let result = pattern.replace_all(password, "");
            return result.to_string();
        }
    }

    password.to_string()
}

pub fn numeric_score(password: &str) -> f64 {
    let password_without_common = password_without_common(password);
    score_password(&password_without_common)
}

pub fn check_score(password: &str) -> PasswordScore {
    password_score(numeric_score(password))
}

pub fn password_score(score: f64) -> PasswordScore {
    match score {
        s if s <= 60.0 => PasswordScore::Vulnerable,
        s if (60.0..90.0).contains(&s) => PasswordScore::Weak,
        _ => PasswordScore::Strong,
    }
}
