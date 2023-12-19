use passwords::analyzer::analyze;
use passwords::scorer::score;

include!(concat!(env!("OUT_DIR"), "/common_passwords.rs"));

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordScore {
    Weak,
    Strong,
    Invulnerable,
}

fn is_common(password: &str) -> bool {
    let password_as_lower = password.to_lowercase();
    COMMON_PASSWORDS
        .iter()
        .any(|common_password| password_as_lower.contains(common_password))
}

pub fn numeric_score(password: &str) -> f64 {
    let mut score = score(&analyze(password));
    if is_common(password) {
        score /= 5f64
    }

    score
}

pub fn check_score(password: &str) -> PasswordScore {
    password_score(numeric_score(password))
}

fn password_score(score: f64) -> PasswordScore {
    match score {
        s if (0.0..80.0).contains(&s) => PasswordScore::Weak,
        s if (80.0..92.0).contains(&s) => PasswordScore::Strong,
        s if (92.0..99.0).contains(&s) => PasswordScore::Invulnerable,
        _ => PasswordScore::Invulnerable,
    }
}
