use passwords::analyzer::analyze;
use passwords::scorer::score;

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordScore {
    VeryDangerous,
    Dangerous,
    VeryWeak,
    Weak,
    Good,
    Strong,
    VeryStrong,
    Invulnerable,
}
pub fn check_score(password: &str) -> PasswordScore {
    let score = score(&analyze(password));
    password_score(score)
}

fn password_score(score: f64) -> PasswordScore {
    match score {
        s if (0.0..20.0).contains(&s) => PasswordScore::VeryDangerous,
        s if (20.0..40.0).contains(&s) => PasswordScore::Dangerous,
        s if (40.0..60.0).contains(&s) => PasswordScore::VeryWeak,
        s if (60.0..80.0).contains(&s) => PasswordScore::Weak,
        s if (80.0..90.0).contains(&s) => PasswordScore::Good,
        s if (90.0..95.0).contains(&s) => PasswordScore::Strong,
        s if (95.0..99.0).contains(&s) => PasswordScore::VeryStrong,
        _ => PasswordScore::Invulnerable,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn score() {
        assert_eq!(password_score(0.0), PasswordScore::VeryDangerous);
        assert_eq!(password_score(10.5), PasswordScore::VeryDangerous);
        assert_eq!(password_score(19.9), PasswordScore::VeryDangerous);

        assert_eq!(password_score(20.0), PasswordScore::Dangerous);
        assert_eq!(password_score(30.1), PasswordScore::Dangerous);
        assert_eq!(password_score(39.9), PasswordScore::Dangerous);

        assert_eq!(password_score(40.0), PasswordScore::VeryWeak);
        assert_eq!(password_score(50.8), PasswordScore::VeryWeak);
        assert_eq!(password_score(59.9), PasswordScore::VeryWeak);

        assert_eq!(password_score(60.0), PasswordScore::Weak);
        assert_eq!(password_score(70.7), PasswordScore::Weak);
        assert_eq!(password_score(79.9), PasswordScore::Weak);

        assert_eq!(password_score(80.0), PasswordScore::Good);
        assert_eq!(password_score(81.3), PasswordScore::Good);
        assert_eq!(password_score(89.9), PasswordScore::Good);

        assert_eq!(password_score(90.0), PasswordScore::Strong);
        assert_eq!(password_score(91.2), PasswordScore::Strong);
        assert_eq!(password_score(94.9), PasswordScore::Strong);

        assert_eq!(password_score(95.0), PasswordScore::VeryStrong);
        assert_eq!(password_score(97.2), PasswordScore::VeryStrong);
        assert_eq!(password_score(98.9), PasswordScore::VeryStrong);

        assert_eq!(password_score(99.0), PasswordScore::Invulnerable);
        assert_eq!(password_score(99.2), PasswordScore::Invulnerable);
        assert_eq!(password_score(100.0), PasswordScore::Invulnerable);
    }
}
