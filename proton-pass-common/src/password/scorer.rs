use crate::password::scorer::PasswordScore::{
    Dangerous, Good, Invulnerable, Strong, VeryDangerous, VeryStrong, VeryWeak, Weak,
};
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
        s if (0.0..20.0).contains(&s) => VeryDangerous,
        s if (20.0..40.0).contains(&s) => Dangerous,
        s if (40.0..60.0).contains(&s) => VeryWeak,
        s if (60.0..80.0).contains(&s) => Weak,
        s if (80.0..90.0).contains(&s) => Good,
        s if (90.0..95.0).contains(&s) => Strong,
        s if (95.0..99.0).contains(&s) => VeryStrong,
        _ => Invulnerable,
    }
}

#[cfg(test)]
mod test {
    use crate::password::scorer::password_score;
    use crate::password::scorer::PasswordScore::{
        Dangerous, Good, Invulnerable, Strong, VeryDangerous, VeryStrong, VeryWeak, Weak,
    };

    #[test]
    fn score() {
        assert_eq!(password_score(0.0), VeryDangerous);
        assert_eq!(password_score(10.5), VeryDangerous);
        assert_eq!(password_score(19.9), VeryDangerous);

        assert_eq!(password_score(20.0), Dangerous);
        assert_eq!(password_score(30.1), Dangerous);
        assert_eq!(password_score(39.9), Dangerous);

        assert_eq!(password_score(40.0), VeryWeak);
        assert_eq!(password_score(50.8), VeryWeak);
        assert_eq!(password_score(59.9), VeryWeak);

        assert_eq!(password_score(60.0), Weak);
        assert_eq!(password_score(70.7), Weak);
        assert_eq!(password_score(79.9), Weak);

        assert_eq!(password_score(80.0), Good);
        assert_eq!(password_score(81.3), Good);
        assert_eq!(password_score(89.9), Good);

        assert_eq!(password_score(90.0), Strong);
        assert_eq!(password_score(91.2), Strong);
        assert_eq!(password_score(94.9), Strong);

        assert_eq!(password_score(95.0), VeryStrong);
        assert_eq!(password_score(97.2), VeryStrong);
        assert_eq!(password_score(98.9), VeryStrong);

        assert_eq!(password_score(99.0), Invulnerable);
        assert_eq!(password_score(99.2), Invulnerable);
        assert_eq!(password_score(100.0), Invulnerable);
    }
}
