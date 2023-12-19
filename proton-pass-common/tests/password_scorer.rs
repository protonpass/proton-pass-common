use proton_pass_common::password::{check_score, PasswordScore};

#[macro_export]
macro_rules! map {
    { $($key:expr => $value:expr),+, } => {
        {
            use std::collections::HashMap;
            let mut m = HashMap::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
    };
}

#[test]
fn score_passwords() {
    let cases = map!(
        "" => PasswordScore::Weak,
        "a" => PasswordScore::Weak,
        "abcde" => PasswordScore::Weak,
        "abcABC123" => PasswordScore::Weak,
        "azK@BC123" => PasswordScore::Weak,

        "ajqu(y%L_12Fe" => PasswordScore::Invulnerable,

        // Appears in a common password list
        "Qwerty12345678" => PasswordScore::Weak,
        "Zsfghj9128734" => PasswordScore::Strong,
    );

    for (input, expected) in cases {
        let score = check_score(input);
        assert_eq!(
            score, expected,
            "{} expected to be {:?} but was {:?}",
            input, expected, score
        );
    }
}
