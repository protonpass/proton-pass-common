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
        "" => PasswordScore::Vulnerable,
        "a" => PasswordScore::Vulnerable,
        "abcde" => PasswordScore::Vulnerable,
        "abcABC123" => PasswordScore::Vulnerable,
        "azK@BC123" => PasswordScore::Vulnerable,

        // Appears in a common password list
        "Qwerty12345678" => PasswordScore::Vulnerable,
        "Zsfghj9128734" => PasswordScore::Weak,
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
