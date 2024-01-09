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
        // Short passwords
        "" => PasswordScore::Vulnerable,
        "a" => PasswordScore::Vulnerable,
        "abcde" => PasswordScore::Vulnerable,

        "abcABC123" => PasswordScore::Vulnerable, // Lowercase, Uppercase and numbers (9)
        "abcABC123pqj" => PasswordScore::Vulnerable, // Lowercase, Uppercase and numbers (12)

        "azK@BC123" => PasswordScore::Vulnerable, // Lowercase, Uppercase, numbers and symbol (9)
        "azK@BC123pqj" => PasswordScore::Weak, // Lowercase, Uppercase, numbers and symbol (12)

        "apjq4n9b2kb2jhgj" => PasswordScore::Vulnerable, // only lowercase and numbers and mildly long (16)
        "1847382519758729" => PasswordScore::Vulnerable, // only numbers and mildly long (16)
        "apqkfjwuiwjkersg" => PasswordScore::Vulnerable, // only lowercase and mildly long (16)
        "EFGUSHWEFUIAJKBE" => PasswordScore::Vulnerable, // only uppercase and mildly long (16)

        "apJEhqCIkeVJpUhA" => PasswordScore::Weak, // only lowercase and uppercase and mildly long (16)
        "apJEhqCIkeVJpUhAr" => PasswordScore::Strong, // only lowercase and uppercase (17)

        "apjq4n9b2kb2jhgjo1nd" => PasswordScore::Strong, // only lowercase and numbers but very long (20)
        "34976128647294268053" => PasswordScore::Strong, // only numbers but very long (20)
        "apqkfjwuiwjkersgyuih" => PasswordScore::Strong, // only lowercase but very long (20)
        "EFGUSHWEFUIAJKBERNJS" => PasswordScore::Strong, // only uppercase but very long (20)

        "_:^¿" => PasswordScore::Vulnerable, // only symbols - short(5)
        "_:^¿=($#-@+/" => PasswordScore::Weak, // only symbols - medium(12)
        "_:^¿=($#-@+/*-%)$!?-" => PasswordScore::Strong, // only symbols but long (20)

        // Appears in a common password list
        "Qwerty12345678" => PasswordScore::Vulnerable,
        "Zsfghj9128734" => PasswordScore::Weak,
    );

    for (input, expected) in cases {
        let score = check_score(input);
        let password_score = score.password_score;
        assert_eq!(
            password_score, expected,
            "{} expected to be {:?} but was {:?}",
            input, expected, password_score
        );
    }
}
