use proton_pass_common::password::{check_score, PasswordScore};

macro_rules! score_test {
    ($($name:ident: $value:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (input, expected) = $value;
            let score = check_score(input);
            assert_eq!(
                score.password_score, expected,
               "{} expected to be {:?} but was {:?} with score {} and penalties {:?}",
                input, expected, &score.password_score, &score.numeric_score, &score.penalties
            );
        }
    )*
    }
}

score_test! {
    word1: ( "Correct", PasswordScore::Vulnerable),
    word1n: ( "Correct4", PasswordScore::Vulnerable),
    word1s: ( "Correct3-", PasswordScore::Vulnerable),
    word2: ( "Correct3-horse", PasswordScore::Vulnerable),
    word2sn: ( "Correct3-horse@", PasswordScore::Vulnerable),
    word3nn: ( "Correct3-horse@Battery8", PasswordScore::Weak),
    word3n: ( "Correct3horse3Battery8", PasswordScore::Weak),
    word3sn: ( "Correct3-horse@Battery8.", PasswordScore::Weak),
    word4sn: ( "Correct3-horse@Battery8.staple8_", PasswordScore::Strong),
    word5: ( "Correct3-horse@Battery8.staple8_Moon", PasswordScore::Strong),
}

score_test! {
    empty: ("", PasswordScore::Vulnerable),
    one_char: ("a", PasswordScore::Vulnerable),
    short_lower: ("abcde", PasswordScore::Vulnerable),
    lower_upper_num_9:("abcABC123" , PasswordScore::Vulnerable),
    lower_upper_num_12:("abcABC123pqj", PasswordScore::Vulnerable),

    lower_upper_num_sym_9: ("azK@BC123" , PasswordScore::Vulnerable),
    lower_upper_num_sym_12: ("azK@BC123pqj", PasswordScore::Weak),

    lower_num_16: ("apjq4n9b2kb2jhgj",PasswordScore::Vulnerable),
    num_16: ("1847382519758729" , PasswordScore::Vulnerable),
    lower_16: ("apqkfjwuiwjkersg", PasswordScore::Vulnerable),
    upper_16: ("EFGUSHWEFUIAJKBE", PasswordScore::Vulnerable),

    lower_upper_16: ("apJEhqCIkeVJpUhA", PasswordScore::Weak),
    lower_upper_17: ("apJEhqCIkeVJpUhAr", PasswordScore::Strong),

    lower_num_20: ("apjq4n9b2kb2jhgjo1nd", PasswordScore::Strong),
    num_20: ("34976128647294268053", PasswordScore::Strong),
    lower_20: ("apqkfjwuiwjkersgyuih", PasswordScore::Strong),
    upper_20: ("EFGUSHWEFUIAJKBERNJS", PasswordScore::Strong),

    sym_5: ("_:^¿", PasswordScore::Vulnerable),
    sym_12: ("_:^¿=($#-@+/" , PasswordScore::Weak),
    sym_20: ("_:^¿=($#-@+/*-%)$!?-", PasswordScore::Strong),

    wordlist_01 : ("Qwerty12345678", PasswordScore::Vulnerable),
    wordlist_02 : ("Zsfghj9128734", PasswordScore::Weak),
}
