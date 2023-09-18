use proton_pass_common::alias_prefix::*;

fn verify(prefix: &str) {
    let result = validate_alias_prefix(prefix);
    if result.is_err() {
        panic!("{} should be valid", prefix);
    }
}
fn verify_error(prefix: &str, expected: AliasPrefixError) {
    let err = validate_alias_prefix(prefix).unwrap_err();
    assert_eq!(expected, err);
}

#[test]
fn valid() {
    verify("abc");
    verify("ab.c");
    verify("a_1-b.c");
}
#[test]
fn empty() {
    verify_error("", AliasPrefixError::PrefixEmpty);
}

#[test]
fn dot_at_the_end() {
    verify_error("a.b.c.", AliasPrefixError::DotAtTheEnd);
}

#[test]
fn too_long() {
    verify_error(
        "abchduwjqkiduthqjcmdutiepqkajcmdhutjfij2",
        AliasPrefixError::PrefixTooLong,
    );
}

#[test]
fn two_consecutive_dots() {
    verify_error("a..b.c", AliasPrefixError::TwoConsecutiveDots);
}

#[test]
fn invalid_character() {
    verify_error("8a^ka", AliasPrefixError::InvalidCharacter);
}
