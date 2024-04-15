use proton_pass_common::domain::{get_root_domain, GetRootDomainError};

#[test]
fn can_extract_root_domain() {
    let input = "test.proton.me";
    let res = get_root_domain(input).expect("should be able to extract domain");
    assert_eq!("proton.me", res);
}

#[test]
fn can_extract_root_domain_from_url() {
    let input = "https://test.proton.me";
    let res = get_root_domain(input).expect("should be able to extract domain");
    assert_eq!("proton.me", res);
}

#[test]
fn returns_error_on_empty_string() {
    let err = get_root_domain("").expect_err("should return an error");
    assert!(matches!(err, GetRootDomainError::CannotGetDomain));
}

#[test]
fn does_not_return_error_on_unknown_tld() {
    let input = "random.abcdefghijkl";
    let res = get_root_domain(input).expect("sohuld not return an error");
    assert_eq!(res, input);
}
