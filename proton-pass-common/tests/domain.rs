use proton_pass_common::domain::{get_domain, get_root_domain, GetRootDomainError};

#[macro_export]
macro_rules! map (
    {$($key:expr => $value:expr), + } => {
        {
            let mut m = std::collections::HashMap::new();
            $(
                m.insert($key, $value);
             )+
            m
        }
    };
);

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
    assert_eq!(input, res);
}

#[test]
fn can_extract_root_domain_without_path() {
    let input = "https://test.some.subdomain.proton.me/path?key=value";
    let res = get_root_domain(input).expect("should be able to extract domain");
    assert_eq!("proton.me", res);
}

#[test]
fn can_extract_domain() {
    let cases = map!(
        "proton.me" => "proton.me",
        "www.proton.me" => "www.proton.me",
        "https://proton.me" => "proton.me",
        "https://www.proton.me" => "www.proton.me",
        "https://some.random.domain.proton.me" => "some.random.domain.proton.me",
        "proton.me/path?key=value" => "proton.me",
        "random.domain.proton.me/path?key=value" => "random.domain.proton.me"
    );

    for (case, expected) in cases {
        let res = get_domain(case).unwrap_or_else(|e| panic!("should be able to get domain for {case}: {:?}", e));
        assert_eq!(expected, res, "expected {expected} got {res}");
    }
}
