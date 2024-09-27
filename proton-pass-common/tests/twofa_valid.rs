use proton_pass_common::twofa::TwofaDomainChecker;

#[test]
fn domain_exist_in_set() {
    let domain = "google.com";

    assert!(TwofaDomainChecker::twofa_domain_eligible(domain));
}

#[test]
fn domain_doesnt_exist_in_set() {
    let domain = "testNonExistingDomain.com";

    assert!(!TwofaDomainChecker::twofa_domain_eligible(domain));
}

#[test]
fn can_match_subdomain() {
    let domain = "test.amazon.com";
    assert!(TwofaDomainChecker::twofa_domain_eligible(domain));
}

#[test]
fn can_match_all_test() {
    let domains = vec![
        "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
        "https://www.amazon.com/",
        "https://amazon.com/",
        "https://www.amazon.com",
        "https://amazon.com",
        "amazon.com",
        "www.amazon.com",
        "amazon.com/some?path=extra",
        "www.amazon.com/some?path=extra"
    ];

    for domain in domains {
        assert!(TwofaDomainChecker::twofa_domain_eligible(domain));
    }
}
