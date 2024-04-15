use proton_pass_common::twofa::TwofaDomainChecker;

#[test]
fn domain_exist_in_set() {
    let domain = "34SP.com";

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
