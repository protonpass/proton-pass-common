use proton_pass_common::twofa::TwofaDomainChecker;

#[test]
fn domain_exist_in_set() {
    let manager = TwofaDomainChecker::default();
    let domain = "34SP.com";

    assert!(manager.twofa_domain_eligible(domain))
}

#[test]
fn domain_doesnt_exist_in_set() {
    let manager = TwofaDomainChecker::default();
    let domain = "testNonExistingDomain.com";

    assert!(!manager.twofa_domain_eligible(domain))
}
