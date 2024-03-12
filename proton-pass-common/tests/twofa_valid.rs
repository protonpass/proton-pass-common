use proton_pass_common::twofa::TwofaDomainCheck;

#[test]
fn domain_exist_in_set() { 
    let manager = TwofaDomainCheck::new()
    .expect("Could not create domain checker");
    let domain = "34SP.com";

    assert!(manager.twofa_domain_eligible(domain))
}

#[test]
fn domain_doesnt_exist_in_set() { 
    let manager = TwofaDomainCheck::new()
    .expect("Could not create domain checker");
    let domain = "testNonExistingDomain.com";

    assert!(!manager.twofa_domain_eligible(domain))
}