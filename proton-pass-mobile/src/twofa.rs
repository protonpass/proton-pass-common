pub use proton_pass_common::twofa::TwofaDomainChecker as CommonTwofaDomainChecker;

pub struct TwofaDomainChecker;

impl TwofaDomainChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn twofa_domain_eligible(&self, domain: String) -> bool {
        CommonTwofaDomainChecker::twofa_domain_eligible(&domain)
    }
}
