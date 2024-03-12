pub use proton_pass_common::twofa::TwofaDomainChecker as CommonTwofaDomainChecker;

pub struct TwofaDomainChecker {
    inner: CommonTwofaDomainChecker,
}

impl TwofaDomainChecker {
    pub fn new() -> Self {
        Self {
            inner: CommonTwofaDomainChecker::default(),
        }
    }

    pub fn twofa_domain_eligible(&self, domain: String) -> bool {
        self.inner.twofa_domain_eligible(&domain)
    }
}
