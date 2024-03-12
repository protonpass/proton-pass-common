pub use proton_pass_common::twofa::TwofaDomainCheck as CommonTwofaDomainCheck;

pub struct TwofaDomainCheck {
    inner: CommonTwofaDomainCheck,
}

impl TwofaDomainCheck {
    pub fn new() -> Self {
        Self {
            inner: CommonTwofaDomainCheck::new().expect("Failed to initialize CommonTwofaDomainCheck"),
        }
    }

    pub fn twofa_domain_eligible(&self, domain: String) -> bool {
        self.inner.twofa_domain_eligible(&domain)
    }
}
