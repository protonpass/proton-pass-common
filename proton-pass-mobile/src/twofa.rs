pub use proton_pass_common::twofa::TwofaDomainCheck as CommonTwofaDomainCheck;

pub struct TwofaDomainCheck {
    inner: CommonTwofaDomainCheck,
}

impl TwofaDomainCheck {
    pub fn new() -> Self {
        Self {
            inner: CommonCreditCardDetector::default()
        }
    }

    pub fn twofa_domain_eligible(&self, domain: String) -> Result<(), LoginError> {
        self.inner.twofa_domain_eligible(&domain)
    }
}