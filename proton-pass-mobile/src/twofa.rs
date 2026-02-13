use proton_pass_common::twofa::TwofaDomainChecker as CommonTwofaDomainChecker;

#[derive(uniffi::Object)]
pub struct TwofaDomainChecker;

#[uniffi::export]
impl TwofaDomainChecker {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn twofa_domain_eligible(&self, domain: String) -> bool {
        CommonTwofaDomainChecker::twofa_domain_eligible(&domain)
    }
}
