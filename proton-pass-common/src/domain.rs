use public_suffix::{EffectiveTLDProvider, Error, DEFAULT_PROVIDER};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum GetRootDomainError {
    CannotGetDomain,
    EmptyLabel,
    InvalidPublicSuffix,
}

pub fn get_root_domain(input: &str) -> Result<String, GetRootDomainError> {
    match DEFAULT_PROVIDER.effective_tld_plus_one(input) {
        Ok(d) => Ok(d.to_string()),
        Err(e) => {
            println!("innser: {:?}", e);
            match e {
                Error::CannotDeriveETldPlus1 => Err(GetRootDomainError::CannotGetDomain),
                Error::EmptyLabel => Err(GetRootDomainError::EmptyLabel),
                Error::InvalidPublicSuffix => Err(GetRootDomainError::InvalidPublicSuffix),
                _ => Err(GetRootDomainError::CannotGetDomain),
            }
        }
    }
}
