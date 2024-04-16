use public_suffix::{EffectiveTLDProvider, Error, DEFAULT_PROVIDER};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum GetRootDomainError {
    CannotGetDomain,
    EmptyLabel,
    InvalidPublicSuffix,
}

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum GetDomainError {
    ParseError,
    UrlHasNoDomain,
}

pub fn get_domain(input: &str) -> Result<String, GetDomainError> {
    match url::Url::parse(input) {
        Ok(u) => match u.domain() {
            Some(d) => Ok(d.to_string()),
            None => Err(GetDomainError::UrlHasNoDomain),
        },
        Err(e) => match e {
            url::ParseError::RelativeUrlWithoutBase => get_domain(&format!("https://{input}")),
            _ => Err(GetDomainError::ParseError),
        },
    }
}

pub fn get_root_domain(input: &str) -> Result<String, GetRootDomainError> {
    match get_domain(input) {
        Ok(domain) => match DEFAULT_PROVIDER.effective_tld_plus_one(&domain) {
            Ok(d) => Ok(d.to_string()),
            Err(e) => match e {
                Error::CannotDeriveETldPlus1 => Err(GetRootDomainError::CannotGetDomain),
                Error::EmptyLabel => Err(GetRootDomainError::EmptyLabel),
                Error::InvalidPublicSuffix => Err(GetRootDomainError::InvalidPublicSuffix),
                _ => Err(GetRootDomainError::CannotGetDomain),
            },
        },
        Err(_) => Err(GetRootDomainError::CannotGetDomain),
    }
}
