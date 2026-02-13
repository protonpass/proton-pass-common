use proton_pass_common::domain::{
    get_domain, get_root_domain, GetDomainError as CommonGetDomainError, GetRootDomainError as CommonGetRootDomainError,
};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum GetRootDomainError {
    CannotGetDomain,
    EmptyLabel,
    InvalidPublicSuffix,
}

impl From<CommonGetRootDomainError> for GetRootDomainError {
    fn from(e: CommonGetRootDomainError) -> Self {
        match e {
            CommonGetRootDomainError::CannotGetDomain => Self::CannotGetDomain,
            CommonGetRootDomainError::EmptyLabel => Self::EmptyLabel,
            CommonGetRootDomainError::InvalidPublicSuffix => Self::InvalidPublicSuffix,
        }
    }
}

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum GetDomainError {
    ParseError,
    UrlHasNoDomain,
}

impl From<CommonGetDomainError> for GetDomainError {
    fn from(e: CommonGetDomainError) -> Self {
        match e {
            CommonGetDomainError::ParseError => Self::ParseError,
            CommonGetDomainError::UrlHasNoDomain => Self::UrlHasNoDomain,
        }
    }
}

#[derive(uniffi::Object)]
pub struct DomainManager;

#[uniffi::export]
impl DomainManager {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn get_root_domain(&self, input: String) -> Result<String, GetRootDomainError> {
        Ok(get_root_domain(&input)?)
    }

    pub fn get_domain(&self, input: String) -> Result<String, GetDomainError> {
        Ok(get_domain(&input)?)
    }
}
