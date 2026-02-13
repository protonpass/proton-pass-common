use proton_pass_common::host::{parse, HostInfo as CommonHostInfo, ParseHostError as CommonParseHostError};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ParseHostError {
    CannotGetDomainFromUrl,
    EmptyHost,
    EmptyUrl,
    HostIsTld,
    ParseUrlError,
    InvalidUrlError,
}

impl From<CommonParseHostError> for ParseHostError {
    fn from(e: CommonParseHostError) -> Self {
        match e {
            CommonParseHostError::CannotGetDomainFromUrl => Self::CannotGetDomainFromUrl,
            CommonParseHostError::EmptyHost => Self::EmptyHost,
            CommonParseHostError::EmptyUrl => Self::EmptyUrl,
            CommonParseHostError::HostIsTld => Self::HostIsTld,
            CommonParseHostError::ParseUrlError => Self::ParseUrlError,
            CommonParseHostError::InvalidUrlError => Self::InvalidUrlError,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostInfo {
    Host {
        protocol: String,
        subdomain: Option<String>,
        domain: String,
        tld: Option<String>,
    },
    Ip {
        ip: String,
    },
}

impl From<CommonHostInfo> for HostInfo {
    fn from(info: CommonHostInfo) -> Self {
        match info {
            CommonHostInfo::Host {
                protocol,
                subdomain,
                domain,
                tld,
            } => HostInfo::Host {
                protocol,
                subdomain,
                domain,
                tld,
            },
            CommonHostInfo::Ip { ip } => Self::Ip { ip },
        }
    }
}

#[derive(uniffi::Object)]
pub struct HostParser;

#[uniffi::export]
impl HostParser {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, url: String) -> Result<HostInfo, ParseHostError> {
        let parsed = parse(&url)?;
        Ok(HostInfo::from(parsed))
    }
}
