use proton_pass_common::totp::error::TOTPError as CommonTOTPError;
use proton_pass_common::totp::sanitizer::{uri_for_editing, uri_for_saving};
use proton_pass_common::totp::{Algorithm, TOTP as CommonTOTP};

// START MAPPING TYPES

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum TOTPError {
    NotTotpUri,
    InvalidAuthority(String),
    NoAuthority,
    InvalidAlgorithm(String),
    InvalidScheme(String),
    URLParseError(proton_pass_common::url::ParseError),
    NoSecret,
    EmptySecret,
    NoQueries,
    SecretParseError,
    InvalidDigitsError,
    InvalidPeriodError,
}

impl From<CommonTOTPError> for TOTPError {
    fn from(e: CommonTOTPError) -> Self {
        match e {
            CommonTOTPError::NotTotpUri => Self::NotTotpUri,
            CommonTOTPError::InvalidAuthority(s) => Self::InvalidAuthority(s),
            CommonTOTPError::NoAuthority => Self::NoAuthority,
            CommonTOTPError::InvalidAlgorithm(s) => Self::InvalidAlgorithm(s),
            CommonTOTPError::InvalidScheme(s) => Self::InvalidScheme(s),
            CommonTOTPError::URLParseError(e) => Self::URLParseError(e),
            CommonTOTPError::NoSecret => Self::NoSecret,
            CommonTOTPError::EmptySecret => Self::EmptySecret,
            CommonTOTPError::NoQueries => Self::NoQueries,
            CommonTOTPError::SecretParseError => Self::SecretParseError,
            CommonTOTPError::InvalidDigits => Self::InvalidDigitsError,
            CommonTOTPError::InvalidPeriod => Self::InvalidPeriodError,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TOTP {
    pub label: Option<String>,
    pub secret: String,
    pub issuer: Option<String>,
    pub algorithm: Option<TOTPAlgorithm>,
    pub digits: Option<u8>,
    pub period: Option<u16>,
}

impl From<CommonTOTP> for TOTP {
    fn from(t: CommonTOTP) -> Self {
        Self {
            label: t.label,
            secret: t.secret,
            issuer: t.issuer,
            algorithm: t.algorithm.map(TOTPAlgorithm::from),
            digits: t.digits,
            period: t.period,
        }
    }
}

impl From<TOTP> for CommonTOTP {
    fn from(t: TOTP) -> Self {
        Self {
            label: t.label,
            secret: t.secret,
            issuer: t.issuer,
            algorithm: t.algorithm.map(Algorithm::from),
            digits: t.digits,
            period: t.period,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TOTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl From<Algorithm> for TOTPAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::SHA1 => Self::SHA1,
            Algorithm::SHA256 => Self::SHA256,
            Algorithm::SHA512 => Self::SHA512,
        }
    }
}

impl From<TOTPAlgorithm> for Algorithm {
    fn from(a: TOTPAlgorithm) -> Self {
        match a {
            TOTPAlgorithm::SHA1 => Self::SHA1,
            TOTPAlgorithm::SHA256 => Self::SHA256,
            TOTPAlgorithm::SHA512 => Self::SHA512,
        }
    }
}

// END MAPPING TYPES

pub struct TotpTokenResult {
    pub totp: TOTP,
    pub token: String,
    pub timestamp: u64,
}

pub struct TotpHandler;

impl TotpHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn get_algorithm(&self, totp: TOTP) -> TOTPAlgorithm {
        TOTPAlgorithm::from(CommonTOTP::from(totp).get_algorithm())
    }

    pub fn get_digits(&self, totp: TOTP) -> u8 {
        CommonTOTP::from(totp).get_digits()
    }

    pub fn get_period(&self, totp: TOTP) -> u16 {
        CommonTOTP::from(totp).get_period()
    }
}

pub struct TotpUriSanitizer;

impl TotpUriSanitizer {
    pub fn new() -> Self {
        Self
    }

    pub fn uri_for_editing(&self, original_uri: String) -> String {
        uri_for_editing(original_uri.as_str())
    }

    pub fn uri_for_saving(&self, original_uri: String, edited_uri: String) -> Result<String, TOTPError> {
        match uri_for_saving(original_uri.as_str(), edited_uri.as_str()) {
            Ok(s) => Ok(s),
            Err(e) => Err(TOTPError::from(e)),
        }
    }
}

pub struct TotpTokenGenerator;

impl TotpTokenGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_token(&self, uri: String, current_time: u64) -> Result<TotpTokenResult, TOTPError> {
        let totp = CommonTOTP::from_uri(&uri)?;
        let token = totp.generate_token(current_time)?;
        Ok(TotpTokenResult {
            token,
            totp: totp.into(),
            timestamp: current_time,
        })
    }
}

pub struct TotpUriParser;

impl TotpUriParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, uri_string: String) -> Result<TOTP, TOTPError> {
        Ok(TOTP::from(CommonTOTP::from_uri(uri_string.as_str())?))
    }
}
