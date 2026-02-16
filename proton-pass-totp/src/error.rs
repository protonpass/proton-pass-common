use proton_pass_derive::{ffi_error, Error};

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TOTPError {
    NotTotpUri,
    InvalidAuthority(String),
    NoAuthority,
    InvalidAlgorithm(String),
    InvalidScheme(String),
    URLParseError(String),
    NoSecret,
    EmptySecret,
    NoQueries,
    SecretParseError,
    InvalidPeriod,
    InvalidDigits,
}

impl From<url::ParseError> for TOTPError {
    fn from(e: url::ParseError) -> Self {
        Self::URLParseError(e.to_string())
    }
}
