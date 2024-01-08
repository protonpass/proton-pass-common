use proton_pass_derive::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TOTPError {
    NotTotpUri,
    InvalidAuthority(String),
    NoAuthority,
    InvalidAlgorithm(String),
    InvalidScheme(String),
    NoSecret,
    EmptySecret,
    NoQueries,
    SecretParseError,
}
