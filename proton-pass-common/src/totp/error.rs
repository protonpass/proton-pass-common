use proton_pass_derive::Error;
use uriparse::URIError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TOTPError {
    InvalidAuthority(String),
    NoAuthority,
    InvalidAlgorithm(String),
    InvalidScheme(String),
    URIError(URIError),
    NoSecret,
    EmptySecret,
    NoQueries,
}
