use proton_pass_derive::Error;
use crate::otp::OTPAlgorithm::{SHA1, SHA256, SHA512};
use crate::otp::OTPType::{HOTP, TOTP};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OTPError {
    InvalidType,
    InvalidAlgorithm
}

#[derive(Debug, PartialEq, Eq)]
pub enum OTPType {
    TOTP,
    HOTP
}

impl OTPType {
    pub fn parse(string: &str) -> Result<OTPType, OTPError> {
        match string.to_uppercase().as_str() {
            "TOTP" => Ok(TOTP),
            "HOTP" => Ok(HOTP),
            _ => Err(OTPError::InvalidType)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OTPAlgorithm {
    SHA1, SHA256, SHA512
}

impl OTPAlgorithm {
    pub fn parse(string: &str) -> Result<OTPAlgorithm, OTPError> {
        match string.to_uppercase().as_str() {
            "SHA1" => Ok(SHA1),
            "SHA256" => Ok(SHA256),
            "SHA512" => Ok(SHA512),
            _ => Err(OTPError::InvalidAlgorithm)
        }
    }
}

#[derive(Debug)]
pub struct OTPComponents {
    pub otp_type: OTPType,
    pub secret: String,
    pub label: Option<String>,
    pub issuer: Option<String>,
    pub algorithm: OTPAlgorithm,
    pub digits: u8,
    pub period: u16
}