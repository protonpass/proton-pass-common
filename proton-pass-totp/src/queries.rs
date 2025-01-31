use crate::algorithm::Algorithm;
use crate::error::TOTPError;
use serde::Deserialize;
use serde_querystring::{from_str, ParseMode};

#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct Queries {
    secret: Option<String>,
    issuer: Option<String>,
    algorithm: Option<String>,
    digits: Option<String>,
    period: Option<String>,
}

impl Queries {
    pub fn new(queries_string: &str) -> Self {
        from_str::<Self>(queries_string, ParseMode::UrlEncoded).unwrap_or_default()
    }

    pub fn get_secret(&self) -> Result<String, TOTPError> {
        if let Some(value) = self.secret.clone() {
            if value.is_empty() {
                Err(TOTPError::EmptySecret)
            } else {
                Ok(value)
            }
        } else {
            Err(TOTPError::NoSecret)
        }
    }

    pub fn get_issuer(&self) -> Option<String> {
        self.issuer.clone()
    }

    pub fn get_algorithm(&self) -> Result<Option<Algorithm>, TOTPError> {
        if let Some(value) = self.algorithm.clone() {
            match Algorithm::try_from(&*value) {
                Ok(algo) => Ok(Some(algo)),
                Err(error) => Err(error),
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_digits(&self) -> Option<u8> {
        self.digits.clone().and_then(|s| s.parse().ok())
    }

    pub fn get_period(&self) -> Option<u16> {
        self.period.clone().and_then(|s| s.parse().ok())
    }
}
