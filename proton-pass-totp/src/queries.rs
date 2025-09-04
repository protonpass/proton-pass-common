use crate::algorithm::Algorithm;
use crate::error::TOTPError;
use serde::Deserialize;
use serde_querystring::{from_str, ParseMode};

#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct Queries {
    pub(crate) secret: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) algorithm: Option<String>,
    pub(crate) digits: Option<String>,
    pub(crate) period: Option<String>,
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

    pub fn get_algorithm(&self) -> Result<Option<Algorithm>, TOTPError> {
        if let Some(value) = self.algorithm.clone() {
            if value == "null" {
                Ok(None)
            } else {
                match Algorithm::try_from(&*value) {
                    Ok(algo) => Ok(Some(algo)),
                    Err(error) => Err(error),
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_digits(&self) -> Result<Option<u8>, TOTPError> {
        match self.digits {
            Some(ref digits) => {
                if digits == "null" {
                    Ok(None)
                } else {
                    match digits.parse::<u8>() {
                        Ok(digits) => {
                            if digits > 0 && digits <= 9 {
                                Ok(Some(digits))
                            } else {
                                Err(TOTPError::InvalidDigits)
                            }
                        }

                        Err(_) => Err(TOTPError::InvalidDigits),
                    }
                }
            }
            None => Ok(None),
        }
    }

    pub fn get_period(&self) -> Result<Option<u16>, TOTPError> {
        match self.period {
            Some(ref period) => {
                if period == "null" {
                    Ok(None)
                } else {
                    match period.parse::<u16>() {
                        Ok(period) => {
                            if period > 0 {
                                Ok(Some(period))
                            } else {
                                Err(TOTPError::InvalidPeriod)
                            }
                        }
                        Err(_) => Err(TOTPError::InvalidPeriod),
                    }
                }
            }
            None => Ok(None),
        }
    }
}
