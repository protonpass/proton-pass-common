use crate::totp::algorithm::Algorithm::{SHA1, SHA256, SHA512};
use crate::totp::error::TOTPError;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl<'a> TryFrom<&'a str> for Algorithm {
    type Error = TOTPError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "SHA1" => Ok(SHA1),
            "SHA256" => Ok(SHA256),
            "SHA512" => Ok(SHA512),
            _ => Err(TOTPError::InvalidAlgorithm(value.to_string())),
        }
    }
}

impl From<&Algorithm> for totp_rs::Algorithm {
    fn from(value: &Algorithm) -> Self {
        match value {
            SHA1 => totp_rs::Algorithm::SHA1,
            SHA256 => totp_rs::Algorithm::SHA256,
            SHA512 => totp_rs::Algorithm::SHA512,
        }
    }
}

impl Algorithm {
    pub fn value(&self) -> &str {
        match self {
            SHA1 => "SHA1",
            SHA256 => "SHA256",
            SHA512 => "SHA512",
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new_algorithm() {
        assert_eq!(Algorithm::try_from("sha1"), Ok(SHA1));
        assert_eq!(Algorithm::try_from("SHA1"), Ok(SHA1));

        assert_eq!(Algorithm::try_from("sha256"), Ok(SHA256));
        assert_eq!(Algorithm::try_from("SHA256"), Ok(SHA256));

        assert_eq!(Algorithm::try_from("sha512"), Ok(SHA512));
        assert_eq!(Algorithm::try_from("SHA512"), Ok(SHA512));

        assert_eq!(
            Algorithm::try_from("sha"),
            Err(TOTPError::InvalidAlgorithm("sha".to_string()))
        );
    }
}
