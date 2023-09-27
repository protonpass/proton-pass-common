use crate::totp::algorithm::Algorithm::{SHA1, SHA256, SHA512};
use crate::totp::error::TOTPError;

#[derive(Debug, PartialEq, Eq)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512
}

impl Algorithm {
    pub fn new(value: &str) -> Result<Self, TOTPError> {
        match value.to_uppercase().as_str() {
            "SHA1" => Ok(SHA1),
            "SHA256" => Ok(SHA256),
            "SHA512" => Ok(SHA512),
            _ => Err(TOTPError::InvalidAlgorithm(value.to_string()))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::totp::algorithm::Algorithm::{SHA1, SHA256, SHA512};
    use crate::totp::algorithm::Algorithm;
    use crate::totp::error::TOTPError;

    #[test]
    fn new_algorithm() {
        assert_eq!(Algorithm::new("sha1"), Ok(SHA1));
        assert_eq!(Algorithm::new("SHA1"), Ok(SHA1));

        assert_eq!(Algorithm::new("sha256"), Ok(SHA256));
        assert_eq!(Algorithm::new("SHA256"), Ok(SHA256));

        assert_eq!(Algorithm::new("sha512"), Ok(SHA512));
        assert_eq!(Algorithm::new("SHA512"), Ok(SHA512));

        assert_eq!(Algorithm::new("sha"), Err(TOTPError::InvalidAlgorithm("sha".to_string())));
    }
}