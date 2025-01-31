use crate::error::TOTPError;

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
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            _ => Err(TOTPError::InvalidAlgorithm(value.to_string())),
        }
    }
}

impl From<&Algorithm> for totp_rs::Algorithm {
    fn from(value: &Algorithm) -> Self {
        match value {
            Algorithm::SHA1 => totp_rs::Algorithm::SHA1,
            Algorithm::SHA256 => totp_rs::Algorithm::SHA256,
            Algorithm::SHA512 => totp_rs::Algorithm::SHA512,
        }
    }
}

impl Algorithm {
    pub fn value(&self) -> &str {
        match self {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new_algorithm() {
        assert_eq!(Algorithm::try_from("sha1"), Ok(Algorithm::SHA1));
        assert_eq!(Algorithm::try_from("SHA1"), Ok(Algorithm::SHA1));

        assert_eq!(Algorithm::try_from("sha256"), Ok(Algorithm::SHA256));
        assert_eq!(Algorithm::try_from("SHA256"), Ok(Algorithm::SHA256));

        assert_eq!(Algorithm::try_from("sha512"), Ok(Algorithm::SHA512));
        assert_eq!(Algorithm::try_from("SHA512"), Ok(Algorithm::SHA512));

        assert_eq!(
            Algorithm::try_from("sha"),
            Err(TOTPError::InvalidAlgorithm("sha".to_string()))
        );
    }
}
