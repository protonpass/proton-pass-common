use crate::totp::algorithm::Algorithm;
use crate::totp::algorithm::Algorithm::SHA1;
use crate::totp::error::TOTPError;
use crate::totp::queries::Queries;
use url::Url;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TOTP {
    pub label: Option<String>,
    pub secret: String,
    pub issuer: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub digits: Option<u8>,
    pub period: Option<u16>,
}

pub const OTP_SCHEME: &str = "otpauth";
pub const TOTP_HOST: &str = "totp";
pub const QUERY_SECRET: &str = "secret";
pub const QUERY_ISSUER: &str = "issuer";
pub const QUERY_ALGORITHM: &str = "algorithm";
pub const QUERY_DIGITS: &str = "digits";
pub const QUERY_PERIOD: &str = "period";

pub const DEFAULT_ALGORITHM: Algorithm = SHA1;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u16 = 30;

impl TOTP {
    pub fn from_uri(uri: &str) -> Result<Self, TOTPError> {
        match Url::parse(uri) {
            Ok(uri) => Self::parse_uri(uri),
            Err(error) => Err(TOTPError::URLParseError(error)),
        }
    }

    fn parse_uri(uri: Url) -> Result<Self, TOTPError> {
        Self::check_scheme(&uri)?;
        Self::check_otp_type(&uri)?;

        let label = Self::parse_label(&uri);

        let queries = &Self::parse_queries(&uri)?;
        let secret = queries.get_secret()?;
        let issuer = queries.get_issuer();
        let algorithm = queries.get_algorithm()?;
        let digits = queries.get_digits();
        let period = queries.get_period();

        Ok(Self {
            label,
            secret,
            issuer,
            algorithm,
            digits,
            period,
        })
    }

    fn parse_queries(uri: &Url) -> Result<Queries, TOTPError> {
        let queries_string = uri.query().ok_or(TOTPError::NoQueries)?;
        Ok(Queries::new(queries_string))
    }
}

impl TOTP {
    fn check_scheme(uri: &Url) -> Result<(), TOTPError> {
        let scheme = uri.scheme().to_string();
        if scheme.to_lowercase() == OTP_SCHEME {
            Ok(())
        } else {
            Err(TOTPError::InvalidScheme(scheme))
        }
    }

    fn check_otp_type(uri: &Url) -> Result<(), TOTPError> {
        let authority = uri.authority();
        if authority.is_empty() {
            Err(TOTPError::NoAuthority)
        } else if authority.to_lowercase() == TOTP_HOST {
            Ok(())
        } else {
            Err(TOTPError::InvalidAuthority(authority.to_string()))
        }
    }

    fn parse_label(uri: &Url) -> Option<String> {
        match uri.path_segments() {
            Some(segments) => {
                if let Some(label) = segments.last() {
                    if !label.is_empty() {
                        Some(label.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl TOTP {
    pub fn has_default_params(&self) -> bool {
        let default_algorithm = match &self.algorithm {
            Some(value) => *value == DEFAULT_ALGORITHM,
            _ => true,
        };

        let default_digits = match &self.digits {
            Some(value) => *value == DEFAULT_DIGITS,
            _ => true,
        };

        let default_period = match &self.period {
            Some(value) => *value == DEFAULT_PERIOD,
            _ => true,
        };

        default_algorithm && default_digits && default_period
    }
}

#[cfg(test)]
mod test_from_uri {
    use crate::totp::algorithm::Algorithm::SHA512;
    use crate::totp::error::TOTPError;
    use crate::totp::totp::TOTP;

    fn make_sut(uri: &str) -> Result<TOTP, TOTPError> {
        TOTP::from_uri(uri)
    }

    #[test]
    fn invalid_scheme() {
        // Given
        let uri = "https://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA1&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::InvalidScheme("https".to_string())));
    }

    #[test]
    fn invalid_authority() {
        // Given
        let uri = "otpauth://hotp/john.doe%40example.com?secret=somesecret&algorithm=SHA1&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::InvalidAuthority("hotp".to_string())));
    }

    #[test]
    fn no_authority() {
        // Given
        let uri = "otpauth://?secret=somesecret&algorithm=SHA1&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::NoAuthority));
    }

    #[test]
    fn no_queries() {
        // Given
        let uri = "otpauth://totp/";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::NoQueries));
    }

    #[test]
    fn no_secret() {
        // Given
        let uri = "otpauth://totp/john.doe%40example.com?algorithm=SHA1&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::NoSecret));
    }

    #[test]
    fn empty_secret() {
        // Given
        let uri = "otpauth://totp/john.doe%40example.com?secret=&algorithm=SHA1&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::EmptySecret));
    }

    #[test]
    fn invalid_algorithm() {
        // Given
        let uri = "otpauth://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA128&digits=8&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        assert_eq!(sut, Err(TOTPError::InvalidAlgorithm("SHA128".to_string())));
    }

    #[test]
    fn explicit_params() {
        // Given
        let uri =
            "otpauth://totp/john.doe%40example.com?secret=somesecret&issuer=ProtonMail&algorithm=SHA512&digits=8&period=45";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, Some("john.doe%40example.com".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("ProtonMail".to_string()));
                assert_eq!(components.algorithm, Some(SHA512));
                assert_eq!(components.digits, Some(8));
                assert_eq!(components.period, Some(45));
            }
            _ => panic!("Should be able to parse"),
        }
    }

    #[test]
    fn implicit_params() {
        // Given
        let uri = "otpauth://totp/?secret=somesecret";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, None);
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, None);
                assert_eq!(components.algorithm, None);
                assert_eq!(components.digits, None);
                assert_eq!(components.period, None);
            }
            _ => panic!("Should be able to parse"),
        }
    }
}

#[cfg(test)]
mod test_has_default_params {
    use crate::totp::algorithm::Algorithm::SHA512;
    use crate::totp::totp::{DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD, TOTP};

    #[test]
    fn custom_params() {
        // Given
        let sut = TOTP {
            label: None,
            secret: "somesecret".to_string(),
            issuer: None,
            algorithm: Some(SHA512),
            digits: Some(DEFAULT_DIGITS),
            period: Some(DEFAULT_PERIOD),
        };

        // Then
        assert!(!sut.has_default_params());
    }

    #[test]
    fn explicit_default_params() {
        // Given
        let sut = TOTP {
            label: None,
            secret: "somesecret".to_string(),
            issuer: None,
            algorithm: Some(DEFAULT_ALGORITHM),
            digits: Some(DEFAULT_DIGITS),
            period: Some(DEFAULT_PERIOD),
        };

        // Then
        assert!(sut.has_default_params());
    }

    #[test]
    fn implicit_default_params() {
        // Given
        let sut = TOTP {
            label: None,
            secret: "somesecret".to_string(),
            issuer: None,
            algorithm: None,
            digits: None,
            period: None,
        };

        // Then
        assert!(sut.has_default_params());
    }
}