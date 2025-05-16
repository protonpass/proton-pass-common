use crate::algorithm::Algorithm;
use crate::error::TOTPError;
use crate::queries::Queries;
use crate::sanitizer::sanitize_secret;
use url::Url;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::SHA1;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u16 = 30;

impl TOTP {
    pub fn from_uri(uri: &str) -> Result<Self, TOTPError> {
        match Url::parse(uri) {
            Ok(uri) => Self::parse_uri(uri),

            // Not an URI, remove all white spaces and treat the whole string as secret
            _ => Ok(TOTP {
                secret: uri.chars().filter(|c| !c.is_whitespace()).collect(),
                ..Default::default()
            }),
        }
    }

    fn parse_uri(uri: Url) -> Result<Self, TOTPError> {
        Self::check_scheme(&uri)?;
        Self::check_otp_type(&uri)?;

        let label = Self::parse_label(&uri);

        let queries = Self::parse_queries(&uri)?;
        let issuer = Self::parse_issuer(&uri, &queries);
        let secret = queries.get_secret()?;
        let algorithm = queries.get_algorithm()?;
        let digits = queries.get_digits()?;

        let period = queries.get_period()?;

        Ok(Self {
            issuer,
            label,
            secret,
            algorithm,
            digits,
            period,
        })
    }

    fn parse_queries(uri: &Url) -> Result<Queries, TOTPError> {
        let queries_string = uri.query().ok_or(TOTPError::NoQueries)?;
        Ok(Queries::new(queries_string))
    }

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

    fn parse_issuer(uri: &Url, queries: &Queries) -> Option<String> {
        if let Some(ref issuer) = queries.issuer {
            return Some(issuer.to_string());
        }

        let path = uri.path_segments()?.next_back()?.trim();
        if path.is_empty() {
            return None;
        }

        match urlencoding::decode(path) {
            Ok(decoded) => {
                let split: Vec<&str> = decoded.split(':').collect();
                split.first().map(|s| s.to_string()).filter(|_| split.len() > 1)
            }
            Err(_) => Some(path.to_string()),
        }
    }

    fn parse_label(uri: &Url) -> Option<String> {
        match uri.path_segments() {
            Some(mut segments) => {
                if let Some(label) = segments.next_back() {
                    if !label.is_empty() {
                        match urlencoding::decode(label) {
                            Ok(decoded) => {
                                let split: Vec<&str> = decoded.split(":").collect();
                                match split.last() {
                                    Some(label) => Some(label.trim().to_string()),
                                    None => Some(decoded.trim().to_string()),
                                }
                            }
                            Err(_) => Some(label.trim().to_string()),
                        }
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

    pub fn get_algorithm(&self) -> Algorithm {
        self.algorithm.unwrap_or(DEFAULT_ALGORITHM)
    }

    pub fn get_digits(&self) -> u8 {
        self.digits.unwrap_or(DEFAULT_DIGITS)
    }

    pub fn get_period(&self) -> u16 {
        self.period.unwrap_or(DEFAULT_PERIOD)
    }

    pub fn to_uri(&self, original_label: Option<String>, original_issuer: Option<String>) -> String {
        let base_uri = format!("{}://{}/", OTP_SCHEME, TOTP_HOST);

        let mut uri = match Url::parse(&base_uri) {
            Ok(value) => value,
            _ => panic!(
                "Should be able to create Url struct with scheme {} and host {}",
                OTP_SCHEME, TOTP_HOST
            ),
        };

        // Add label path
        if let Some(edited_label) = &self.label {
            uri.set_path(edited_label.as_str());
        } else if let Some(original_label) = original_label {
            uri.set_path(original_label.as_str());
        }

        // Set secret query
        uri.query_pairs_mut().append_pair(QUERY_SECRET, &self.secret);

        // Set issuer query
        if let Some(edited_issuer) = &self.issuer {
            uri.query_pairs_mut().append_pair(QUERY_ISSUER, edited_issuer.as_str());
        } else if let Some(original_issuer) = original_issuer {
            uri.query_pairs_mut()
                .append_pair(QUERY_ISSUER, original_issuer.as_str());
        }

        // Set algorithm query
        let algorithm = match &self.algorithm {
            Some(entered_algorithm) => entered_algorithm,
            _ => &DEFAULT_ALGORITHM,
        };
        uri.query_pairs_mut().append_pair(QUERY_ALGORITHM, algorithm.value());

        // Set digits
        let digits = match &self.digits {
            Some(entered_digits) => entered_digits,
            _ => &DEFAULT_DIGITS,
        };
        uri.query_pairs_mut().append_pair(QUERY_DIGITS, &format!("{}", digits));

        // Set period
        let period = match &self.period {
            Some(entered_period) => entered_period,
            _ => &DEFAULT_PERIOD,
        };
        uri.query_pairs_mut().append_pair(QUERY_PERIOD, &format!("{}", period));
        uri.as_str().to_string()
    }

    pub fn generate_token(&self, current_time: u64) -> Result<String, TOTPError> {
        let sanitized_secret = sanitize_secret(self.secret.as_str());
        let secret = match totp_rs::Secret::Encoded(sanitized_secret.clone()).to_bytes() {
            Ok(secret) => secret,
            Err(_) => match totp_rs::Secret::Raw(sanitized_secret.into_bytes()).to_bytes() {
                Ok(secret) => secret,
                Err(_) => return Err(TOTPError::SecretParseError),
            },
        };
        let algorithm = self.get_algorithm();
        let totp = totp_rs::TOTP::new_unchecked(
            totp_rs::Algorithm::from(algorithm),
            self.get_digits() as usize,
            1,
            self.get_period() as u64,
            secret,
        );
        Ok(totp.generate(current_time))
    }
}

#[cfg(test)]
mod test_from_uri {
    use super::*;

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
                assert_eq!(components.label, Some("john.doe@example.com".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("ProtonMail".to_string()));
                assert_eq!(components.algorithm, Some(Algorithm::SHA512));
                assert_eq!(components.digits, Some(8));
                assert_eq!(components.period, Some(45));
            }
            _ => panic!("Should be able to parse"),
        }
    }

    #[test]
    fn can_parse_label() {
        // Given
        let uri =
            "otpauth://totp/issuer%3Alabel?secret=somesecret&issuer=ProtonMail&algorithm=SHA512&digits=8&period=45";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, Some("label".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("ProtonMail".to_string()));
                assert_eq!(components.algorithm, Some(Algorithm::SHA512));
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

    #[test]
    fn whole_uri_as_secret() {
        let sut = make_sut("not an uri").expect("Should be able to parse");
        assert_eq!(sut.label, None);
        assert_eq!(sut.secret, "notanuri");
        assert_eq!(sut.issuer, None);
        assert_eq!(sut.algorithm, None);
        assert_eq!(sut.digits, None);
        assert_eq!(sut.period, None);
    }

    #[test]
    fn parse_issuer_from_multiple_formats() {
        let cases = vec![
            (
                "otpauth://totp/ISSUER:username?secret=SECRET&algorithm=SHA256&digits=8&period=60",
                Some("ISSUER".to_string()),
            ),
            (
                "otpauth://totp/ISSUER:username?issuer=OTHER&secret=SECRET&algorithm=SHA256&digits=8&period=60",
                Some("OTHER".to_string()),
            ),
            (
                "otpauth://totp/username?issuer=ISSUER&secret=SECRET&algorithm=SHA256&digits=8&period=60",
                Some("ISSUER".to_string()),
            ),
            (
                "otpauth://totp/username?secret=SECRET&algorithm=SHA256&digits=8&period=60",
                None,
            ),
        ];

        for (uri, expected_issuer) in cases {
            let parsed = TOTP::from_uri(uri).expect("Should be able to parse");
            assert_eq!(parsed.issuer, expected_issuer);
        }
    }
}

#[cfg(test)]
mod test_has_default_params {
    use super::*;

    #[test]
    fn custom_params() {
        // Given
        let sut = TOTP {
            label: None,
            secret: "somesecret".to_string(),
            issuer: None,
            algorithm: Some(Algorithm::SHA512),
            digits: Some(DEFAULT_DIGITS),
            period: Some(DEFAULT_PERIOD),
        };

        // Then
        assert!(!sut.has_default_params());
        assert_eq!(sut.get_algorithm(), Algorithm::SHA512);
        assert_eq!(sut.get_digits(), DEFAULT_DIGITS);
        assert_eq!(sut.get_period(), DEFAULT_PERIOD);
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
        assert_eq!(sut.get_algorithm(), DEFAULT_ALGORITHM);
        assert_eq!(sut.get_digits(), DEFAULT_DIGITS);
        assert_eq!(sut.get_period(), DEFAULT_PERIOD);
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
        assert_eq!(sut.get_algorithm(), DEFAULT_ALGORITHM);
        assert_eq!(sut.get_digits(), DEFAULT_DIGITS);
        assert_eq!(sut.get_period(), DEFAULT_PERIOD);
    }
}

#[cfg(test)]
mod test_to_uri {
    use super::*;

    #[test]
    fn to_uri() {
        assert_eq!(
            TOTP {
                label: None,
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(None, None),
            "otpauth://totp/?secret=some_secret&algorithm=SHA1&digits=6&period=30".to_string()
        );

        assert_eq!(
            TOTP {
                label: None,
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(Some("john.doe".to_string()), None),
            "otpauth://totp/john.doe?secret=some_secret&algorithm=SHA1&digits=6&period=30".to_string()
        );

        assert_eq!(
            TOTP {
                label: None,
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(Some("john.doe".to_string()), Some("Proton".to_string())),
            "otpauth://totp/john.doe?secret=some_secret&issuer=Proton&algorithm=SHA1&digits=6&period=30".to_string()
        );

        assert_eq!(
            TOTP {
                label: Some("jane.doe".to_string()),
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(Some("john.doe".to_string()), Some("Proton".to_string())),
            "otpauth://totp/jane.doe?secret=some_secret&issuer=Proton&algorithm=SHA1&digits=6&period=30".to_string()
        );

        assert_eq!(
            TOTP {
                label: Some("jane.doe".to_string()),
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: Some(Algorithm::SHA512),
                digits: Some(8),
                period: None,
            }
            .to_uri(Some("john.doe".to_string()), Some("Proton".to_string())),
            "otpauth://totp/jane.doe?secret=some_secret&issuer=Proton&algorithm=SHA512&digits=8&period=30".to_string()
        );
    }
}

#[cfg(test)]
mod test_generate_token {
    use super::*;

    #[test]
    fn full_uri() {
        let uri = "otpauth://totp/jane.doe?secret=JBSWY3DPEHPK3PXP&issuer=Proton&algorithm=SHA1&digits=6&period=30";
        let totp = TOTP::from_uri(uri).expect("Able to parse");
        let token = totp.generate_token(1_704_971_572).expect("Able to generate token");
        assert_eq!(token, "983462");
    }

    #[test]
    fn secret_only() {
        let totp = TOTP::from_uri("random-invalid-secret").expect("Able to parse");
        let token = totp.generate_token(1_704_971_921).expect("Able to generate token");
        assert_eq!(token, "964817");
    }

    #[test]
    fn full_uri_consistent_with_secret_only() {
        let secret = "JBSWY3DPEHPK3PXP";
        let timestamp = 1_704_972_215;
        let uri = format!("otpauth://totp/mylabel?secret={secret}&algorithm=SHA1&digits=6&period=30");
        let expected = "612829";

        let uri_token = TOTP::from_uri(&uri).unwrap().generate_token(timestamp).unwrap();
        let secret_token = TOTP::from_uri(secret).unwrap().generate_token(timestamp).unwrap();

        assert_eq!(expected, uri_token);
        assert_eq!(expected, secret_token);
    }
}
