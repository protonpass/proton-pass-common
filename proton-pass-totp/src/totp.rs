use crate::algorithm::Algorithm;
use crate::error::TOTPError;
use crate::queries::Queries;
use crate::sanitizer::sanitize_secret;
use proton_pass_derive::ffi_type;
use url::Url;

#[ffi_type]
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

        let queries = Self::parse_queries(&uri)?;
        let label = Self::parse_label(&uri, &queries);
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

        // Find the separator colon in the encoded string first
        // This handles cases like "issuer%3Awithcolon:label%3Awithcolon"
        // where we want to split on the unencoded colon, not encoded ones
        if let Some(separator_pos) = path.find(':') {
            let issuer_part = &path[..separator_pos];
            match urlencoding::decode(issuer_part) {
                Ok(decoded_issuer) => {
                    let trimmed = decoded_issuer.trim();
                    if !trimmed.is_empty() {
                        Some(trimmed.to_string())
                    } else {
                        None
                    }
                }
                Err(_) => Some(issuer_part.to_string()),
            }
        } else {
            // No unencoded colon found, fall back to old logic
            // Decode first, then look for colons (for fully encoded paths like "issuer%3Alabel")
            match urlencoding::decode(path) {
                Ok(decoded) => {
                    if let Some(last_colon_pos) = decoded.rfind(':') {
                        let issuer_part = decoded[..last_colon_pos].trim();
                        if !issuer_part.is_empty() {
                            Some(issuer_part.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }
    }

    fn parse_label(uri: &Url, queries: &Queries) -> Option<String> {
        match uri.path_segments() {
            Some(mut segments) => {
                if let Some(label) = segments.next_back() {
                    if !label.is_empty() {
                        // Find the separator colon in the encoded string first
                        if let Some(separator_pos) = label.find(':') {
                            let potential_issuer_encoded = &label[..separator_pos];
                            let potential_label_encoded = &label[separator_pos + 1..];

                            // Decode both parts
                            let potential_issuer = match urlencoding::decode(potential_issuer_encoded) {
                                Ok(decoded) => decoded.trim().to_string(),
                                Err(_) => potential_issuer_encoded.to_string(),
                            };

                            let potential_label = match urlencoding::decode(potential_label_encoded) {
                                Ok(decoded) => decoded.trim().to_string(),
                                Err(_) => potential_label_encoded.to_string(),
                            };

                            // If there's an explicit issuer query parameter, check if it
                            // matches to determine whether we need to split and which part
                            // to keep
                            if let Some(ref query_issuer) = queries.issuer {
                                if query_issuer == &potential_issuer {
                                    // Explicit issuer matches path issuer -> only label
                                    Some(potential_label)
                                } else {
                                    // Explicit issuer doesn't match, treat whole path as label
                                    match urlencoding::decode(label) {
                                        Ok(decoded) => Some(decoded.trim().to_string()),
                                        Err(_) => Some(label.trim().to_string()),
                                    }
                                }
                            } else {
                                // No explicit issuer, split on colon
                                Some(potential_label)
                            }
                        } else {
                            // No unencoded colon found, fall back to old logic
                            // Decode first, then look for colons (for fully encoded paths like "issuer%3Alabel")
                            match urlencoding::decode(label) {
                                Ok(decoded) => {
                                    if let Some(last_colon_pos) = decoded.rfind(':') {
                                        let potential_issuer = decoded[..last_colon_pos].trim();
                                        let potential_label = decoded[last_colon_pos + 1..].trim();

                                        // If there's an explicit issuer query parameter, check if it matches
                                        if let Some(ref query_issuer) = queries.issuer {
                                            if query_issuer == potential_issuer {
                                                // Explicit issuer matches path issuer -> only label
                                                Some(potential_label.to_string())
                                            } else {
                                                // Explicit issuer doesn't match, treat whole path as label
                                                Some(decoded.trim().to_string())
                                            }
                                        } else {
                                            // No explicit issuer, split on colon
                                            Some(potential_label.to_string())
                                        }
                                    } else {
                                        // No colon, use the whole decoded string
                                        Some(decoded.trim().to_string())
                                    }
                                }
                                Err(_) => Some(label.trim().to_string()),
                            }
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
        let base_uri = format!("{OTP_SCHEME}://{TOTP_HOST}/");

        let mut uri = match Url::parse(&base_uri) {
            Ok(value) => value,
            _ => panic!("Should be able to create Url struct with scheme {OTP_SCHEME} and host {TOTP_HOST}"),
        };

        // Add label path (URL encode if it contains special characters like colons)
        if let Some(edited_label) = &self.label {
            uri.set_path(&urlencoding::encode(edited_label));
        } else if let Some(original_label) = original_label {
            uri.set_path(&urlencoding::encode(&original_label));
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
        uri.query_pairs_mut().append_pair(QUERY_DIGITS, &format!("{digits}"));

        // Set period
        let period = match &self.period {
            Some(entered_period) => entered_period,
            _ => &DEFAULT_PERIOD,
        };
        uri.query_pairs_mut().append_pair(QUERY_PERIOD, &format!("{period}"));
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
        // Given - traditional issuer:label format without explicit issuer query
        let uri = "otpauth://totp/issuer%3Alabel?secret=somesecret&algorithm=SHA512&digits=8&period=45";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, Some("label".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("issuer".to_string()));
                assert_eq!(components.algorithm, Some(Algorithm::SHA512));
                assert_eq!(components.digits, Some(8));
                assert_eq!(components.period, Some(45));
            }
            _ => panic!("Should be able to parse"),
        }
    }

    #[test]
    fn can_parse_label_with_encoded_colon_and_explicit_issuer() {
        // Given - URI with URL encoded colon in label AND explicit issuer in query
        // This represents the new behavior where labels with colons are preserved
        let uri =
            "otpauth://totp/name%3A%20updated?secret=somesecret&issuer=My%20Company&algorithm=SHA1&digits=6&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, Some("name: updated".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("My Company".to_string()));
                assert_eq!(components.algorithm, Some(Algorithm::SHA1));
                assert_eq!(components.digits, Some(6));
                assert_eq!(components.period, Some(30));
            }
            _ => panic!("Should be able to parse"),
        }
    }

    #[test]
    fn can_parse_issuer_with_encoded_colon_and_label() {
        // Given - URI with URL encoded issuer:label format (traditional format)
        // This should continue to work for backward compatibility
        let uri =
            "otpauth://totp/My%3A%20Company%3Auser%40example.com?secret=somesecret&algorithm=SHA1&digits=6&period=30";

        // When
        let sut = make_sut(uri);

        // Then
        match sut {
            Ok(components) => {
                assert_eq!(components.label, Some("user@example.com".to_string()));
                assert_eq!(components.secret, "somesecret");
                assert_eq!(components.issuer, Some("My: Company".to_string()));
                assert_eq!(components.algorithm, Some(Algorithm::SHA1));
                assert_eq!(components.digits, Some(6));
                assert_eq!(components.period, Some(30));
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

    #[test]
    fn to_uri_with_colon_in_label() {
        // Test that labels with colons get URL encoded
        assert_eq!(
            TOTP {
                label: Some("name: updated".to_string()),
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(None, None),
            "otpauth://totp/name%3A%20updated?secret=some_secret&algorithm=SHA1&digits=6&period=30".to_string()
        );

        // Test that original labels with colons get URL encoded
        assert_eq!(
            TOTP {
                label: None,
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(Some("original: name".to_string()), None),
            "otpauth://totp/original%3A%20name?secret=some_secret&algorithm=SHA1&digits=6&period=30".to_string()
        );

        // Test that edited labels take precedence and get URL encoded
        assert_eq!(
            TOTP {
                label: Some("edited: name".to_string()),
                secret: "some_secret".to_string(),
                issuer: None,
                algorithm: None,
                digits: None,
                period: None,
            }
            .to_uri(Some("original: name".to_string()), None),
            "otpauth://totp/edited%3A%20name?secret=some_secret&algorithm=SHA1&digits=6&period=30".to_string()
        );
    }

    #[test]
    fn round_trip_with_colon_in_label() {
        // Test that we can generate a URI with a colon in the label and parse it back correctly
        let original_totp = TOTP {
            label: Some("name: updated".to_string()),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: Some("My Company".to_string()),
            algorithm: Some(Algorithm::SHA256),
            digits: Some(8),
            period: Some(60),
        };

        // Generate URI
        let uri = original_totp.to_uri(None, None);

        // Parse it back
        let parsed_totp = TOTP::from_uri(&uri).expect("Should be able to parse generated URI");

        // Verify all fields are preserved
        assert_eq!(parsed_totp.label, original_totp.label);
        assert_eq!(parsed_totp.secret, original_totp.secret);
        assert_eq!(parsed_totp.issuer, original_totp.issuer);
        assert_eq!(parsed_totp.algorithm, original_totp.algorithm);
        assert_eq!(parsed_totp.digits, original_totp.digits);
        assert_eq!(parsed_totp.period, original_totp.period);
    }

    #[test]
    fn round_trip_maintains_issuer_label_parsing() {
        // Test that the traditional issuer:label format still works after our changes
        let uri =
            "otpauth://totp/GitHub%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30";

        let parsed_totp = TOTP::from_uri(uri).expect("Should be able to parse");

        // Verify issuer and label are parsed correctly from issuer:label format
        assert_eq!(parsed_totp.label, Some("user@example.com".to_string()));
        assert_eq!(parsed_totp.issuer, Some("GitHub".to_string()));
        assert_eq!(parsed_totp.secret, "JBSWY3DPEHPK3PXP");

        // Generate URI back and verify it can be parsed again
        let regenerated_uri = parsed_totp.to_uri(None, None);
        let reparsed_totp = TOTP::from_uri(&regenerated_uri).expect("Should be able to parse regenerated URI");

        assert_eq!(reparsed_totp.label, parsed_totp.label);
        assert_eq!(reparsed_totp.issuer, parsed_totp.issuer);
        assert_eq!(reparsed_totp.secret, parsed_totp.secret);
    }

    #[test]
    fn mixed_encoded_unencoded_colons() {
        // Test mixed scenarios with both encoded and unencoded colons
        // This tests the edge case where we have:
        // - Unencoded colon as issuer:label separator
        // - Encoded colon as part of the actual label content

        // Test case 1: issuer:label%3Awithcolon (no explicit issuer query)
        // Should parse as issuer="issuer", label="label:withcolon"
        let uri1 = "otpauth://totp/issuer:label%3Awithcolon?secret=somesecret&algorithm=SHA512&digits=8&period=10";
        let parsed1 = TOTP::from_uri(uri1).expect("Should parse mixed colon URI");

        assert_eq!(parsed1.issuer, Some("issuer".to_string()));
        assert_eq!(parsed1.label, Some("label:withcolon".to_string()));
        assert_eq!(parsed1.secret, "somesecret");
        assert_eq!(parsed1.algorithm, Some(Algorithm::SHA512));
        assert_eq!(parsed1.digits, Some(8));
        assert_eq!(parsed1.period, Some(10));

        // Test case 2: Complex case with multiple colons
        // Format: issuer%3Awithcolon:label%3Aalso%3Awithcolon
        // Should parse as issuer="issuer:withcolon", label="label:also:withcolon"
        let uri2 = "otpauth://totp/issuer%3Awithcolon:label%3Aalso%3Awithcolon?secret=anothersecret&algorithm=SHA1&digits=6&period=30";
        let parsed2 = TOTP::from_uri(uri2).expect("Should parse complex mixed colon URI");

        assert_eq!(parsed2.issuer, Some("issuer:withcolon".to_string()));
        assert_eq!(parsed2.label, Some("label:also:withcolon".to_string()));
        assert_eq!(parsed2.secret, "anothersecret");

        // Test case 3: With explicit issuer query parameter that matches
        // The explicit issuer should take precedence, and path should be split correctly
        let uri3 =
            "otpauth://totp/Company:user%3Aupdated?secret=secret123&issuer=Company&algorithm=SHA256&digits=7&period=45";
        let parsed3 = TOTP::from_uri(uri3).expect("Should parse with matching explicit issuer");

        assert_eq!(parsed3.issuer, Some("Company".to_string()));
        assert_eq!(parsed3.label, Some("user:updated".to_string()));
        assert_eq!(parsed3.secret, "secret123");

        // Test case 4: With explicit issuer query parameter that doesn't match
        // Should treat the whole path as label since explicit issuer doesn't match path issuer
        let uri4 = "otpauth://totp/Company:user%3Aupdated?secret=secret456&issuer=Different&algorithm=SHA256&digits=7&period=45";
        let parsed4 = TOTP::from_uri(uri4).expect("Should parse with non-matching explicit issuer");

        assert_eq!(parsed4.issuer, Some("Different".to_string()));
        assert_eq!(parsed4.label, Some("Company:user:updated".to_string()));
        assert_eq!(parsed4.secret, "secret456");

        // Test round-trip behavior for complex cases
        // Generate URI from parsed data and verify it can be parsed back correctly
        let regenerated1 = parsed1.to_uri(None, None);
        let reparsed1 = TOTP::from_uri(&regenerated1).expect("Should parse regenerated URI");
        assert_eq!(reparsed1.label, parsed1.label);
        assert_eq!(reparsed1.issuer, parsed1.issuer);
        assert_eq!(reparsed1.secret, parsed1.secret);
    }

    #[test]
    fn integration_test_colon_fix() {
        // This is the main integration test for the colon fix

        // Test 1: Entry names with colons should be preserved when generating/parsing URIs
        let original_totp = TOTP {
            label: Some("name: updated".to_string()),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: Some("My Company".to_string()),
            algorithm: Some(Algorithm::SHA256),
            digits: Some(8),
            period: Some(60),
        };

        // Generate URI - should URL encode the colon in the label
        let uri = original_totp.to_uri(None, None);
        assert!(
            uri.contains("name%3A%20updated"),
            "URI should contain URL encoded colon: {uri}"
        );
        assert!(
            uri.contains("issuer=My") && uri.contains("Company"),
            "URI should have explicit issuer query: {uri}"
        );

        // Parse it back - should preserve the colon in the label
        let parsed_totp = TOTP::from_uri(&uri).expect("Should be able to parse generated URI");
        assert_eq!(
            parsed_totp.label,
            Some("name: updated".to_string()),
            "Label with colon should be preserved"
        );
        assert_eq!(
            parsed_totp.issuer,
            Some("My Company".to_string()),
            "Issuer should be preserved"
        );
        assert_eq!(parsed_totp.secret, original_totp.secret);

        // Test 2: Traditional issuer:label format should still work for backward compatibility
        let traditional_uri = "otpauth://totp/GitHub%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP";
        let traditional_parsed = TOTP::from_uri(traditional_uri).expect("Should parse traditional format");
        assert_eq!(traditional_parsed.label, Some("user@example.com".to_string()));
        assert_eq!(traditional_parsed.issuer, Some("GitHub".to_string()));

        // Test 3: When explicit issuer matches path issuer, should split (backward compatibility)
        let compat_uri = "otpauth://totp/Company%3Auser?secret=SECRET&issuer=Company";
        let compat_parsed = TOTP::from_uri(compat_uri).expect("Should parse compatibility format");
        assert_eq!(compat_parsed.label, Some("user".to_string()));
        assert_eq!(compat_parsed.issuer, Some("Company".to_string()));

        // Test 4: When explicit issuer doesn't match path issuer, treat path as full label
        let new_uri = "otpauth://totp/name%3A%20updated?secret=SECRET&issuer=Different%20Company";
        let new_parsed = TOTP::from_uri(new_uri).expect("Should parse new format");
        assert_eq!(new_parsed.label, Some("name: updated".to_string()));
        assert_eq!(new_parsed.issuer, Some("Different Company".to_string()));
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
