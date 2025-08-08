pub mod gen;

use crate::parser::google::gen::google_authenticator::migration_payload::OtpType;
use crate::parser::{ImportError, ImportResult, ThirdPartyImportError};
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
use base64::Engine;
use gen::google_authenticator::migration_payload as google;
use protobuf::Message;
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoogleAuthenticatorParseError {
    BadUri,
    BadContent,
    Unsupported,
}

impl From<GoogleAuthenticatorParseError> for ThirdPartyImportError {
    fn from(err: GoogleAuthenticatorParseError) -> Self {
        match err {
            GoogleAuthenticatorParseError::BadUri => Self::BadContent,
            GoogleAuthenticatorParseError::BadContent => Self::BadContent,
            GoogleAuthenticatorParseError::Unsupported => Self::BadContent,
        }
    }
}

impl TryFrom<google::Algorithm> for Algorithm {
    type Error = GoogleAuthenticatorParseError;

    fn try_from(value: google::Algorithm) -> Result<Self, Self::Error> {
        match value {
            google::Algorithm::ALGORITHM_UNSPECIFIED => Err(Self::Error::Unsupported),
            google::Algorithm::ALGORITHM_SHA1 => Ok(Algorithm::SHA1),
            google::Algorithm::ALGORITHM_SHA256 => Ok(Algorithm::SHA256),
            google::Algorithm::ALGORITHM_SHA512 => Ok(Algorithm::SHA512),
            google::Algorithm::ALGORITHM_MD5 => Err(Self::Error::Unsupported),
        }
    }
}

impl TryFrom<google::OtpParameters> for AuthenticatorEntry {
    type Error = GoogleAuthenticatorParseError;

    fn try_from(parameters: google::OtpParameters) -> Result<Self, Self::Error> {
        let otp_type = parameters
            .type_
            .enum_value()
            .map_err(|_| GoogleAuthenticatorParseError::Unsupported)?;

        match otp_type {
            OtpType::OTP_TYPE_TOTP => {
                let algorithm = parameters
                    .algorithm
                    .enum_value()
                    .map_err(|_| GoogleAuthenticatorParseError::Unsupported)?
                    .try_into()?;

                Ok(Self {
                    content: AuthenticatorEntryContent::Totp(TOTP {
                        label: Some(parameters.name),
                        secret: base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &parameters.secret),
                        issuer: Some(parameters.issuer),
                        algorithm: Some(algorithm),
                        digits: match parameters.digits.enum_value_or_default() {
                            google::DigitCount::DIGIT_COUNT_UNSPECIFIED => None,
                            google::DigitCount::DIGIT_COUNT_EIGHT => Some(8),
                            google::DigitCount::DIGIT_COUNT_SIX => Some(6),
                        },
                        period: Some(30), // Google always uses period=30
                    }),
                    note: None,
                    id: Self::generate_id(),
                })
            }
            OtpType::OTP_TYPE_HOTP => {
                warn!("Received HOTP OtpType, which we don't support");
                Err(GoogleAuthenticatorParseError::Unsupported)
            }
            _ => {
                warn!("Received unsupported OTP OtpType, which we don't support");
                Err(GoogleAuthenticatorParseError::Unsupported)
            }
        }
    }
}

pub fn parse_google_authenticator_totp(input: &str) -> Result<ImportResult, GoogleAuthenticatorParseError> {
    let uri = url::Url::parse(input).map_err(|_| GoogleAuthenticatorParseError::BadUri)?;
    if uri.scheme() != "otpauth-migration" {
        return Err(GoogleAuthenticatorParseError::BadUri);
    }
    let data = uri
        .query_pairs()
        .filter(|(k, _)| k == "data")
        .map(|(_, v)| v.to_string())
        .next()
        .ok_or(GoogleAuthenticatorParseError::BadUri)?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&data)
        .map_err(|_| GoogleAuthenticatorParseError::BadContent)?;

    let parsed = gen::google_authenticator::MigrationPayload::parse_from_bytes(&decoded)
        .map_err(|_| GoogleAuthenticatorParseError::BadContent)?;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, param) in parsed.otp_parameters.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(param.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                let printable_param = format!(
                    "issuer={}|algo={:?}|type={:?}",
                    param.issuer, param.algorithm, param.type_
                );
                errors.push(ImportError {
                    context: format!("Error in entry {idx}"),
                    message: format!("param: [{printable_param}] | error: {e:?}"),
                })
            }
        }
    }

    Ok(ImportResult { entries, errors })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_can_import() {
        let input = "otpauth-migration://offline?data=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";

        let res = parse_google_authenticator_totp(input).expect("should be able to parse");
        assert!(res.errors.is_empty());

        let entries = res.entries;
        assert_eq!(entries.len(), 1);

        let entry = match &entries[0].content {
            AuthenticatorEntryContent::Totp(entry) => entry.clone(),
            _ => panic!("should be a TOTP entry"),
        };

        assert_eq!("MYLABEL", entry.label.expect("should contain a label"));
        assert_eq!("MYISSUER", entry.issuer.expect("should contain an issuer"));
        assert_eq!(Algorithm::SHA256, entry.algorithm.expect("should contain an algorithm"));
        assert_eq!(8, entry.digits.expect("should contain digits"));

        // Google only exports 30
        assert_eq!(30, entry.period.expect("should contain a period"));
    }

    #[test]
    fn fails_on_empty_input() {
        let res = parse_google_authenticator_totp("").expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_bad_scheme() {
        let input = "totp://offline?data=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";

        let res = parse_google_authenticator_totp(input).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_missing_data() {
        let input = "otpauth-migration://offline?datafail=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";
        let res = parse_google_authenticator_totp(input).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_malformed_content() {
        let input = "otpauth-migration://offline?data=invaliddata";
        let res = parse_google_authenticator_totp(input).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadContent);
    }

    #[test]
    fn fails_on_invalid_content_data() {
        let input = "otpauth-migration://offline?data=rSQ04U9PcneFhvjOxzmevg%3D%3D";

        let res = parse_google_authenticator_totp(input).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadContent);
    }

    #[test]
    fn can_import_skipping_hotp() {
        let input = "otpauth-migration://offline?data=CisKD23SMN0jCOSRhDdt0huEQRISY29kZSAxIGdvb2dsZSBhdXRoIAEoATACCikKCkhlbGxvId6tvu8SDEdvb2dsZTQgY29kZRoHVGVzdEFwcCACKAEwAgotCgpIZWxsbyHerb7vEhB1c2VyQGV4YW1wbGUuY29tGgdUZXN0QXBwIAIoATACCi0KCkhlbGxvId6tvu8SEHVzZXJAZXhhbXBsZS5jb20aB1Rlc3RBcHAgAigBMAIKLQoKSGVsbG8h3q2%2B7xIQdXNlckBleGFtcGxlLmNvbRoHVGVzdEFwcCABKAEwAgojCg8JUlSVJWySNI0hGEbRpGkSCGhvdHBpdGVtIAEoATABOAEKLgoZfJQ0DaM4zlOOg0jScbbhGEoS3Cm4giOkRRIJaG90cGl0ZW0yIAEoATABOAEQAhgBIAA%3D";
        let res = parse_google_authenticator_totp(input).expect("should not fail");
        assert_eq!(res.entries.len(), 5);

        assert_eq!(res.errors.len(), 2);
    }
}
