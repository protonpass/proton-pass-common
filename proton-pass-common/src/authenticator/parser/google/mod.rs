pub mod gen;

use crate::authenticator::AuthenticatorEntry;
use crate::totp::algorithm::Algorithm;
use crate::totp::totp::TOTP;
use base64::Engine;
use gen::google_authenticator::migration_payload as google;
use protobuf::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoogleAuthenticatorParseError {
    BadUri,
    BadContent,
    Unsupported,
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
        let algorithm = parameters
            .algorithm
            .enum_value()
            .map_err(|_| GoogleAuthenticatorParseError::Unsupported)?
            .try_into()?;

        Ok(Self {
            totp: TOTP {
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
            },
        })
    }
}

pub fn parse_google_authenticator_totp(
    input: &str,
    fail_on_error: bool,
) -> Result<Vec<AuthenticatorEntry>, GoogleAuthenticatorParseError> {
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

    let mut entries = vec![];

    for param in parsed.otp_parameters {
        if let Ok(v) = param.type_.enum_value() {
            if v == google::OtpType::OTP_TYPE_TOTP {
                match AuthenticatorEntry::try_from(param) {
                    Ok(entry) => entries.push(entry),
                    Err(_) => {
                        if fail_on_error {
                            return Err(GoogleAuthenticatorParseError::Unsupported);
                        }
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_can_import() {
        let input = "otpauth-migration://offline?data=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";

        let res = parse_google_authenticator_totp(input, false).expect("should be able to parse");
        assert_eq!(res.len(), 1);

        let entry = res[0].totp.clone();

        assert_eq!("MYLABEL", entry.label.expect("should contain a label"));
        assert_eq!("MYISSUER", entry.issuer.expect("should contain an issuer"));
        assert_eq!(Algorithm::SHA256, entry.algorithm.expect("should contain an algorithm"));
        assert_eq!(8, entry.digits.expect("should contain digits"));

        // Google only exports 30
        assert_eq!(30, entry.period.expect("should contain a period"));
    }

    #[test]
    fn fails_on_empty_input() {
        let res = parse_google_authenticator_totp("", false).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_bad_scheme() {
        let input = "totp://offline?data=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";

        let res = parse_google_authenticator_totp(input, false).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_missing_data() {
        let input = "otpauth-migration://offline?datafail=CjUKBWYkQUSTEgdNWUxBQkVMGghNWUlTU1VFUiACKAIwAkITNjE5NGJjMTczNzcyNzc5ODc5MxACGAEgAA%3D%3D";
        let res = parse_google_authenticator_totp(input, false).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadUri);
    }

    #[test]
    fn fails_on_malformed_content() {
        let input = "otpauth-migration://offline?data=invaliddata";
        let res = parse_google_authenticator_totp(input, false).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadContent);
    }

    #[test]
    fn fails_on_invalid_content_data() {
        let input = "otpauth-migration://offline?data=rSQ04U9PcneFhvjOxzmevg%3D%3D";

        let res = parse_google_authenticator_totp(input, false).expect_err("should fail");
        assert_eq!(res, GoogleAuthenticatorParseError::BadContent);
    }
}
