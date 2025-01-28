use crate::authenticator::parser::lastpass::LastPassImportError;
use crate::authenticator::AuthenticatorEntry;
use crate::authenticator::AuthenticatorEntryContent::Totp;
use crate::totp::algorithm::Algorithm as TotpAlgorithm;
use crate::totp::totp::TOTP;
use std::ops::Not;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Into<TotpAlgorithm> for Algorithm {
    fn into(self) -> crate::totp::algorithm::Algorithm {
        match self {
            Algorithm::SHA1 => TotpAlgorithm::SHA1,
            Algorithm::SHA256 => TotpAlgorithm::SHA256,
            Algorithm::SHA512 => TotpAlgorithm::SHA512,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Account {
    #[serde(rename = "accountID")]
    pub account_id: String,
    #[serde(rename = "lmiUserId")]
    pub lmi_user_id: String,
    #[serde(rename = "issuerName")]
    pub issuer_name: String,
    #[serde(rename = "originalIssuerName")]
    pub original_issuer_name: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "originalUserName")]
    pub original_user_name: String,
    #[serde(rename = "pushNotification")]
    pub push_notification: bool,
    pub secret: String,
    #[serde(rename = "timeStep")]
    pub time_step: u16,
    pub digits: u8,
    #[serde(rename = "creationTimestamp")]
    pub creation_timestamp: u64,
    #[serde(rename = "isFavorite")]
    pub is_favorite: bool,
    pub algorithm: Algorithm,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Root {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "deviceSecret")]
    pub device_secret: String,
    #[serde(rename = "localDeviceId")]
    pub local_device_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    pub version: u16,
    pub accounts: Vec<Account>,
}

impl TryFrom<Account> for AuthenticatorEntry {
    type Error = LastPassImportError;

    fn try_from(value: Account) -> Result<Self, Self::Error> {
        Ok(AuthenticatorEntry {
            note: None,
            content: Totp(TOTP {
                label: value.user_name.is_empty().not().then(|| value.user_name),
                secret: value.secret,
                issuer: value.issuer_name.is_empty().not().then(|| value.issuer_name),
                algorithm: Some(value.algorithm.into()),
                digits: Some(value.digits),
                period: Some(value.time_step),
            }),
        })
    }
}

pub fn parse_lastpass_json(input: &str, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, LastPassImportError> {
    let parsed = serde_json::from_str::<Root>(input).map_err(|e| LastPassImportError::BadContent(e.to_string()))?;

    let mut items = Vec::new();
    for accounts in parsed.accounts {
        match AuthenticatorEntry::try_from(accounts) {
            Ok(entry) => items.push(entry),
            Err(e) => {
                if fail_on_error {
                    return Err(e);
                }
            }
        }
    }
    Ok(items)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::authenticator::test_utils::get_file_contents;
    use crate::authenticator::AuthenticatorEntryContent;
    use crate::totp::algorithm::Algorithm;
    use crate::totp::totp::TOTP;

    fn check_totp(
        entry: &TOTP,
        algorithm: Algorithm,
        digits: u8,
        period: u16,
        issuer: Option<String>,
        label: Option<String>,
    ) {
        assert_eq!(algorithm, entry.algorithm.expect("Should have an algorithm"));
        assert_eq!(digits, entry.digits.expect("Should have digits"));
        assert_eq!(period, entry.period.expect("Should have period"));
        assert_eq!(issuer, entry.issuer);
        assert_eq!(label, entry.label);
    }

    #[test]
    fn can_parse_content() {
        let input = get_file_contents("lastpass/lastpass.json");

        let res = parse_lastpass_json(&input, false).expect("should be able to parse");
        assert_eq!(res.len(), 3);

        match &res[0].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(
                    totp,
                    Algorithm::SHA1,
                    6,
                    30,
                    Some("issuer".to_string()),
                    Some("account name default".to_string()),
                );
            }
            _ => panic!("Should be a TOTP"),
        }
        match &res[1].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA256, 8, 20, Some("other".to_string()), None);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &res[2].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA512, 6, 30, None, Some("sha512 name".to_string()));
            }
            _ => panic!("Should be a TOTP"),
        }
    }
}
