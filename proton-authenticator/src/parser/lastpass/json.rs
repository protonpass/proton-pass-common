use crate::parser::lastpass::LastPassImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;
use crate::AuthenticatorEntryContent::Totp;
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;

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
    pub algorithm: String,
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
                label: string_option_if_not_empty(value.user_name),
                secret: value.secret,
                issuer: string_option_if_not_empty(value.issuer_name),
                algorithm: match Algorithm::try_from(value.algorithm.as_str()) {
                    Ok(a) => Some(a),
                    Err(_) => {
                        return Err(LastPassImportError::BadContent(format!(
                            "Unknown algorithm: {}",
                            value.algorithm
                        )))
                    }
                },
                digits: Some(value.digits),
                period: Some(value.time_step),
            }),
            id: Self::generate_id(),
        })
    }
}

fn string_option_if_not_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn parse_lastpass_json(input: &str) -> Result<ImportResult, LastPassImportError> {
    let parsed = serde_json::from_str::<Root>(input).map_err(|e| LastPassImportError::BadContent(e.to_string()))?;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, account) in parsed.accounts.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(account.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                errors.push(ImportError {
                    context: format!("Errir in entry {idx}"),
                    message: format!("Error parsing account {:?}: {:?}", account, e),
                });
            }
        }
    }
    Ok(ImportResult { entries, errors })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents;
    use crate::AuthenticatorEntryContent;
    use proton_pass_totp::algorithm::Algorithm;
    use proton_pass_totp::totp::TOTP;

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

        let res = parse_lastpass_json(&input).expect("should be able to parse");
        assert!(res.errors.is_empty());

        let entries = res.entries;
        assert_eq!(entries.len(), 3);

        match &entries[0].content {
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
        match &entries[1].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA256, 8, 20, Some("other".to_string()), None);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &entries[2].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA512, 6, 30, None, Some("sha512 name".to_string()));
            }
            _ => panic!("Should be a TOTP"),
        }
    }
}
