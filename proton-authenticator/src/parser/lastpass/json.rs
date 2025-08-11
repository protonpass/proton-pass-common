use crate::parser::lastpass::LastPassImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;
use crate::AuthenticatorEntryContent::Totp;
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Account {
    #[serde(rename = "issuerName")]
    pub issuer_name: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub secret: String,
    #[serde(rename = "timeStep")]
    pub time_step: u16,
    pub digits: u8,
    pub algorithm: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Root {
    pub version: u16,
    pub accounts: Vec<Account>,
}

impl TryFrom<Account> for AuthenticatorEntry {
    type Error = LastPassImportError;

    fn try_from(value: Account) -> Result<Self, Self::Error> {
        Ok(AuthenticatorEntry {
            note: None,
            content: Totp(TOTP {
                label: string_option_if_not_empty(value.user_name.clone()),
                secret: value.secret,
                issuer: string_option_if_not_empty(value.issuer_name).or(Some(value.user_name)),
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
                    context: format!("Error in entry {idx}"),
                    message: format!("Error parsing account {}: {e:?}", account.user_name),
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
                check_totp(totp, Algorithm::SHA512, 6, 30, Some("sha512 name".to_string()), Some("sha512 name".to_string()));
            }
            _ => panic!("Should be a TOTP"),
        }
    }

    #[test]
    fn can_parse_lastpass_ios_export() {
        let input = get_file_contents("lastpass/lastpass_ios_export.json");

        let res = parse_lastpass_json(&input).expect("should be able to parse");
        assert!(res.errors.is_empty());

        let entries = res.entries;
        assert_eq!(entries.len(), 2);

        match &entries[0].content {
            AuthenticatorEntryContent::Totp(totp) => check_totp(
                totp,
                Algorithm::SHA1,
                6,
                30,
                Some("code 1 lastpass".to_string()),
                Some("snjxxndjbdbdb".to_string()),
            ),
            _ => panic!("Should be a TOTP"),
        }

        match &entries[1].content {
            AuthenticatorEntryContent::Totp(totp) => check_totp(
                totp,
                Algorithm::SHA1,
                6,
                30,
                Some("code2 lastpass".to_string()),
                Some("ndjdbxxnbcb".to_string()),
            ),
            _ => panic!("Should be a TOTP"),
        }
    }

    #[test]
    fn can_parse_lastpass_with_missing_fields() {
        let content = get_file_contents("lastpass/lastpass_missing_fields.json");
        let res = parse_lastpass_json(&content).expect("should be able to parse");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 1);

        let entry = &res.entries[0];
        assert_eq!("sometest", entry.issuer());
        assert_eq!("sometest", entry.name());
    }
}
