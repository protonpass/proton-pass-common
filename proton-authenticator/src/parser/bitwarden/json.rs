use crate::parser::bitwarden::BitwardenImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Login {
    pub totp: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Struct {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i64,
    pub login: Login,
    pub favorite: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct Root {
    pub encrypted: bool,
    pub items: Vec<Struct>,
}

impl TryFrom<Struct> for AuthenticatorEntry {
    type Error = BitwardenImportError;

    fn try_from(value: Struct) -> Result<Self, Self::Error> {
        AuthenticatorEntry::from_uri(&value.login.totp, None).map_err(|_| BitwardenImportError::Unsupported)
    }
}

pub fn parse_bitwarden_json(input: &str) -> Result<ImportResult, BitwardenImportError> {
    let parsed = serde_json::from_str::<Root>(input).map_err(|_| BitwardenImportError::BadContent)?;
    if parsed.encrypted {
        return Err(BitwardenImportError::MissingPassword);
    }

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, item) in parsed.items.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(item) {
            Ok(entry) => entries.push(entry),
            Err(e) => errors.push(ImportError {
                context: format!("Error in entry {idx}"),
                message: format!("{:?}", e),
            }),
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

    fn check_totp(entry: &TOTP, algorithm: Algorithm, digits: u8, period: u16) {
        assert_eq!(algorithm, entry.algorithm.expect("Should have an algorithm"));
        assert_eq!(digits, entry.digits.expect("Should have digits"));
        assert_eq!(period, entry.period.expect("Should have period"));
    }

    #[test]
    fn can_parse_content() {
        let input = get_file_contents("bitwarden/bitwarden.json");

        let res = parse_bitwarden_json(&input).expect("should be able to parse");
        let entries = res.entries;
        assert_eq!(entries.len(), 4);

        match &entries[0].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA256, 8, 15);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &entries[1].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 6, 30);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &entries[2].content {
            AuthenticatorEntryContent::Steam(_) => {}
            _ => panic!("Should be STEAM"),
        }
        match &entries[3].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 7, 30);
            }
            _ => panic!("Should be a TOTP"),
        }
    }
}
