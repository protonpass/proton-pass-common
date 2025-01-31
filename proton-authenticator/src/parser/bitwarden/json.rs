use crate::parser::bitwarden::BitwardenImportError;
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

pub fn parse_bitwarden_json(input: &str, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, BitwardenImportError> {
    let parsed = serde_json::from_str::<Root>(input).map_err(|_| BitwardenImportError::BadContent)?;
    if parsed.encrypted {
        return Ok(vec![]);
    }

    let mut items = Vec::new();
    for item in parsed.items {
        match AuthenticatorEntry::try_from(item) {
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

        let res = parse_bitwarden_json(&input, false).expect("should be able to parse");
        assert_eq!(res.len(), 4);

        match &res[0].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA256, 8, 15);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &res[1].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 6, 30);
            }
            _ => panic!("Should be a TOTP"),
        }
        match &res[2].content {
            AuthenticatorEntryContent::Steam(_) => {}
            _ => panic!("Should be STEAM"),
        }
        match &res[3].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 7, 30);
            }
            _ => panic!("Should be a TOTP"),
        }
    }
}
