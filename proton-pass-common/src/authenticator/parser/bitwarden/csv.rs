use super::BitwardenImportError;
use crate::authenticator::{AuthenticatorEntry, AuthenticatorEntryError};

fn process_string(input: &str) -> String {
    let mut lines = Vec::new();
    for line in input.lines() {
        if line.starts_with("folder,favorite") {
            continue;
        }
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }

    lines.join("\n")
}

pub fn parse_bitwarden_csv(input: &str, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, BitwardenImportError> {
    let processed = process_string(input);
    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(processed.as_bytes());

    let mut entries = Vec::new();
    for result in csv_reader.records() {
        match result {
            Ok(record) => match record.get(5) {
                Some(r) => match AuthenticatorEntry::from_uri(r, None) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        if fail_on_error {
                            return match e {
                                AuthenticatorEntryError::ParseError => Err(BitwardenImportError::BadContent),
                                AuthenticatorEntryError::UnsupportedUri => Err(BitwardenImportError::Unsupported),
                                AuthenticatorEntryError::SerializationError(_) => Err(BitwardenImportError::BadContent),
                            };
                        }
                    }
                },
                None => {
                    if fail_on_error {
                        return Err(BitwardenImportError::BadContent);
                    }
                }
            },
            Err(_) => {
                if fail_on_error {
                    return Err(BitwardenImportError::BadContent);
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::authenticator::test_utils::get_file_contents;
    use crate::authenticator::AuthenticatorEntryContent;
    use crate::totp::algorithm::Algorithm;
    use crate::totp::totp::TOTP;

    fn check_totp(entry: &TOTP, algorithm: Algorithm, digits: u8, period: u16) {
        assert_eq!(algorithm, entry.algorithm.expect("Should have an algorithm"));
        assert_eq!(digits, entry.digits.expect("Should have digits"));
        assert_eq!(period, entry.period.expect("Should have period"));
    }

    #[test]
    fn can_parse_bitwarden_csv() {
        let input = get_file_contents("bitwarden/bitwarden.csv");

        let res = parse_bitwarden_csv(&input, false).expect("Should be able to parse the CSV");
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
