use super::BitwardenImportError;
use crate::authenticator::entry::AuthenticatorEntryError;
use crate::authenticator::AuthenticatorEntry;

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
                Some(r) => match AuthenticatorEntry::from_uri(r) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        if fail_on_error {
                            return match e {
                                AuthenticatorEntryError::ParseError => Err(BitwardenImportError::BadContent),
                                AuthenticatorEntryError::UnsupportedUri => Err(BitwardenImportError::Unsupported),
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
        let input = r#"folder,favorite,type,name,login_uri,login_totp
,,1,ISSUER,,otpauth://totp/ISSUER%3ALABEL_256_8_15?secret=SECRETDATA&algorithm=SHA256&digits=8&period=15&issuer=ISSUER,ISSUER,15,8
,,1,ISSUER_DEFAULT,,otpauth://totp/ISSUER_DEFAULT%3ALABEL_DEFAULT?secret=SOMESECRET&algorithm=SHA1&digits=6&period=30&issuer=ISSUER_DEFAULT,ISSUER_DEFAULT,30,6
,,1,SteamName,,steam://STEAMKEY,SteamName,30,6
,,1,SevenDigits,,otpauth://totp/SevenDigits%3ASeven%20digit%20username?secret=SEVENDIGITSECRET&algorithm=SHA1&digits=7&period=30&issuer=SevenDigits,SevenDigits,30,7
        "#;

        let res = parse_bitwarden_csv(input, false).expect("Should be able to parse the CSV");
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
