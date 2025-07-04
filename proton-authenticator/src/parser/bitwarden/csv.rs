use super::BitwardenImportError;
use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
use csv::StringRecord;
use proton_pass_totp::totp::TOTP;

pub fn parse_bitwarden_csv(input: &str) -> Result<ImportResult, BitwardenImportError> {
    let mut csv_reader = csv::ReaderBuilder::new().flexible(true).from_reader(input.as_bytes());

    let headers = match csv_reader.headers() {
        Ok(headers) => headers,
        Err(e) => {
            warn!("Bitwarden csv does not have headers: {e:?}");
            return Err(BitwardenImportError::BadContent);
        }
    };

    let totp_idx = find_header_index(headers, "login_totp")?;
    let name_idx = find_header_index(headers, "name")?;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, result) in csv_reader.records().enumerate() {
        match result {
            Ok(record) => match record.get(totp_idx) {
                Some(r) => parse_line(&record, r, &mut entries, &mut errors, idx, name_idx),
                None => errors.push(ImportError {
                    context: format!("Error in record {idx}"),
                    message: format!("Malformed line: {record:?}"),
                }),
            },
            Err(e) => errors.push(ImportError {
                context: format!("Error in record {idx}"),
                message: format!("Malformed line: {e:?}"),
            }),
        }
    }

    Ok(ImportResult { entries, errors })
}

fn find_header_index(headers: &StringRecord, header: &str) -> Result<usize, BitwardenImportError> {
    match headers.iter().position(|h| h == header) {
        Some(idx) => Ok(idx),
        None => {
            warn!("Bitwarden csv does not have the {header} header");
            Err(BitwardenImportError::BadContent)
        }
    }
}

fn parse_line(
    record: &StringRecord,
    uri: &str,
    entries: &mut Vec<AuthenticatorEntry>,
    errors: &mut Vec<ImportError>,
    idx: usize,
    name_idx: usize,
) {
    if uri.starts_with("otpauth://") {
        parse_totp_line(uri, record, entries, errors, idx, name_idx);
    } else if uri.starts_with("steam://") {
        parse_steam_line(record, uri, entries, errors, idx, name_idx)
    } else {
        errors.push(ImportError {
            context: format!("Error in record {idx}"),
            message: format!("Unknown URI format: {uri}"),
        });
    }
}

fn parse_totp_line(
    uri: &str,
    record: &StringRecord,
    entries: &mut Vec<AuthenticatorEntry>,
    errors: &mut Vec<ImportError>,
    idx: usize,
    name_idx: usize,
) {
    match TOTP::from_uri(uri) {
        Ok(mut totp) => {
            let parse_label = match totp.label {
                None => true,
                Some(ref l) => l.is_empty(),
            };

            if parse_label {
                if let Some(name) = record.get(name_idx) {
                    totp.label = Some(name.trim().to_string());
                }
            }

            entries.push(AuthenticatorEntry {
                content: AuthenticatorEntryContent::Totp(totp),
                note: None,
                id: AuthenticatorEntry::generate_id(),
            });
        }
        Err(e) => {
            errors.push(ImportError {
                context: format!("Error in record {idx}"),
                message: format!("Error parsing TOTP uri [{uri}]: {e:?}"),
            });
        }
    }
}

fn parse_steam_line(
    record: &StringRecord,
    uri: &str,
    entries: &mut Vec<AuthenticatorEntry>,
    errors: &mut Vec<ImportError>,
    idx: usize,
    name_idx: usize,
) {
    match SteamTotp::new_from_uri(uri) {
        Ok(mut steam) => {
            // Get custom label from CSV
            if let Some(name) = record.get(name_idx) {
                steam.name = Some(name.to_string());
            }
            entries.push(AuthenticatorEntry {
                content: AuthenticatorEntryContent::Steam(steam),
                note: None,
                id: AuthenticatorEntry::generate_id(),
            });
        }
        Err(e) => {
            errors.push(ImportError {
                context: format!("Error in record {idx}"),
                message: format!("Error parsing steam uri [{uri}]: {e:?}"),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents;
    use crate::AuthenticatorEntryContent;
    use proton_pass_totp::algorithm::Algorithm;
    use proton_pass_totp::totp::TOTP;

    fn check_totp(entry: &TOTP, algorithm: Algorithm, digits: u8, period: u16, label: &str) {
        assert_eq!(algorithm, entry.algorithm.expect("Should have an algorithm"));
        assert_eq!(digits, entry.digits.expect("Should have digits"));
        assert_eq!(period, entry.period.expect("Should have period"));
        assert_eq!(label, entry.label.clone().expect("Should have label"));
    }

    #[test]
    fn can_parse_bitwarden_csv() {
        let input = get_file_contents("bitwarden/bitwarden.csv");

        let res = parse_bitwarden_csv(&input).expect("Should be able to parse the CSV");
        assert!(res.errors.is_empty(), "Errors should be empty: {:?}", res.errors);

        let entries = res.entries;
        assert_eq!(entries.len(), 4);

        match &entries[0].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA256, 8, 15, "LABEL_256_8_15");
            }
            _ => panic!("Should be a TOTP"),
        }
        match &entries[1].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 6, 30, "LABEL_DEFAULT");
            }
            _ => panic!("Should be a TOTP"),
        }
        match &entries[2].content {
            AuthenticatorEntryContent::Steam(steam) => {
                assert_eq!(steam.name.clone().expect("Should have a name"), "SteamName");
            }
            _ => panic!("Should be STEAM"),
        }
        match &entries[3].content {
            AuthenticatorEntryContent::Totp(totp) => {
                check_totp(totp, Algorithm::SHA1, 7, 30, "Seven digit username");
            }
            _ => panic!("Should be a TOTP"),
        }
    }

    #[test]
    fn can_parse_sample_bitwarden_csv() {
        let input = get_file_contents("bitwarden/bitwarden_sample.csv");
        let res = parse_bitwarden_csv(&input).expect("Should be able to parse the CSV");
        assert!(res.errors.is_empty());

        let entries = res.entries;

        assert_eq!(entries.len(), 3);

        fn check_label(entry: &AuthenticatorEntry, label: &str) {
            match &entry.content {
                AuthenticatorEntryContent::Totp(totp) => {
                    check_totp(totp, Algorithm::SHA1, 6, 30, label);
                }
                _ => panic!("Should be a TOTP"),
            }
        }

        check_label(&entries[0], "Code 2");
        check_label(&entries[1], "Code 3");
        check_label(&entries[2], "Code1");
    }

    #[test]
    fn steam_entry_imported_from_bitwarden_csv_generates_correct_code() {
        let input = get_file_contents("bitwarden/bitwarden.csv");

        let res = parse_bitwarden_csv(&input).expect("Should be able to parse the CSV");
        let entries = res.entries;
        assert_eq!(entries.len(), 4);

        let steam_entry = entries
            .iter()
            .find(|e| matches!(&e.content, AuthenticatorEntryContent::Steam(_)))
            .expect("should contain a steam entry");

        let now = 1742298622;
        let code = crate::AuthenticatorClient::generate_code(steam_entry, now).expect("should generate code");
        assert_eq!("NTK5M", code.current_code);
    }
}
