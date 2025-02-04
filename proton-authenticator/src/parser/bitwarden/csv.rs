use super::BitwardenImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;

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

pub fn parse_bitwarden_csv(input: &str) -> Result<ImportResult, BitwardenImportError> {
    let processed = process_string(input);
    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(processed.as_bytes());

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, result) in csv_reader.records().enumerate() {
        match result {
            Ok(record) => match record.get(5) {
                Some(r) => match AuthenticatorEntry::from_uri(r, None) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        errors.push(ImportError {
                            context: format!("Error in record {idx}"),
                            message: format!("Error parsing entry: {:?}", e),
                        });
                    }
                },
                None => errors.push(ImportError {
                    context: format!("Error in record {idx}"),
                    message: format!("Malformed line: {:?}", record),
                }),
            },
            Err(e) => errors.push(ImportError {
                context: format!("Error in record {idx}"),
                message: format!("Malformed line: {:?}", e),
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
    fn can_parse_bitwarden_csv() {
        let input = get_file_contents("bitwarden/bitwarden.csv");

        let res = parse_bitwarden_csv(&input).expect("Should be able to parse the CSV");
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
