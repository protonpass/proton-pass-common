use super::EnteImportError;
use crate::parser::{ImportError, ImportResult};
use crate::utils::conceal;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};

fn check_if_encrypted(input: &str) -> Result<(), EnteImportError> {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(_) => Err(EnteImportError::MissingPassword),
        Err(_) => Ok(()),
    }
}

pub fn parse_ente_txt(input: &str) -> Result<ImportResult, EnteImportError> {
    check_if_encrypted(input)?;
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        let line_start = conceal(line);
        if !trimmed.is_empty() {
            match AuthenticatorEntryContent::from_uri(trimmed) {
                Ok(content) => match sanitize_content(content) {
                    Ok(sanitized) => entries.push(AuthenticatorEntry {
                        content: sanitized,
                        note: None,
                        id: AuthenticatorEntry::generate_id(),
                    }),
                    Err(e) => errors.push(ImportError {
                        context: format!("Error in line {}", idx + 1),
                        message: format!("Could not process [{line_start}]: {e:?}"),
                    }),
                },
                Err(e) => errors.push(ImportError {
                    context: format!("Error in line {}", idx + 1),
                    message: format!("Could not process [{line_start}]: {e:?}"),
                }),
            };
        }
    }

    if entries.is_empty() && !errors.is_empty() {
        Err(EnteImportError::BadContent)
    } else {
        Ok(ImportResult { entries, errors })
    }
}

// Ente sometimes adds the issuer as a prefix to the label. Make sure to remove it
fn sanitize_content(content: AuthenticatorEntryContent) -> Result<AuthenticatorEntryContent, EnteImportError> {
    match content {
        AuthenticatorEntryContent::Totp(mut totp) => {
            // Handle issuer prefix removal when both label and issuer exist
            if let (Some(label), Some(issuer)) = (&totp.label, &totp.issuer) {
                let issuer_prefix = format!("{issuer}:");
                if label.starts_with(&issuer_prefix) {
                    let edited_label = label.replace(&issuer_prefix, "");
                    totp.label = Some(edited_label);
                }
            }

            // Handle empty or missing issuer by using label as fallback
            let issuer = match &totp.issuer {
                Some(issuer) => {
                    if issuer.is_empty() {
                        totp.label.clone()
                    } else {
                        totp.issuer.clone()
                    }
                }
                None => totp.label.clone(),
            };
            totp.issuer = issuer;

            Ok(AuthenticatorEntryContent::Totp(totp))
        }
        _ => Ok(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ente::test::check_ente_entries;
    use crate::test_utils::get_file_contents;
    use proton_pass_totp::Algorithm;

    #[test]
    fn can_import_txt_file() {
        let content = get_file_contents("ente/plain.txt");
        let imported = parse_ente_txt(content.as_str()).expect("should be able to import");
        check_ente_entries(imported.entries);
    }

    #[test]
    fn can_import_txt_file_with_hotp() {
        let content = get_file_contents("ente/plain_with_hotp.txt");
        let res = parse_ente_txt(content.as_str()).expect("should be able to import");

        assert_eq!(res.entries.len(), 5);
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].context, "Error in line 4");
        assert!(res.errors[0].message.contains("UnsupportedUri"))
    }

    #[test]
    fn can_import_txt_file_with_steam_and_hotp() {
        let content = get_file_contents("ente/plain_with_steam_and_hotp.txt");
        let res = parse_ente_txt(content.as_str()).expect("should be able to import");

        assert_eq!(res.entries.len(), 2);
        assert!(matches!(res.entries[0].content, AuthenticatorEntryContent::Steam(_)));
        assert!(matches!(res.entries[1].content, AuthenticatorEntryContent::Totp(_)));

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].context, "Error in line 2");
        assert!(res.errors[0].message.contains("UnsupportedUri"))
    }

    #[test]
    fn can_detect_encrypted_file() {
        let content = get_file_contents("ente/encrypted.lowcomplexity.txt");
        let err = parse_ente_txt(content.as_str()).expect_err("should return an error");
        assert!(matches!(err, EnteImportError::MissingPassword))
    }

    #[test]
    fn can_import_with_missing_fields() {
        let content = get_file_contents("ente/plain_with_missing_fields.txt");
        let res = parse_ente_txt(&content).expect("should be able to import");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 1);

        assert_eq!("accountname", res.entries[0].name());
        assert_eq!("accountname", res.entries[0].issuer());
    }

    #[test]
    fn can_import_with_many_entries() {
        let content = get_file_contents("ente/plain_20_entries.txt");
        let res = parse_ente_txt(&content).expect("should be able to import");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 20);

        for (idx, entry) in res.entries.into_iter().enumerate() {
            assert_eq!(format!("Account {}", idx + 1), entry.name());
            assert_eq!("SECRETO", entry.secret());
        }
    }

    #[test]
    fn can_import_entry_with_literal_nulls() {
        let content = "otpauth://totp/COMPANYNAME:SOMELABEL?secret=XXXXXXXXXXXX&issuer=COMPANYNAME&algorithm=null&digits=null&period=null&codeDisplay=%7B%22pinned%22%3Afalse%2C%22trashed%22%3Afalse%2C%22lastUsedAt%22%3A0%2C%22tapCount%22%3A0%2C%22tags%22%3A%5B%5D%7D";
        let res = parse_ente_txt(content).expect("should be able to import");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 1);

        let entry = &res.entries[0];
        assert_eq!("COMPANYNAME", entry.issuer());
        assert_eq!("XXXXXXXXXXXX", entry.secret());

        let totp_params = entry.get_totp_parameters().unwrap();
        assert_eq!(Algorithm::SHA1, totp_params.algorithm);
        assert_eq!(30, totp_params.period);
        assert_eq!(6, totp_params.digits);
    }
}
