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
        AuthenticatorEntryContent::Totp(mut totp) => match (&totp.label, &totp.issuer) {
            (Some(label), Some(issuer)) => {
                let issuer_prefix = format!("{issuer}:");
                if label.starts_with(&issuer_prefix) {
                    let edited_label = label.replace(&issuer_prefix, "");
                    totp.label = Some(edited_label);
                }
                Ok(AuthenticatorEntryContent::Totp(totp))
            }
            _ => Ok(AuthenticatorEntryContent::Totp(totp)),
        },
        _ => Ok(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ente::test::check_ente_entries;
    use crate::test_utils::get_file_contents;

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
}
