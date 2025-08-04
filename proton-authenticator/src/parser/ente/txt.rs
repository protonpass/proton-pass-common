use super::EnteImportError;
use crate::parser::{ImportError, ImportResult};
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};

const LINE_START_MAX_LEN: usize = 20;

pub fn parse_ente_txt(input: &str) -> Result<ImportResult, EnteImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        let line_start = get_line_start(line);
        if !trimmed.is_empty() {
            match AuthenticatorEntryContent::from_uri(trimmed) {
                Ok(content) => match sanitize_content(content) {
                    Ok(sanitized) => entries.push(AuthenticatorEntry {
                        content: sanitized,
                        note: None,
                        id: AuthenticatorEntry::generate_id(),
                    }),
                    Err(e) => errors.push(ImportError {
                        context: format!("Error in line {idx}"),
                        message: format!("Could not process [{line_start}]: {e:?}"),
                    }),
                },
                Err(e) => errors.push(ImportError {
                    context: format!("Error in line {idx}"),
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

fn get_line_start(line: &str) -> String {
    let suffix = if line.len() > LINE_START_MAX_LEN { "..." } else { "" }.to_string();
    format!("{}{}", line.chars().take(20).collect::<String>(), suffix)
}

// Ente sometimes adds the issuer as a prefix to the label. MAke sure to remove it
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
        _ => Err(EnteImportError::Unsupported),
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
        assert_eq!(res.errors[0].context, "Error in line 3");
        assert!(res.errors[0].message.contains("UnsupportedUri"))
    }
}
