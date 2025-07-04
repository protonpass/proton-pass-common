use super::EnteImportError;
use crate::parser::{ImportError, ImportResult};
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};

pub fn parse_ente_txt(input: &str) -> Result<ImportResult, EnteImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
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
                        message: format!("Could not process [{line}]: {e:?}"),
                    }),
                },
                Err(e) => errors.push(ImportError {
                    context: format!("Error in line {idx}"),
                    message: format!("Could not process [{line}]: {e:?}"),
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
}
