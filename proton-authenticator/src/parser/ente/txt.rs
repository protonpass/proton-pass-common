use super::EnteImportError;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};

pub fn parse_ente_txt(input: &str, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, EnteImportError> {
    let mut entries = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let res = match AuthenticatorEntryContent::from_uri(trimmed) {
                Ok(content) => sanitize_content(content),
                Err(_) => Err(EnteImportError::BadContent),
            };

            match res {
                Ok(content) => entries.push(AuthenticatorEntry { content, note: None }),
                Err(e) => {
                    if fail_on_error {
                        return Err(e);
                    } else {
                        continue;
                    }
                }
            }
        }
    }
    Ok(entries)
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
        let imported = parse_ente_txt(content.as_str(), false).expect("should be able to import");
        check_ente_entries(imported);
    }
}
