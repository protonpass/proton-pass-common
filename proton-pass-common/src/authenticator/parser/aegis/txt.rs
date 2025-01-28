use crate::authenticator::parser::aegis::AegisImportError;
use crate::authenticator::AuthenticatorEntry;

pub fn parse_aegis_txt(input: &str, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, AegisImportError> {
    let mut entries = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            match AuthenticatorEntry::from_uri(trimmed, None) {
                Ok(entry) => entries.push(entry),
                Err(_) => {
                    if fail_on_error {
                        return Err(AegisImportError::Unsupported);
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::parser::aegis::test::check_export_matches;
    use crate::authenticator::test_utils::get_file_contents;

    #[test]
    fn can_parse_aegis_txt() {
        let content = get_file_contents("aegis/aegis-txt.txt");
        let parsed = parse_aegis_txt(&content, false).expect("should be able to parse");
        check_export_matches(parsed)
    }
}
