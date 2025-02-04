use crate::parser::aegis::AegisImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;

pub fn parse_aegis_txt(input: &str) -> Result<ImportResult, AegisImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            match AuthenticatorEntry::from_uri(trimmed, None) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    errors.push(ImportError {
                        context: format!("Error in line {idx}"),
                        message: format!("Error in line [{}] : {:?}", trimmed, e),
                    });
                }
            }
        }
    }

    Ok(ImportResult { entries, errors })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::aegis::test::check_export_matches;
    use crate::test_utils::get_file_contents;

    #[test]
    fn can_parse_aegis_txt() {
        let content = get_file_contents("aegis/aegis-txt.txt");
        let parsed = parse_aegis_txt(&content).expect("should be able to parse");
        check_export_matches(parsed.entries);
        assert!(parsed.errors.is_empty());
    }
}
