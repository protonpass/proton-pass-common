use crate::parser::aegis::AegisImportError;
use crate::parser::{ImportError, ImportResult};
use crate::AuthenticatorEntry;

const LINE_START_MAX_LEN: usize = 20;

pub fn parse_aegis_txt(input: &str) -> Result<ImportResult, AegisImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let line_start = get_line_start(trimmed);
            match AuthenticatorEntry::from_uri(trimmed, None) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    errors.push(ImportError {
                        context: format!("Error in line {idx}"),
                        message: format!("Error in line [{line_start}] : {e:?}"),
                    });
                }
            }
        }
    }

    Ok(ImportResult { entries, errors })
}

fn get_line_start(line: &str) -> String {
    let suffix = if line.len() > LINE_START_MAX_LEN { "..." } else { "" }.to_string();
    format!("{}{}", line.chars().take(20).collect::<String>(), suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::aegis::test::check_export_matches;
    use crate::test_utils::get_file_contents;
    use crate::AuthenticatorEntryContent;

    #[test]
    fn can_parse_aegis_txt() {
        let content = get_file_contents("aegis/aegis-txt.txt");
        let parsed = parse_aegis_txt(&content).expect("should be able to parse");
        check_export_matches(parsed.entries, false);
        assert!(parsed.errors.is_empty());
    }

    #[test]
    fn steam_entry_imported_from_aegis_txt_generates_correct_code() {
        let content = get_file_contents("aegis/aegis-txt.txt");
        let parsed = parse_aegis_txt(&content).expect("should be able to parse");

        let steam_entry = parsed
            .entries
            .iter()
            .find(|e| matches!(&e.content, AuthenticatorEntryContent::Steam(_)))
            .expect("entry should exist");

        let now = 1742298622;
        let code = crate::AuthenticatorClient::generate_code(steam_entry, now).expect("should generate code");
        assert_eq!("NTK5M", code.current_code);
    }
}
