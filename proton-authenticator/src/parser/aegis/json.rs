use crate::parser::aegis::{db, encrypted, AegisImportError};
use crate::parser::ImportResult;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CommonHeader {
    slots: Option<Vec<encrypted::Slot>>,
    params: Option<encrypted::HeaderParams>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CommonRoot {
    pub header: CommonHeader,
}

pub fn parse_aegis_json(input: &str, password: Option<String>) -> Result<ImportResult, AegisImportError> {
    let root_parsed: CommonRoot = serde_json::from_str(input).map_err(|e| {
        warn!("Error parsing aegis backup file: {e:?}");
        AegisImportError::BadContent
    })?;
    let db_root = match password {
        Some(p) => {
            if root_parsed.header.slots.is_none() || root_parsed.header.params.is_none() {
                warn!("Tried to import aegis non-encrypted backup with a password");
                return Err(AegisImportError::NotEncryptedBackupWithPassword);
            }
            encrypted::decrypt_aegis_encrypted_backup(input, &p)?
        }
        None => {
            if root_parsed.header.slots.is_some() || root_parsed.header.params.is_some() {
                warn!("Tried to import aegis encrypted backup without a password");
                return Err(AegisImportError::EncryptedBackupWithNoPassword);
            }
            let root_with_db: db::CommonRootWithDb =
                serde_json::from_str(input).map_err(|_| AegisImportError::BadContent)?;
            root_with_db.db
        }
    };

    db::parse_aegis_db(db_root)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::aegis::test::check_export_matches;
    use crate::test_utils::get_file_contents;
    use crate::AuthenticatorEntryContent;

    #[test]
    fn can_import_unencrypted_json() {
        let contents = get_file_contents("aegis/aegis-json-unencrypted.json");
        let res = parse_aegis_json(&contents, None).expect("should be able to parse");
        check_export_matches(res.entries, true);
        assert_eq!(res.errors.len(), 0);
    }

    #[test]
    fn steam_entry_imported_from_aegis_json_generates_correct_code() {
        let contents = get_file_contents("aegis/aegis-json-unencrypted.json");
        let res = parse_aegis_json(&contents, None).expect("should be able to parse");

        let steam_entry = res
            .entries
            .iter()
            .find(|e| matches!(&e.content, AuthenticatorEntryContent::Steam(_)))
            .expect("entry should exist");

        let now = 1742298622;
        let code = crate::AuthenticatorClient::generate_code(steam_entry, now).expect("should generate code");
        assert_eq!("NTK5M", code.current_code);
    }

    #[test]
    fn can_import_encrypted_json() {
        let contents = get_file_contents("aegis/aegis-json-encrypted-test.json");
        let res = parse_aegis_json(&contents, Some("test".to_string())).expect("should be able to parse");
        check_export_matches(res.entries, true);
        assert_eq!(res.errors.len(), 0);
    }

    #[test]
    fn encrypted_backup_with_no_password_returns_error() {
        let encrypted = get_file_contents("aegis/aegis-json-encrypted-test.json");
        let err = parse_aegis_json(&encrypted, None).expect_err("should return an error");

        assert!(matches!(err, AegisImportError::EncryptedBackupWithNoPassword));
    }

    #[test]
    fn unencrypted_backup_with_password_returns_error() {
        let encrypted = get_file_contents("aegis/aegis-json-unencrypted.json");
        let err = parse_aegis_json(&encrypted, Some("test".to_string())).expect_err("should return an error");

        assert!(matches!(err, AegisImportError::NotEncryptedBackupWithPassword));
    }

    #[test]
    fn imports_with_missing_fields() {
        let content = get_file_contents("aegis/aegis-json-unencrypted-with-missing-fields.json");
        let res = parse_aegis_json(&content, None).expect("should be able to parse");

        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 3);

        assert_eq!("Proton", res.entries[0].issuer());
        assert_eq!("some@test.email", res.entries[0].name());

        assert_eq!("Amazon", res.entries[1].issuer());
        assert_eq!("some@account.test", res.entries[1].name());

        // Name as fallback issuer
        assert_eq!("Somename", res.entries[2].issuer());
        assert_eq!("Somename", res.entries[2].name());
    }
}
