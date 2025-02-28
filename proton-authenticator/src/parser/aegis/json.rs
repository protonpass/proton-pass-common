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
    let root_parsed: CommonRoot = serde_json::from_str(input).map_err(|_| AegisImportError::BadContent)?;
    let db_root = match password {
        Some(p) => {
            if root_parsed.header.slots.is_none() || root_parsed.header.params.is_none() {
                return Err(AegisImportError::NotEncryptedBackupWithPassword);
            }
            encrypted::decrypt_aegis_encrypted_backup(input, &p)?
        }
        None => {
            if root_parsed.header.slots.is_some() || root_parsed.header.params.is_some() {
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

    #[test]
    fn can_import_unencrypted_json() {
        let contents = get_file_contents("aegis/aegis-json-unencrypted.json");
        let res = parse_aegis_json(&contents, None).expect("should be able to parse");
        check_export_matches(res.entries, true);
        assert_eq!(res.errors.len(), 0);
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
}
