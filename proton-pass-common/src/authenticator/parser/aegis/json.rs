use crate::authenticator::parser::aegis::{db, encrypted, AegisImportError};
use crate::authenticator::AuthenticatorEntry;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CommonHeader {
    slots: Option<Vec<encrypted::Slot>>,
    params: Option<encrypted::HeaderParams>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CommonRoot {
    pub header: CommonHeader,
}

pub fn parse_aegis_json(
    input: &str,
    password: Option<String>,
    fail_on_error: bool,
) -> Result<Vec<AuthenticatorEntry>, AegisImportError> {
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

    db::parse_aegis_db(db_root, fail_on_error)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::authenticator::test_utils::get_file_contents;

    fn check_export_matches(entries: Vec<AuthenticatorEntry>) {
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn can_import_unencrypted_json() {
        let contents = get_file_contents("aegis/aegis-json-unencrypted.json");
        let res = parse_aegis_json(&contents, None, true).expect("should be able to parse");
        check_export_matches(res)
    }

    #[test]
    fn can_import_encrypted_json() {
        let contents = get_file_contents("aegis/aegis-json-encrypted-test.json");
        let res = parse_aegis_json(&contents, Some("test".to_string()), true).expect("should be able to parse");
        check_export_matches(res)
    }

    #[test]
    fn encrypted_backup_with_no_password_returns_error() {
        let encrypted = get_file_contents("aegis/aegis-json-encrypted-test.json");
        let err = parse_aegis_json(&encrypted, None, true).expect_err("should return an error");

        assert!(matches!(err, AegisImportError::EncryptedBackupWithNoPassword));
    }

    #[test]
    fn unencrypted_backup_with_password_returns_error() {
        let encrypted = get_file_contents("aegis/aegis-json-unencrypted.json");
        let err = parse_aegis_json(&encrypted, Some("test".to_string()), true).expect_err("should return an error");

        assert!(matches!(err, AegisImportError::NotEncryptedBackupWithPassword));
    }
}
