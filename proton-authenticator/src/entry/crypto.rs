use crate::crypto::{decrypt, encrypt, EncryptionTag};
use crate::{AuthenticatorEntry, AuthenticatorError};

pub fn encrypt_entries(entries: Vec<AuthenticatorEntry>, mut key: Vec<u8>) -> Result<Vec<Vec<u8>>, AuthenticatorError> {
    let mut encrypted_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let serialized = entry.serialize().map_err(|e| {
            AuthenticatorError::SerializationError(format!("failed to serialize authenticator entry: {e:?}"))
        })?;

        let encrypted = encrypt(&serialized, &key, EncryptionTag::Entry)
            .map_err(|e| AuthenticatorError::Unknown(format!("failed to encrypt entry: {e:?}")))?;

        encrypted_entries.push(encrypted);
    }

    key.clear();
    Ok(encrypted_entries)
}

pub fn decrypt_entries(entries: Vec<Vec<u8>>, mut key: Vec<u8>) -> Result<Vec<AuthenticatorEntry>, AuthenticatorError> {
    let mut decrypted_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let decrypted = decrypt(&entry, &key, EncryptionTag::Entry)
            .map_err(|e| AuthenticatorError::Unknown(format!("failed to decrypt entry: {e:?}")))?;

        let deserialized = AuthenticatorEntry::deserialize(&decrypted).map_err(|e| {
            AuthenticatorError::SerializationError(format!("failed to deserialize authenticator entry: {e:?}"))
        })?;

        decrypted_entries.push(deserialized);
    }

    key.clear();
    Ok(decrypted_entries)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::generate_encryption_key;
    use crate::entry::serializer::deserialize_entry;

    #[test]
    fn test_encrypt_entries_empty_list() {
        let res = encrypt_entries(vec![], generate_encryption_key()).expect("should not fail");
        assert!(res.is_empty());
    }

    #[test]
    fn test_encrypt_entries_can_be_decrypted() {
        let key = generate_encryption_key();
        let e1 = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL1?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15",
            Some("".to_string()),
        )
        .unwrap();
        let e2 = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL2?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15",
            None,
        )
        .unwrap();
        let e3 = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL2?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15",
            Some("note".to_string()),
        )
        .unwrap();
        let res =
            encrypt_entries(vec![e1.clone(), e2.clone(), e3.clone()], key.clone()).expect("should be able to encrypt");
        assert_eq!(res.len(), 3);

        let decrypted_e1 = decrypt(&res[0], &key, EncryptionTag::Entry).expect("should be able to decrypt");
        let deserialized_e1 = deserialize_entry(&decrypted_e1).expect("should be able to deserialize");
        assert_eq!(deserialized_e1, e1);

        let decrypted_e2 = decrypt(&res[1], &key, EncryptionTag::Entry).expect("should be able to decrypt");
        let deserialized_e2 = deserialize_entry(&decrypted_e2).expect("should be able to deserialize");
        assert_eq!(deserialized_e2, e2);

        let decrypted_e3 = decrypt(&res[2], &key, EncryptionTag::Entry).expect("should be able to decrypt");
        let deserialized_e3 = deserialize_entry(&decrypted_e3).expect("should be able to deserialize");
        assert_eq!(deserialized_e3, e3);
    }

    #[test]
    fn test_decrypt_entries_empty_list() {
        let res = decrypt_entries(vec![], generate_encryption_key()).expect("should not fail");
        assert!(res.is_empty());
    }
}
