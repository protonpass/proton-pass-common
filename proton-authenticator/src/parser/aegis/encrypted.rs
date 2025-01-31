use super::AegisImportError;
use crate::parser::aegis::db::AegisDbRoot;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use scrypt::{scrypt, Params as ScryptParams};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct KeyParams {
    nonce: String,
    tag: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Slot {
    key: String,
    key_params: KeyParams,
    n: u32,
    r: u32,
    p: u32,
    salt: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct HeaderParams {
    nonce: String,
    tag: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Header {
    slots: Vec<Slot>,
    params: HeaderParams,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExportData {
    header: Header,
    db: String,
}

pub fn decrypt_aegis_encrypted_backup(input: &str, password: &str) -> Result<AegisDbRoot, AegisImportError> {
    let export_data: ExportData = serde_json::from_str(input).map_err(|_| AegisImportError::BadContent)?;
    let slot = &export_data.header.slots[0];

    // Convert hex salt string to bytes:
    let salt_bytes = hex::decode(&slot.salt).map_err(|_| AegisImportError::BadContent)?;

    // Build ScryptParams from the provided N, r, p
    let params = ScryptParams::new(slot.n.trailing_zeros() as u8, slot.r, slot.p, 32)
        .map_err(|_| AegisImportError::UnableToDecrypt)?;

    // Our derived key length should be 32 bytes for AES-256.
    let mut derived_key = [0u8; 32];
    scrypt(password.as_bytes(), &salt_bytes, &params, &mut derived_key).map_err(|_| AegisImportError::BadPassword)?;

    let encrypted_master_key = hex::decode(&slot.key).map_err(|_| AegisImportError::BadContent)?;

    // Convert nonce & tag to bytes
    let slot_nonce_bytes = hex::decode(&slot.key_params.nonce).expect("bad nonce hex");
    let slot_tag_bytes = hex::decode(&slot.key_params.tag).expect("bad tag hex");

    // Nonce must typically be 12 bytes for GCM:
    let slot_nonce = GenericArray::from_slice(&slot_nonce_bytes);

    // Tag must be 16 bytes:
    let slot_tag: GenericArray<u8, U16> = GenericArray::clone_from_slice(&slot_tag_bytes);

    // Create the AES-256-GCM instance from the derived key
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&derived_key));

    // Copy encrypted bytes into a buffer we can decrypt in place
    let mut master_key_ciphertext = encrypted_master_key.clone();

    // Decrypt in place, providing the tag separately
    cipher
        .decrypt_in_place_detached(
            slot_nonce,
            // optional associated data:
            b"",
            &mut master_key_ciphertext,
            aes_gcm::Tag::from_slice(&slot_tag),
        )
        .map_err(|_| AegisImportError::BadPassword)?;

    // 5.1 Decode base64 ciphertext
    let db_ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&export_data.db)
        .map_err(|_| AegisImportError::BadContent)?;

    // 5.2 Decode the JSON's db nonce & tag from hex
    let db_nonce_bytes = hex::decode(&export_data.header.params.nonce).map_err(|_| AegisImportError::BadContent)?;
    let db_tag_bytes = hex::decode(&export_data.header.params.tag).map_err(|_| AegisImportError::BadContent)?;

    // Convert to AES-GCM types
    let db_nonce = GenericArray::from_slice(&db_nonce_bytes);
    let db_tag: GenericArray<u8, U16> = GenericArray::clone_from_slice(&db_tag_bytes);

    // 5.3 Create a new AES-256-GCM instance, but this time with the decrypted “master key”:
    let master_key = &master_key_ciphertext; // from step 4
    let db_cipher = Aes256Gcm::new(GenericArray::from_slice(master_key));

    // Copy the ciphertext to a mutable buffer for in-place decryption
    let mut db_ciphertext_mut = db_ciphertext.clone();

    db_cipher
        .decrypt_in_place_detached(
            db_nonce,
            b"", // no additional authenticated data
            &mut db_ciphertext_mut,
            aes_gcm::Tag::from_slice(&db_tag),
        )
        .map_err(|_| AegisImportError::UnableToDecrypt)?;

    let as_str = String::from_utf8_lossy(&db_ciphertext_mut);

    let parsed: AegisDbRoot = serde_json::from_str(&as_str).map_err(|_| AegisImportError::BadContent)?;
    Ok(parsed)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents;

    #[test]
    fn invalid_key_returns_error() {
        let input = get_file_contents("aegis/aegis-json-encrypted-test.json");
        let err = decrypt_aegis_encrypted_backup(&input, "invalid").expect_err("should not be able to decrypt");
        assert!(matches!(err, AegisImportError::BadPassword));
    }
}
