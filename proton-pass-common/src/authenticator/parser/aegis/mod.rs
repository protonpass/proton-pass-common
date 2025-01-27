mod db;
mod encrypted;
mod json;

#[derive(Clone, Debug)]
pub enum AegisImportError {
    Unsupported,
    BadContent,
    BadPassword,
    NotEncryptedBackupWithPassword,
    EncryptedBackupWithNoPassword,
    UnableToDecrypt,
}

pub use json::parse_aegis_json;
