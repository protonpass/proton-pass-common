use crate::parser::ThirdPartyImportError;

mod csv;
mod json;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitwardenImportError {
    BadContent,
    Unsupported,
    EncryptedBackup(String),
}

impl From<BitwardenImportError> for ThirdPartyImportError {
    fn from(value: BitwardenImportError) -> Self {
        Self::Bitwarden(value)
    }
}

pub use csv::parse_bitwarden_csv;
pub use json::parse_bitwarden_json;
