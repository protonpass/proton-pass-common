use crate::parser::ThirdPartyImportError;

mod csv;
mod json;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitwardenImportError {
    BadContent,
    Unsupported,
    MissingPassword,
}

impl From<BitwardenImportError> for ThirdPartyImportError {
    fn from(value: BitwardenImportError) -> Self {
        match value {
            BitwardenImportError::BadContent => Self::BadContent,
            BitwardenImportError::Unsupported => Self::BadContent,
            BitwardenImportError::MissingPassword => Self::MissingPassword,
        }
    }
}

pub use csv::parse_bitwarden_csv;
pub use json::parse_bitwarden_json;
