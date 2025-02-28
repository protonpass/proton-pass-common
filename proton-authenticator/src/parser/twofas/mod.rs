use crate::parser::ThirdPartyImportError;

mod parser;

#[derive(Clone, Debug)]
pub enum TwoFasImportError {
    BadContent,
    Unsupported,
    UnableToDecrypt,
    WrongPassword,
    MissingPassword,
}

impl From<TwoFasImportError> for ThirdPartyImportError {
    fn from(e: TwoFasImportError) -> Self {
        match e {
            TwoFasImportError::BadContent => Self::BadContent,
            TwoFasImportError::Unsupported => Self::BadContent,
            TwoFasImportError::UnableToDecrypt => Self::DecryptionFailed,
            TwoFasImportError::WrongPassword => Self::BadPassword,
            TwoFasImportError::MissingPassword => Self::MissingPassword,
        }
    }
}

pub use parser::parse_2fas_file;
