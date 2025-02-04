use crate::parser::ThirdPartyImportError;

mod parser;

#[derive(Clone, Debug)]
pub enum TwoFasImportError {
    BadContent,
    Unsupported,
    UnableToDecrypt,
    WrongPassword,
}

impl From<TwoFasImportError> for ThirdPartyImportError {
    fn from(e: TwoFasImportError) -> Self {
        Self::TwoFas(e)
    }
}

pub use parser::parse_2fas_file;
