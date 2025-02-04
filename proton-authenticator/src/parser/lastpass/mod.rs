use crate::parser::ThirdPartyImportError;

mod json;

#[derive(Clone, Debug)]
pub enum LastPassImportError {
    BadContent(String),
    Unsupported,
    UnableToDecrypt,
}

impl From<LastPassImportError> for ThirdPartyImportError {
    fn from(e: LastPassImportError) -> Self {
        Self::LastPass(e)
    }
}

pub use json::parse_lastpass_json;
