use crate::parser::ThirdPartyImportError;

mod json;

#[derive(Clone, Debug)]
pub enum LastPassImportError {
    BadContent(String),
}

impl From<LastPassImportError> for ThirdPartyImportError {
    fn from(e: LastPassImportError) -> Self {
        match e {
            LastPassImportError::BadContent(_) => Self::BadContent,
        }
    }
}

pub use json::parse_lastpass_json;
