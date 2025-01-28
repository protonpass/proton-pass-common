mod json;

#[derive(Clone, Debug)]
pub enum LastPassImportError {
    BadContent(String),
    Unsupported,
    UnableToDecrypt,
}

pub use json::parse_lastpass_json;
