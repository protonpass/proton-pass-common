mod csv;
mod json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwardenImportError {
    BadContent,
    Unsupported,
}

pub use csv::parse_bitwarden_csv;
pub use json::parse_bitwarden_json;
