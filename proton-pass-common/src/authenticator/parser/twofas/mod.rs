mod parser;

#[derive(Clone, Debug)]
pub enum TwoFasImportError {
    BadContent,
    Unsupported,
    UnableToDecrypt,
    WrongPassword,
}

pub use parser::parse_2fas_file;
