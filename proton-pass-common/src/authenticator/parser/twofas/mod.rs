mod encrypted;

#[derive(Clone, Debug)]
pub enum TwoFasImportError {
    BadContent,
    Unsupported,
    UnableToDecrypt,
    WrongPassword,
}

pub use encrypted::parse_2fas_file;
