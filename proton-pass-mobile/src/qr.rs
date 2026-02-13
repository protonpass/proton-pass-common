use proton_pass_common::qr::generate_svg_qr_code;
use proton_pass_common::qrcode::types::QrError as CommonQrError;

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum QrCodeError {
    DataTooLong,
    InvalidVersion,
    UnsupportedCharacterSet,
    InvalidEciDesignator,
    InvalidCharacter,
}

impl From<CommonQrError> for QrCodeError {
    fn from(value: CommonQrError) -> Self {
        match value {
            CommonQrError::DataTooLong => Self::DataTooLong,
            CommonQrError::InvalidVersion => Self::InvalidVersion,
            CommonQrError::UnsupportedCharacterSet => Self::UnsupportedCharacterSet,
            CommonQrError::InvalidEciDesignator => Self::InvalidEciDesignator,
            CommonQrError::InvalidCharacter => Self::InvalidCharacter,
        }
    }
}

#[derive(uniffi::Object)]
pub struct QrCodeGenerator;

#[uniffi::export]
impl QrCodeGenerator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn generate_svg_qr_code(&self, value: String) -> Result<String, QrCodeError> {
        generate_svg_qr_code(&value).map_err(|e| e.into())
    }
}
