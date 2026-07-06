use proton_pass_common::image::{image_bytes_to_256_webp, ConvertImageError as CommonConvertImageError};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ConvertImageError {
    UnsupportedInputFormat,
    Image(String),
}

impl From<CommonConvertImageError> for ConvertImageError {
    fn from(value: CommonConvertImageError) -> Self {
        match value {
            CommonConvertImageError::UnsupportedInputFormat => Self::UnsupportedInputFormat,
            CommonConvertImageError::Image(msg) => Self::Image(msg),
        }
    }
}

#[derive(uniffi::Object)]
pub struct ImageConverter;

#[uniffi::export]
impl ImageConverter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Converts an image (JPEG, PNG, or WebP) to a 256x256 WebP with lossy compression.
    pub fn convert_to_256_webp(&self, input: Vec<u8>) -> Result<Vec<u8>, ConvertImageError> {
        image_bytes_to_256_webp(&input).map_err(|e| e.into())
    }
}
