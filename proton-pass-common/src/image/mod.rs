use image::{imageops::FilterType, GenericImageView, ImageError, ImageFormat};
use zenwebp::{EncodeRequest, LossyConfig, PixelLayout};

/// Maximum desired image size after compression
const TARGET_SIZE: u32 = 10 * 1024; // 10kb

/// Maximum allowed dimensions for the input image, otherwise resized to this size
const MAX_DIMENSIONS: u32 = 256;

/// Max input size to avoid memory overflows
const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Debug)]
pub enum ConvertImageError {
    /// Unsupported image format
    UnsupportedInputFormat,

    /// Image conversion failed
    Image(String),
}

impl std::fmt::Display for ConvertImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertImageError::UnsupportedInputFormat => write!(f, "Unsupported input format"),
            ConvertImageError::Image(msg) => write!(f, "Image error: {}", msg),
        }
    }
}

impl From<ImageError> for ConvertImageError {
    fn from(err: ImageError) -> Self {
        ConvertImageError::Image(err.to_string())
    }
}

/// Converts an image (JPEG, PNG, or WebP) to a 256x256 WebP with lossy compression to a given size.
/// If the input image is smaller than 256x256, it will be converted to WebP without resizing.
pub fn image_bytes_to_256_webp(input: &[u8]) -> Result<Vec<u8>, ConvertImageError> {
    if input.len() > MAX_INPUT_SIZE {
        return Err(ConvertImageError::Image(format!("Image too big. Max size allowed: {MAX_INPUT_SIZE}")));
    }

    let format = image::guess_format(input).map_err(|_| ConvertImageError::UnsupportedInputFormat)?;

    match format {
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP => {}
        _ => return Err(ConvertImageError::UnsupportedInputFormat),
    }

    let img = image::load_from_memory_with_format(input, format)?;
    let (width, height) = img.dimensions();

    let output_img = if width > MAX_DIMENSIONS || height > MAX_DIMENSIONS {
        img.resize(MAX_DIMENSIONS, MAX_DIMENSIONS, FilterType::Lanczos3)
    } else {
        img
    };

    let rgba = output_img.to_rgba8();
    let width = output_img.width();
    let height = output_img.height();
    let config = LossyConfig::new().with_target_size(TARGET_SIZE);
    let webp_bytes = EncodeRequest::lossy(&config, rgba.as_raw(), PixelLayout::Rgba8, width, height)
        .encode()
        .map_err(|e| ConvertImageError::Image(format!("WebP encoding failed: {:?}", e)))?;
    Ok(webp_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_image(name: &str) -> Vec<u8> {
        let crate_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let file_path = crate_path.join("test_data").join("file_format").join(name);
        std::fs::read(&file_path).unwrap_or_else(|_| panic!("Cannot open {}", file_path.display()))
    }

    #[test]
    fn test_jpeg_conversion() {
        let jpeg_bytes = get_test_image("sample.jpg");
        let result = image_bytes_to_256_webp(&jpeg_bytes);
        assert!(result.is_ok());

        let webp_bytes = result.unwrap();
        // Verify it's a valid WebP by checking the RIFF header
        assert_eq!(&webp_bytes[0..4], &[0x52, 0x49, 0x46, 0x46]); // 'RIFF'
    }

    #[test]
    fn test_png_conversion() {
        let png_bytes = get_test_image("sample.png");
        let result = image_bytes_to_256_webp(&png_bytes);
        assert!(result.is_ok());

        let output_bytes = result.unwrap();
        // Verify it's a valid WebP
        assert_eq!(&output_bytes[0..4], &[0x52, 0x49, 0x46, 0x46]); // 'RIFF'
    }

    #[test]
    fn test_unsupported_format() {
        // Try with a text file which should fail
        let txt_bytes = get_test_image("sample.txt");
        let result = image_bytes_to_256_webp(&txt_bytes);

        // The error might be UnsupportedInputFormat or an ImageError from guess_format
        assert!(result.is_err());
    }
}
