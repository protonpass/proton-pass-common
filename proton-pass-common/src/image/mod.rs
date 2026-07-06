use std::io::Cursor;

use image::{imageops::FilterType, GenericImageView, ImageError, ImageFormat};

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

/// Converts an image (JPEG, PNG, or WebP) to a 256x256 PNG.
/// If the input image is smaller than 256x256, it will be converted to PNG without resizing.
///
/// # Arguments
/// * `input` - The image bytes in JPEG, PNG, or WebP format
///
/// # Returns
/// * `Ok(Vec<u8>)` - The converted PNG image bytes
/// * `Err(ConvertImageError)` - If the format is unsupported or conversion fails
pub fn image_bytes_to_256_png(input: &[u8]) -> Result<Vec<u8>, ConvertImageError> {
    let format = image::guess_format(input)?;

    match format {
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP => {}
        _ => return Err(ConvertImageError::UnsupportedInputFormat),
    }

    let img = image::load_from_memory_with_format(input, format)?;
    let (width, height) = img.dimensions();

    let output_img = if width > 256 || height > 256 {
        img.resize(256, 256, FilterType::Lanczos3)
    } else {
        img
    };

    let mut output = Cursor::new(Vec::new());
    output_img.write_to(&mut output, ImageFormat::Png)?;

    Ok(output.into_inner())
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
        let result = image_bytes_to_256_png(&jpeg_bytes);
        assert!(result.is_ok());

        let png_bytes = result.unwrap();
        // Verify it's a valid PNG by checking the magic number
        assert_eq!(&png_bytes[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
    }

    #[test]
    fn test_png_conversion() {
        let png_bytes = get_test_image("sample.png");
        let result = image_bytes_to_256_png(&png_bytes);
        assert!(result.is_ok());

        let output_bytes = result.unwrap();
        // Verify it's a valid PNG
        assert_eq!(&output_bytes[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
    }

    #[test]
    fn test_unsupported_format() {
        // Try with a text file which should fail
        let txt_bytes = get_test_image("sample.txt");
        let result = image_bytes_to_256_png(&txt_bytes);

        // The error might be UnsupportedInputFormat or an ImageError from guess_format
        assert!(result.is_err());
    }

    #[test]
    fn test_output_is_png() {
        let jpeg_bytes = get_test_image("sample.jpg");
        let result = image_bytes_to_256_png(&jpeg_bytes).unwrap();

        // PNG signature: 89 50 4E 47 0D 0A 1A 0A
        assert_eq!(result[0], 0x89);
        assert_eq!(result[1], 0x50); // 'P'
        assert_eq!(result[2], 0x4E); // 'N'
        assert_eq!(result[3], 0x47); // 'G'
    }
}
