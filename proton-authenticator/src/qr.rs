use rxing::{
    common::HybridBinarizer, BarcodeFormat, BinaryBitmap, DecodeHintValue, DecodeHints, Luma8LuminanceSource,
    MultiFormatReader, Reader,
};
use std::collections::HashSet;

pub fn parse_qr_code(input: &[u8]) -> Option<String> {
    let img = match image::load_from_memory(input) {
        Ok(img) => img.to_rgba8(),
        Err(e) => {
            warn!("Error loading image from memory: {e:?}");
            return None;
        }
    };

    let image_bytes = img.to_vec();
    let luma = convert_image_to_luma(&image_bytes);

    let width = img.width();
    let height = img.height();

    let mut multi_format_reader = MultiFormatReader::default();
    let hints = get_hints();
    match multi_format_reader.decode_with_hints(
        &mut BinaryBitmap::new(HybridBinarizer::new(Luma8LuminanceSource::new(luma, width, height))),
        &hints,
    ) {
        Ok(decoded) => Some(decoded.getText().to_string()),
        Err(e) => {
            warn!("Error decoding QR code: {:?}", e);
            None
        }
    }
}

fn convert_image_to_luma(data: &[u8]) -> Vec<u8> {
    let mut luma_data = Vec::with_capacity(data.len() / 4);
    for src_pixel in data.chunks_exact(4) {
        let [red, green, blue, alpha] = src_pixel else {
            continue;
        };
        let pixel = if *alpha == 0 {
            // white, so we know its luminance is 255
            0xFF
        } else {
            // .299R + 0.587G + 0.114B (YUV/YIQ for PAL and NTSC),
            // (306*R) >> 10 is approximately equal to R*0.299, and so on.
            // 0x200 >> 10 is 0.5, it implements rounding.

            ((306 * (*red as u64) + 601 * (*green as u64) + 117 * (*blue as u64) + 0x200) >> 10) as u8
        };
        luma_data.push(pixel);
    }

    luma_data
}

fn get_hints() -> DecodeHints {
    DecodeHints::default()
        .with(DecodeHintValue::TryHarder(true))
        .with(DecodeHintValue::PureBarcode(false))
        .with(DecodeHintValue::PossibleFormats(HashSet::from([
            BarcodeFormat::QR_CODE,
        ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn read_file(filename: &str) -> Vec<u8> {
        fs::read(format!("test_data/qr/{filename}")).unwrap_or_else(|_| panic!("Failed to read test data {filename}"))
    }

    fn parse_google_authenticator_qr(filename: &str) {
        let input = read_file(filename);
        let result = parse_qr_code(&input);

        let text = result.expect("Should parse QR code");
        assert!(text.starts_with("otpauth-migration://"));
    }

    #[test]
    fn parse_example_qr_code() {
        let input = read_file("example.png");
        let result = parse_qr_code(&input);

        let text = result.expect("Should parse QR code");
        assert_eq!("This is an example", text);
    }

    #[test]
    fn parse_google_authenticator_qr_code_1() {
        parse_google_authenticator_qr("GoogleAuthenticatorExport_1.png")
    }

    #[test]
    fn parse_google_authenticator_qr_code_2() {
        parse_google_authenticator_qr("GoogleAuthenticatorExport_2.png")
    }

    #[test]
    fn parse_google_authenticator_qr_code_3() {
        parse_google_authenticator_qr("GoogleAuthenticatorExport_3.png")
    }

    #[test]
    fn parse_code_in_screenshot() {
        let input = read_file("GoogleAuthImportScreenshotCropped.jpg");
        let result = parse_qr_code(&input);

        let text = result.expect("Should parse QR code");
        assert!(text.starts_with("otpauth-migration://"));
    }

    #[test]
    fn parse_big_code_in_screenshot() {
        parse_google_authenticator_qr("GoogleAuthenticator_ScreenshotBigQR.jpeg")
    }

    #[test]
    fn parse_invalid_image() {
        let invalid_data = b"not an image";
        let result = parse_qr_code(invalid_data);
        assert!(result.is_none(), "Should return None for invalid image data");
    }

    #[test]
    fn parse_empty_data() {
        let empty_data = b"";
        let result = parse_qr_code(empty_data);
        assert!(result.is_none(), "Should return None for empty data");
    }
}
