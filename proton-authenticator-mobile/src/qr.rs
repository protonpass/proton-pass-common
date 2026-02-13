#[derive(uniffi::Object)]
pub struct QrCodeScanner;

#[uniffi::export]
impl QrCodeScanner {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn scan_qr_code(&self, image: &[u8]) -> Option<String> {
        proton_authenticator::qr::parse_qr_code(image)
    }
}
