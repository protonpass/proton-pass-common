use crate::QrCodeError;
use proton_pass_common::qr::generate_svg_qr_code;
use proton_pass_common::wifi::{generate_wifi_uri, WifiError as CommonWifiError, WifiSecurity as CommonWifiSecurity};
use proton_pass_derive::Error;

#[derive(uniffi::Object)]
pub struct WifiQrCodeGenerator;

#[derive(uniffi::Enum)]
pub enum WifiSecurity {
    Unspecified,
    WPA,
    WPA2,
    WPA3,
    WEP,
}

impl From<WifiSecurity> for CommonWifiSecurity {
    fn from(value: WifiSecurity) -> Self {
        match value {
            WifiSecurity::Unspecified => Self::Unspecified,
            WifiSecurity::WPA => Self::WPA,
            WifiSecurity::WPA2 => Self::WPA2,
            WifiSecurity::WPA3 => Self::WPA3,
            WifiSecurity::WEP => Self::WEP,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WifiError {
    EmptySSID,
}

impl From<CommonWifiError> for WifiError {
    fn from(value: CommonWifiError) -> Self {
        match value {
            CommonWifiError::EmptySSID => Self::EmptySSID,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WifiQrCodeGeneratorError {
    Wifi(WifiError),
    QrCode(QrCodeError),
}

#[uniffi::export]
impl WifiQrCodeGenerator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn generate_svg_qr_code(
        &self,
        ssid: String,
        password: String,
        security: WifiSecurity,
    ) -> Result<String, WifiQrCodeGeneratorError> {
        let uri = generate_wifi_uri(&ssid, &password, security.into())
            .map_err(|e| WifiQrCodeGeneratorError::Wifi(e.into()))?;

        generate_svg_qr_code(&uri).map_err(|e| WifiQrCodeGeneratorError::QrCode(e.into()))
    }
}
