use crate::QrCodeError;
use proton_pass_common::qr::generate_svg_qr_code;
use proton_pass_common::wifi::{generate_wifi_uri, WifiError as CommonWifiError, WifiSecurity as CommonWifiSecurity};
use proton_pass_derive::Error;
use proton_pass_types::WifiSecurity;

#[derive(uniffi::Object)]
pub struct WifiQrCodeGenerator;

fn to_common(value: WifiSecurity) -> CommonWifiSecurity {
    match value {
        WifiSecurity::UnspecifiedWifiSecurity => CommonWifiSecurity::Unspecified,
        WifiSecurity::WPA => CommonWifiSecurity::WPA,
        WifiSecurity::WPA2 => CommonWifiSecurity::WPA2,
        WifiSecurity::WPA3 => CommonWifiSecurity::WPA3,
        WifiSecurity::WEP => CommonWifiSecurity::WEP,
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
        let uri = generate_wifi_uri(&ssid, &password, to_common(security))
            .map_err(|e| WifiQrCodeGeneratorError::Wifi(e.into()))?;

        generate_svg_qr_code(&uri).map_err(|e| WifiQrCodeGeneratorError::QrCode(e.into()))
    }
}
