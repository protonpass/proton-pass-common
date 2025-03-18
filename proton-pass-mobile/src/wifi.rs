use proton_pass_common::wifi::{generate_wifi_uri, WifiError as CommonWifiError, WifiSecurity as CommonWifiSecurity};

pub struct WifiQrCodeGenerator;

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

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum WifiQrCodeGeneratorError {
    EmptySSID,
}

impl From<CommonWifiError> for WifiQrCodeGeneratorError {
    fn from(value: CommonWifiError) -> Self {
        match value {
            CommonWifiError::EmptySSID => WifiQrCodeGeneratorError::EmptySSID,
        }
    }
}

impl WifiQrCodeGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_uri(
        &self,
        ssid: String,
        password: String,
        security: WifiSecurity,
    ) -> Result<String, WifiQrCodeGeneratorError> {
        generate_wifi_uri(&ssid, &password, security.into()).map_err(|e| e.into())
    }
}
