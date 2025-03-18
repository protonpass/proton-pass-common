use proton_pass_derive::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WifiSecurity {
    Unspecified,
    WPA,
    WPA2,
    WPA3,
    WEP,
}

impl WifiSecurity {
    fn value(&self) -> &'static str {
        match self {
            WifiSecurity::Unspecified => "WPA2", // Defaulting to WPA2
            WifiSecurity::WPA => "WPA",
            WifiSecurity::WPA2 => "WPA2",
            WifiSecurity::WPA3 => "WPA3",
            WifiSecurity::WEP => "WEP",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WifiError {
    EmptySSID,
}

pub fn generate_wifi_uri(ssid: &str, password: &str, security: WifiSecurity) -> Result<String, WifiError> {
    if ssid.is_empty() {
        return Err(WifiError::EmptySSID);
    }

    if password.is_empty() {
        return Ok(format!("WIFI:S:{};T:nopass;;", ssid));
    }
    Ok(format!("WIFI:S:{};T:{};P:{};;", ssid, security.value(), password))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_ssid() {
        let result = generate_wifi_uri("", "some password", WifiSecurity::WPA);
        assert_eq!(result, Err(WifiError::EmptySSID))
    }

    #[test]
    fn empty_password() {
        let result = generate_wifi_uri("my_ssid", "", WifiSecurity::WPA2);
        assert_eq!(result, Ok("WIFI:S:my_ssid;T:nopass;;".to_string()));
    }

    #[test]
    fn securities() {
        let unspecified = generate_wifi_uri("my_ssid", "my_password", WifiSecurity::Unspecified);
        assert_eq!(unspecified, Ok("WIFI:S:my_ssid;T:WPA2;P:my_password;;".to_string()));

        let wpa = generate_wifi_uri("my_ssid", "my_password", WifiSecurity::WPA);
        assert_eq!(wpa, Ok("WIFI:S:my_ssid;T:WPA;P:my_password;;".to_string()));

        let wpa2 = generate_wifi_uri("my_ssid", "my_password", WifiSecurity::WPA2);
        assert_eq!(wpa2, Ok("WIFI:S:my_ssid;T:WPA2;P:my_password;;".to_string()));

        let wpa3 = generate_wifi_uri("my_ssid", "my_password", WifiSecurity::WPA3);
        assert_eq!(wpa3, Ok("WIFI:S:my_ssid;T:WPA3;P:my_password;;".to_string()));

        let wep = generate_wifi_uri("my_ssid", "my_password", WifiSecurity::WEP);
        assert_eq!(wep, Ok("WIFI:S:my_ssid;T:WEP;P:my_password;;".to_string()));
    }
}
