use proton_pass_common::wifi::WifiSecurity;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmWifiSecurity {
    Unspecified,
    WPA,
    WPA2,
    WPA3,
    WEP,
}

impl From<WasmWifiSecurity> for WifiSecurity {
    fn from(val: WasmWifiSecurity) -> Self {
        match val {
            WasmWifiSecurity::Unspecified => WifiSecurity::Unspecified,
            WasmWifiSecurity::WPA => WifiSecurity::WPA,
            WasmWifiSecurity::WPA2 => WifiSecurity::WPA2,
            WasmWifiSecurity::WPA3 => WifiSecurity::WPA3,
            WasmWifiSecurity::WEP => WifiSecurity::WEP,
        }
    }
}
