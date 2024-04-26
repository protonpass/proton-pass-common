pub use proton_pass_common::creditcard::{CreditCardDetector, CreditCardType};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmCreditCardType {
    Visa,
    Mastercard,
    AmericanExpress,
    DinersClub,
    Discover,
    Jcb,
    UnionPay,
    Maestro,
    Elo,
    Mir,
    Hiper,
    Hipercard,
    Unknown,
}

impl From<CreditCardType> for WasmCreditCardType {
    fn from(value: CreditCardType) -> Self {
        match value {
            CreditCardType::Visa => WasmCreditCardType::Visa,
            CreditCardType::Mastercard => WasmCreditCardType::Mastercard,
            CreditCardType::AmericanExpress => WasmCreditCardType::AmericanExpress,
            CreditCardType::DinersClub => WasmCreditCardType::DinersClub,
            CreditCardType::Discover => WasmCreditCardType::Discover,
            CreditCardType::JCB => WasmCreditCardType::Jcb,
            CreditCardType::UnionPay => WasmCreditCardType::UnionPay,
            CreditCardType::Maestro => WasmCreditCardType::Maestro,
            CreditCardType::Elo => WasmCreditCardType::Elo,
            CreditCardType::Mir => WasmCreditCardType::Mir,
            CreditCardType::Hiper => WasmCreditCardType::Hiper,
            CreditCardType::Hipercard => WasmCreditCardType::Hipercard,
            CreditCardType::Unknown => WasmCreditCardType::Unknown,
        }
    }
}
