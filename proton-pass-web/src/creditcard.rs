pub use proton_pass_common::creditcard::{CreditCardDetector, CreditCardType};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub enum WasmCreditCardType {
    Visa,
    Mastercard,
    AmericanExpress,
    DinersClub,
    Discover,
    JCB,
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
            CreditCardType::JCB => WasmCreditCardType::JCB,
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
