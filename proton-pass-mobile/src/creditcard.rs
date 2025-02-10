use proton_pass_common::creditcard::detector::{
    CreditCardDetector as CommonCreditCardDetector, CreditCardType as CommonCreditCardType,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CreditCardType {
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

impl From<CommonCreditCardType> for CreditCardType {
    fn from(value: CommonCreditCardType) -> Self {
        match value {
            CommonCreditCardType::Visa => Self::Visa,
            CommonCreditCardType::Mastercard => Self::Mastercard,
            CommonCreditCardType::AmericanExpress => Self::AmericanExpress,
            CommonCreditCardType::DinersClub => Self::DinersClub,
            CommonCreditCardType::Discover => Self::Discover,
            CommonCreditCardType::JCB => Self::JCB,
            CommonCreditCardType::UnionPay => Self::UnionPay,
            CommonCreditCardType::Maestro => Self::Maestro,
            CommonCreditCardType::Elo => Self::Elo,
            CommonCreditCardType::Mir => Self::Mir,
            CommonCreditCardType::Hiper => Self::Hiper,
            CommonCreditCardType::Hipercard => Self::Hipercard,
            CommonCreditCardType::Unknown => Self::Unknown,
        }
    }
}

pub struct CreditCardDetector {
    inner: CommonCreditCardDetector,
}

impl CreditCardDetector {
    pub fn new() -> Self {
        Self {
            inner: CommonCreditCardDetector::default(),
        }
    }

    pub fn detect(&self, number: String) -> CreditCardType {
        CreditCardType::from(self.inner.detect(&number))
    }
}
