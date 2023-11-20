use proton_pass_common::creditcard::detector::CreditCardDetector as CommonCreditCardDetector;
pub use proton_pass_common::creditcard::detector::CreditCardType;

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
        self.inner.detect(&number)
    }
}
