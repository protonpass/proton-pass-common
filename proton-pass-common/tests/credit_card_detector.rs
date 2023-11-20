use proton_pass_common::creditcard::detector::CreditCardDetector;
use proton_pass_common::creditcard::detector::CreditCardType;

#[test]
fn test_detect_visa() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("4111111111111111"), CreditCardType::Visa);
    assert_eq!(detector.detect("4012888888881881"), CreditCardType::Visa);
    assert_eq!(detector.detect("4242424242424242"), CreditCardType::Visa);
    assert_eq!(detector.detect("4000056655665556"), CreditCardType::Visa);
    assert_eq!(detector.detect("4222222222222"), CreditCardType::Visa);
    assert_eq!(detector.detect("4462030000000000"), CreditCardType::Visa);
    assert_eq!(detector.detect("4484070000000000"), CreditCardType::Visa);
    assert_eq!(detector.detect("44 840_7000+000·00-00"), CreditCardType::Visa);
}

#[test]
fn test_detect_mastercard() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("5112345678901234"), CreditCardType::Mastercard);
    assert_eq!(detector.detect("2312345678901234"), CreditCardType::Mastercard);
    assert_eq!(detector.detect("5555555555554444"), CreditCardType::Mastercard);
    assert_eq!(detector.detect("5200828282828210"), CreditCardType::Mastercard);
    assert_eq!(detector.detect("5105105105105100"), CreditCardType::Mastercard);
}

#[test]
fn test_detect_american_express() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("378282246310005"), CreditCardType::AmericanExpress);
    assert_eq!(detector.detect("341111111111111"), CreditCardType::AmericanExpress);
    assert_eq!(detector.detect("371449635398431"), CreditCardType::AmericanExpress);
}

#[test]
fn test_detect_diners_club() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("3056930009020004"), CreditCardType::DinersClub);
    assert_eq!(detector.detect("36227206271667"), CreditCardType::DinersClub);
}

#[test]
fn test_detect_discover() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("6011111111111117"), CreditCardType::Discover);
    assert_eq!(detector.detect("6011000990139424"), CreditCardType::Discover);
    assert_eq!(detector.detect("6011981111111113"), CreditCardType::Discover);
}

#[test]
fn test_detect_jcb() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("3530111333300000"), CreditCardType::JCB);
    assert_eq!(detector.detect("3566002020360505"), CreditCardType::JCB);
}

#[test]
fn test_detect_union_pay() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("6200000000000005"), CreditCardType::UnionPay);
    assert_eq!(detector.detect("6200000000000000005"), CreditCardType::UnionPay);
    assert_eq!(detector.detect("6200000000000047"), CreditCardType::UnionPay);
    assert_eq!(detector.detect("8100000000000005"), CreditCardType::UnionPay);
    assert_eq!(detector.detect("8100000000000000005"), CreditCardType::UnionPay);
}

#[test]
fn test_detect_maestro() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("6759649826438453"), CreditCardType::Maestro);
    assert_eq!(detector.detect("6799990100000000019"), CreditCardType::Maestro);
}

#[test]
fn test_detect_mir() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("2200000000000000"), CreditCardType::Mir);
    assert_eq!(detector.detect("2204999999999999"), CreditCardType::Mir);
}

#[test]
fn test_detect_elo() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("5066991111111118"), CreditCardType::Elo);
    assert_eq!(detector.detect("6362970000457013"), CreditCardType::Elo);
}

#[test]
fn test_detect_hiper() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("6370950000000005"), CreditCardType::Hiper);
}

#[test]
fn test_detect_hipercard() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("6062820000000001"), CreditCardType::Hipercard);
    assert_eq!(detector.detect("6062826786276634"), CreditCardType::Hipercard);
}

#[test]
fn test_detect_unknown() {
    let detector = CreditCardDetector::default();
    assert_eq!(detector.detect("1234567890123456"), CreditCardType::Unknown);
    assert_eq!(detector.detect("invalidinput"), CreditCardType::Unknown);
}
