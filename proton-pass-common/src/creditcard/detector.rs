use luhn::valid;
use regex::Regex;

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

fn get_regexes() -> Vec<(CreditCardType, Regex)> {
    vec![
        (CreditCardType::Visa, Regex::new(r"^4[0-9]{12}(?:[0-9]{3})?$").unwrap()),
        (CreditCardType::Mastercard, Regex::new(r"^(5[1-5]\d{14}|2(?:2[2-9]|2[3-9]|2[7-9]0)\d{12}|22[3-9]\d{12}|2[3-6]\d{14}|27[0-1]\d{13}|2720\d{12})$").unwrap()),
        (CreditCardType::AmericanExpress, Regex::new(r"^3[47][0-9]{13}$").unwrap()),
        (CreditCardType::DinersClub, Regex::new(r"^(30[0-5]|36|3[89])\d{11,15}$").unwrap()),
        (CreditCardType::Discover, Regex::new(r"^6011[0-9]{12}$|^64[4-9][0-9]{13}$|^65[0-9]{14}$").unwrap()),
        (CreditCardType::JCB, Regex::new(r"^(?:2131|1800|35\d{3})\d{11}$").unwrap()),
        (CreditCardType::UnionPay, Regex::new(r"^62[0-9]{14,17}$|^81[0-9]{14,17}$").unwrap()),
        (CreditCardType::Elo, Regex::new(r"^(401178|401179|438935|457631|457632|431274|451416|457393|504175|506699\d{10}|506778\d{10}|509\d{6}|627780|636297\d{10}|636368\d{10}|650031\d{10}|650033\d{10}|650035\d{10}|650051\d{10}|650405\d{10}|650439\d{10}|650485\d{10}|650538\d{10}|650541\d{10}|650598\d{10}|650700\d{10}|650718\d{10}|650720\d{10}|650727\d{10}|650901\d{10}|650978\d{10}|651652\d{10}|651679\d{10}|655000\d{10}|655019\d{10}|655021\d{10}|655058\d{10})$").unwrap()),
        (CreditCardType::Mir, Regex::new(r"^220[0-4][0-9]{12,15}$").unwrap()),
        (CreditCardType::Hiper, Regex::new(r"^637095[0-9]{10}$|^63737423[0-9]{8}$|^63743358[0-9]{8}$|^637568[0-9]{10}$|^637599[0-9]{10}$|^637609[0-9]{10}$|^637612[0-9]{10}$").unwrap()),
        (CreditCardType::Hipercard, Regex::new(r"^606282[0-9]{10}$").unwrap()),
        (CreditCardType::Maestro, Regex::new(r"^(?:5[06789]|6)[0-9]{11,}$").unwrap()),
    ]
}

pub struct CreditCardDetector {
    regexes: Vec<(CreditCardType, Regex)>,
}

impl Default for CreditCardDetector {
    fn default() -> Self {
        Self { regexes: get_regexes() }
    }
}

impl CreditCardDetector {
    pub fn detect(&self, number: &str) -> CreditCardType {
        let cleaned_card_number: String = number.chars().filter(char::is_ascii_digit).collect();

        let mut card = None;
        for (card_type, pattern) in self.regexes.iter() {
            if pattern.is_match(&cleaned_card_number) {
                card = Some(card_type.clone());
                break;
            }
        }
        match card {
            None => CreditCardType::Unknown,
            Some(c) => {
                if valid(&cleaned_card_number) {
                    c
                } else {
                    CreditCardType::Unknown
                }
            }
        }
    }
}
