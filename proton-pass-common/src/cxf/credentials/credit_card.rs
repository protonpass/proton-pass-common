use credential_exchange_format::{Credential, CreditCardCredential, EditableField, EditableFieldYearMonth};
use proton_pass_types::{CardType, CreditCardItem};

use crate::cxf::{
    CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension,
    fields::{concealed_field_to_string, opt_concealed_field, opt_field_to_string, opt_string_field, string_field},
};

fn card_type_to_string(card_type: &CardType) -> String {
    match card_type {
        CardType::Visa => "Visa".to_string(),
        CardType::Mastercard => "Mastercard".to_string(),
        CardType::AmericanExpress => "American Express".to_string(),
        other => format!("{other:?}"),
    }
}

fn string_to_card_type(value: &str) -> CardType {
    match value.to_lowercase().as_str() {
        "visa" => CardType::Visa,
        "mastercard" => CardType::Mastercard,
        "american express" => CardType::AmericanExpress,
        _ => CardType::Other,
    }
}

fn parse_year_month(
    value: &str,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<EditableFieldYearMonth> {
    if value.is_empty() {
        return None;
    }
    let parsed = (|| {
        let (year, month) = value.split_once('-')?;
        let year: u16 = year.parse().ok()?;
        let month: u8 = month.parse().ok()?;
        let month = credential_exchange_format::Month::try_from(month).ok()?;
        Some(EditableFieldYearMonth { year, month })
    })();
    if parsed.is_none() {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: format!("Could not export card expiration date '{value}': expected format YYYY-MM"),
            kind: CxfWarningKind::MalformedInput,
        });
    }
    parsed
}

pub(crate) fn credit_card_to_credential(
    item: &CreditCardItem,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> CxfCredential {
    let expiry_date = parse_year_month(&item.expiration_date, item_title, warnings).map(|ym| EditableField {
        id: None,
        value: ym.into(),
        label: None,
        extensions: None,
    });

    Credential::CreditCard(Box::new(CreditCardCredential {
        number: opt_concealed_field(&item.number),
        full_name: opt_string_field(&item.cardholder_name),
        card_type: if item.card_type == CardType::Unspecified {
            None
        } else {
            Some(string_field(card_type_to_string(&item.card_type)))
        },
        verification_number: opt_concealed_field(&item.verification_number),
        pin: opt_concealed_field(&item.pin),
        expiry_date,
        valid_from: None,
    }))
}

pub(crate) fn credential_to_credit_card(cred: &CreditCardCredential<ProtonExtension>) -> CreditCardItem {
    let expiration_date = cred
        .expiry_date
        .clone()
        .and_then(|f| f.value.into_expected().ok())
        .map(String::from)
        .unwrap_or_default();

    let card_type = opt_field_to_string(cred.card_type.clone());

    CreditCardItem {
        cardholder_name: opt_field_to_string(cred.full_name.clone()),
        card_type: if card_type.is_empty() {
            CardType::Unspecified
        } else {
            string_to_card_type(&card_type)
        },
        number: cred.number.clone().map(concealed_field_to_string).unwrap_or_default(),
        verification_number: cred
            .verification_number
            .clone()
            .map(concealed_field_to_string)
            .unwrap_or_default(),
        expiration_date,
        pin: cred.pin.clone().map(concealed_field_to_string).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CreditCardItem {
        CreditCardItem {
            cardholder_name: "John Doe".to_string(),
            card_type: CardType::Visa,
            number: "4111111111111111".to_string(),
            verification_number: "123".to_string(),
            expiration_date: "2030-05".to_string(),
            pin: "1234".to_string(),
        }
    }

    #[test]
    fn credit_card_round_trips() {
        let item = sample();
        let mut warnings = Vec::new();
        let cred = credit_card_to_credential(&item, None, &mut warnings);
        let Credential::CreditCard(cred) = cred else {
            panic!("expected credit card credential")
        };
        let back = credential_to_credit_card(&cred);
        assert_eq!(back, item);
        assert!(warnings.is_empty());
    }

    #[test]
    fn missing_optional_fields_round_trip_to_empty() {
        let item = CreditCardItem {
            cardholder_name: String::new(),
            card_type: CardType::Unspecified,
            number: String::new(),
            verification_number: String::new(),
            expiration_date: String::new(),
            pin: String::new(),
        };
        let mut warnings = Vec::new();
        let cred = credit_card_to_credential(&item, None, &mut warnings);
        let Credential::CreditCard(cred) = cred else {
            panic!("expected credit card credential")
        };
        let back = credential_to_credit_card(&cred);
        assert_eq!(back, item);
        assert!(warnings.is_empty());
    }

    #[test]
    fn malformed_expiration_date_produces_warning() {
        let item = CreditCardItem {
            expiration_date: "not-a-date".to_string(),
            ..sample()
        };
        let mut warnings = Vec::new();
        let cred = credit_card_to_credential(&item, Some("My Card"), &mut warnings);
        let Credential::CreditCard(cred) = cred else {
            panic!("expected credit card credential")
        };
        assert!(cred.expiry_date.is_none());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::MalformedInput);
        assert_eq!(warnings[0].item_title.as_deref(), Some("My Card"));
    }

    #[test]
    fn unknown_card_type_string_maps_to_other() {
        assert_eq!(string_to_card_type("diners club"), CardType::Other);
    }

    #[test]
    fn card_type_matches_case_insensitively() {
        assert_eq!(string_to_card_type("VISA"), CardType::Visa);
        assert_eq!(string_to_card_type("MasterCard"), CardType::Mastercard);
        assert_eq!(string_to_card_type("American Express"), CardType::AmericanExpress);
    }
}
