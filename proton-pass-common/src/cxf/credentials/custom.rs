use credential_exchange_format::{
    ApiKeyCredential, Credential, CustomFieldsCredential, EditableField, EditableFieldDate, EditableFieldValue,
};
use proton_pass_types::{CustomItem, CustomSection, ItemExtraField, ItemExtraFieldContent};

use crate::cxf::{
    CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension,
    fields::{opt_concealed_field_to_string, opt_date_field_to_string, opt_field_to_string},
};

pub(crate) fn extra_field_to_editable_value(field: &ItemExtraField) -> Option<EditableFieldValue<ProtonExtension>> {
    match &field.content {
        ItemExtraFieldContent::Text(value) => Some(EditableFieldValue::String(EditableField {
            id: None,
            value: credential_exchange_format::EditableFieldString(value.clone()).into(),
            label: Some(field.name.clone()),
            extensions: None,
        })),
        ItemExtraFieldContent::Hidden(value) => Some(EditableFieldValue::ConcealedString(EditableField {
            id: None,
            value: credential_exchange_format::EditableFieldConcealedString(value.clone()).into(),
            label: Some(field.name.clone()),
            extensions: None,
        })),
        ItemExtraFieldContent::Timestamp(seconds) => {
            let date = jiff::Timestamp::from_second(*seconds)
                .ok()?
                .to_zoned_datetime(jiff::tz::TimeZone::UTC)
                .date();
            Some(EditableFieldValue::Date(EditableField {
                id: None,
                value: EditableFieldDate(date).into(),
                label: Some(field.name.clone()),
                extensions: None,
            }))
        }
        ItemExtraFieldContent::Totp(_) => None,
    }
}

pub(crate) fn editable_value_to_extra_field(
    value: &EditableFieldValue<ProtonExtension>,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> ItemExtraField {
    match value {
        EditableFieldValue::String(field) => ItemExtraField {
            name: field.label.clone().unwrap_or_default(),
            content: ItemExtraFieldContent::Text(field.value.clone().into()),
        },
        EditableFieldValue::ConcealedString(field) => ItemExtraField {
            name: field.label.clone().unwrap_or_default(),
            content: ItemExtraFieldContent::Hidden(field.value.clone().into()),
        },
        EditableFieldValue::Date(field) => {
            let name = field.label.clone().unwrap_or_default();
            let seconds = field
                .value
                .as_expected()
                .ok()
                .and_then(|d| d.0.to_zoned_datetime(jiff::tz::TimeZone::UTC).ok())
                .map(|zdt| zdt.timestamp().as_second())
                .unwrap_or_default();
            ItemExtraField {
                name,
                content: ItemExtraFieldContent::Timestamp(seconds),
            }
        }
        other => {
            let name = field_label(other);
            warnings.push(CxfWarning {
                item_title: item_title.map(|s| s.to_string()),
                message: format!("Field '{name}' has an unsupported field type, imported as text"),
                kind: CxfWarningKind::PartialFieldMapping,
            });
            ItemExtraField {
                name,
                content: ItemExtraFieldContent::Text(field_value_as_string(other)),
            }
        }
    }
}

fn field_label(value: &EditableFieldValue<ProtonExtension>) -> String {
    match value {
        EditableFieldValue::String(f) => f.label.clone(),
        EditableFieldValue::ConcealedString(f) => f.label.clone(),
        EditableFieldValue::Email(f) => f.label.clone(),
        EditableFieldValue::Number(f) => f.label.clone(),
        EditableFieldValue::Boolean(f) => f.label.clone(),
        EditableFieldValue::Date(f) => f.label.clone(),
        EditableFieldValue::YearMonth(f) => f.label.clone(),
        EditableFieldValue::SubdivisionCode(f) => f.label.clone(),
        EditableFieldValue::CountryCode(f) => f.label.clone(),
        EditableFieldValue::WifiNetworkSecurityType(f) => f.label.clone(),
        _ => None,
    }
    .unwrap_or_default()
}

fn field_value_as_string(value: &EditableFieldValue<ProtonExtension>) -> String {
    match value {
        EditableFieldValue::Email(f) => f.value.clone().into(),
        EditableFieldValue::Number(f) => f.value.clone().into(),
        EditableFieldValue::SubdivisionCode(f) => f.value.clone().into(),
        EditableFieldValue::CountryCode(f) => f.value.clone().into(),
        EditableFieldValue::Boolean(f) => f.value.clone().into(),
        EditableFieldValue::YearMonth(f) => f.value.clone().into(),
        EditableFieldValue::WifiNetworkSecurityType(f) => f.value.clone().into(),
        _ => String::new(),
    }
}

pub(crate) fn custom_section_to_credential(section: &CustomSection) -> CxfCredential {
    let fields = section
        .section_fields
        .iter()
        .filter_map(extra_field_to_editable_value)
        .collect();

    Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: Some(section.section_name.clone()),
        fields,
        extensions: Vec::new(),
    }))
}

pub(crate) fn extra_fields_to_credential(fields: &[ItemExtraField]) -> Option<CxfCredential> {
    let mapped: Vec<_> = fields.iter().filter_map(extra_field_to_editable_value).collect();
    if mapped.is_empty() {
        return None;
    }
    Some(Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: None,
        fields: mapped,
        extensions: Vec::new(),
    })))
}

pub(crate) fn credential_to_custom_section(
    cred: &CustomFieldsCredential<ProtonExtension>,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> CustomSection {
    CustomSection {
        section_name: cred.label.clone().unwrap_or_else(|| "Custom Fields".to_string()),
        section_fields: cred
            .fields
            .iter()
            .map(|f| editable_value_to_extra_field(f, item_title, warnings))
            .collect(),
    }
}

pub(crate) fn custom_item_to_credentials(custom: &CustomItem) -> Vec<CxfCredential> {
    custom.sections.iter().map(custom_section_to_credential).collect()
}

pub(crate) fn credentials_to_custom_item(
    creds: &[CustomFieldsCredential<ProtonExtension>],
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> CustomItem {
    CustomItem {
        sections: creds
            .iter()
            .map(|c| credential_to_custom_section(c, item_title, warnings))
            .collect(),
    }
}

pub(crate) fn api_key_credential_to_custom_item(cred: &ApiKeyCredential<ProtonExtension>) -> CustomItem {
    CustomItem {
        sections: vec![CustomSection {
            section_name: "API Key".to_string(),
            section_fields: api_key_credential_to_extra_fields(cred),
        }],
    }
}

pub(crate) fn api_key_credential_to_extra_fields(cred: &ApiKeyCredential<ProtonExtension>) -> Vec<ItemExtraField> {
    let mut fields = Vec::new();

    let key = opt_concealed_field_to_string(cred.key.clone());
    if !key.is_empty() {
        fields.push(ItemExtraField {
            name: "API Key".to_string(),
            content: ItemExtraFieldContent::Hidden(key),
        });
    }

    let username = opt_field_to_string(cred.username.clone());
    if !username.is_empty() {
        fields.push(ItemExtraField {
            name: "Username".to_string(),
            content: ItemExtraFieldContent::Text(username),
        });
    }

    let key_type = opt_field_to_string(cred.key_type.clone());
    if !key_type.is_empty() {
        fields.push(ItemExtraField {
            name: "Key Type".to_string(),
            content: ItemExtraFieldContent::Text(key_type),
        });
    }

    let url = opt_field_to_string(cred.url.clone());
    if !url.is_empty() {
        fields.push(ItemExtraField {
            name: "URL".to_string(),
            content: ItemExtraFieldContent::Text(url),
        });
    }

    let valid_from = opt_date_field_to_string(cred.valid_from.clone());
    if !valid_from.is_empty() {
        fields.push(ItemExtraField {
            name: "Valid From".to_string(),
            content: ItemExtraFieldContent::Text(valid_from),
        });
    }

    let expiry_date = opt_date_field_to_string(cred.expiry_date.clone());
    if !expiry_date.is_empty() {
        fields.push(ItemExtraField {
            name: "Expires".to_string(),
            content: ItemExtraFieldContent::Text(expiry_date),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_field(name: &str, value: &str) -> ItemExtraField {
        ItemExtraField {
            name: name.to_string(),
            content: ItemExtraFieldContent::Text(value.to_string()),
        }
    }

    #[test]
    fn text_field_round_trips() {
        let field = text_field("username", "bob");
        let editable = extra_field_to_editable_value(&field).unwrap();
        let mut warnings = Vec::new();
        let back = editable_value_to_extra_field(&editable, None, &mut warnings);
        assert_eq!(back, field);
        assert!(warnings.is_empty());
    }

    #[test]
    fn hidden_field_round_trips() {
        let field = ItemExtraField {
            name: "secret".to_string(),
            content: ItemExtraFieldContent::Hidden("shh".to_string()),
        };
        let editable = extra_field_to_editable_value(&field).unwrap();
        let mut warnings = Vec::new();
        let back = editable_value_to_extra_field(&editable, None, &mut warnings);
        assert_eq!(back, field);
    }

    #[test]
    fn timestamp_field_loses_time_of_day() {
        let original_seconds = 1_700_000_123;
        let field = ItemExtraField {
            name: "created".to_string(),
            content: ItemExtraFieldContent::Timestamp(original_seconds),
        };
        let editable = extra_field_to_editable_value(&field).unwrap();
        let mut warnings = Vec::new();
        let back = editable_value_to_extra_field(&editable, None, &mut warnings);
        match back.content {
            ItemExtraFieldContent::Timestamp(seconds) => assert_ne!(seconds, original_seconds),
            _ => panic!("expected timestamp"),
        }
    }

    #[test]
    fn totp_field_is_excluded_from_generic_mapping() {
        let field_name = "field_name";
        let totp_uri = "otpauth://totp/x";
        let field = ItemExtraField {
            name: field_name.to_string(),
            content: ItemExtraFieldContent::Totp(totp_uri.to_string()),
        };
        assert!(extra_field_to_editable_value(&field).is_none());
    }

    #[test]
    fn unexpected_field_type_produces_warning() {
        let label = "email";
        let value = "a@b.com";
        let editable = EditableFieldValue::Email(EditableField {
            id: None,
            value: credential_exchange_format::EditableFieldEmail(value.to_string()).into(),
            label: Some(label.to_string()),
            extensions: None,
        });
        let mut warnings = Vec::new();
        let back = editable_value_to_extra_field(&editable, Some("Item"), &mut warnings);
        assert_eq!(back.name, label);
        assert_eq!(back.content, ItemExtraFieldContent::Text(value.to_string()));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::PartialFieldMapping);
    }

    #[test]
    fn custom_section_round_trips() {
        let section = CustomSection {
            section_name: "My section".to_string(),
            section_fields: vec![text_field("field1", "value1")],
        };
        let cred = custom_section_to_credential(&section);
        let Credential::CustomFields(cred) = cred else {
            panic!("expected custom fields credential")
        };
        let mut warnings = Vec::new();
        let back = credential_to_custom_section(&cred, None, &mut warnings);
        assert_eq!(back, section);
    }

    #[test]
    fn custom_item_round_trips() {
        let custom = CustomItem {
            sections: vec![CustomSection {
                section_name: "Section A".to_string(),
                section_fields: vec![text_field("f", "v")],
            }],
        };
        let creds = custom_item_to_credentials(&custom);
        let creds: Vec<_> = creds
            .into_iter()
            .map(|c| match c {
                Credential::CustomFields(c) => *c,
                _ => panic!("expected custom fields credential"),
            })
            .collect();
        let mut warnings = Vec::new();
        let back = credentials_to_custom_item(&creds, None, &mut warnings);
        assert_eq!(back, custom);
    }

    #[test]
    fn missing_label_falls_back_to_custom_fields_title() {
        let cred = CustomFieldsCredential::<ProtonExtension> {
            id: None,
            label: None,
            fields: vec![],
            extensions: vec![],
        };
        let mut warnings = Vec::new();
        let section = credential_to_custom_section(&cred, None, &mut warnings);
        assert_eq!(section.section_name, "Custom Fields");
    }

    #[test]
    fn api_key_credential_maps_present_fields_to_custom_fields() {
        let cred = ApiKeyCredential::<ProtonExtension> {
            key: Some("secret-token".to_string().into()),
            username: Some("service-account".to_string().into()),
            key_type: Some("Bearer".to_string().into()),
            url: Some("https://api.example.com".to_string().into()),
            valid_from: None,
            expiry_date: None,
        };
        let custom_item = api_key_credential_to_custom_item(&cred);
        assert_eq!(custom_item.sections.len(), 1);
        let fields = &custom_item.sections[0].section_fields;
        assert_eq!(fields.len(), 4);
        assert!(fields.contains(&ItemExtraField {
            name: "API Key".to_string(),
            content: ItemExtraFieldContent::Hidden("secret-token".to_string()),
        }));
        assert!(fields.contains(&ItemExtraField {
            name: "Username".to_string(),
            content: ItemExtraFieldContent::Text("service-account".to_string()),
        }));
        assert!(fields.contains(&ItemExtraField {
            name: "Key Type".to_string(),
            content: ItemExtraFieldContent::Text("Bearer".to_string()),
        }));
        assert!(fields.contains(&ItemExtraField {
            name: "URL".to_string(),
            content: ItemExtraFieldContent::Text("https://api.example.com".to_string()),
        }));
    }

    #[test]
    fn api_key_credential_with_no_fields_produces_an_empty_section() {
        let cred = ApiKeyCredential::<ProtonExtension> {
            key: None,
            username: None,
            key_type: None,
            url: None,
            valid_from: None,
            expiry_date: None,
        };
        let custom_item = api_key_credential_to_custom_item(&cred);
        assert_eq!(custom_item.sections.len(), 1);
        assert!(custom_item.sections[0].section_fields.is_empty());
    }
}
