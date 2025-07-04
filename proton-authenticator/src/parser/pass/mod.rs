use crate::parser::{ImportError, ImportResult, ThirdPartyImportError};
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use zip::ZipArchive;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PassImportError {
    BadContent,
    BadZip,
    MissingDataFile,
}

#[derive(Debug, Deserialize)]
struct ProtonPassExport {
    vaults: HashMap<String, Vault>,
}

#[derive(Debug, Deserialize)]
struct Vault {
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    data: ItemData,
}

#[derive(Debug, Deserialize)]
struct ItemData {
    metadata: ItemMetadata,
    #[serde(rename = "extraFields", default)]
    extra_fields: Vec<ExtraField>,
    #[serde(rename = "type")]
    item_type: String,
    content: Option<ItemContent>,
}

#[derive(Debug, Deserialize)]
struct ItemMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Deserialize)]
struct ItemContent {
    #[serde(rename = "totpUri", default)]
    totp_uri: String,
}

#[derive(Debug, Deserialize)]
struct ExtraField {
    #[serde(rename = "fieldName")]
    field_name: String,
    #[serde(rename = "type")]
    field_type: String,
    data: ExtraFieldData,
}

#[derive(Debug, Deserialize)]
struct ExtraFieldData {
    #[serde(rename = "totpUri")]
    totp_uri: Option<String>,
}

impl From<PassImportError> for ThirdPartyImportError {
    fn from(value: PassImportError) -> Self {
        match value {
            PassImportError::BadContent => Self::BadContent,
            PassImportError::BadZip => Self::BadContent,
            PassImportError::MissingDataFile => Self::BadContent,
        }
    }
}

pub fn parse_pass_zip(input: &[u8]) -> Result<ImportResult, PassImportError> {
    let cursor = std::io::Cursor::new(input);

    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        error!("Error opening zip: {e:?}");
        PassImportError::BadZip
    })?;

    // Find the "Proton Pass/data.json" file
    let mut json_content = String::new();
    let mut found_file = false;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            error!("Error opening file inside zip at index {i}: {e:?}");
            PassImportError::BadZip
        })?;
        if file.name() == "Proton Pass/data.json" {
            // Read the JSON content
            file.read_to_string(&mut json_content).map_err(|e| {
                error!("Error reading Pass data file inside zip: {e:?}");
                PassImportError::BadContent
            })?;
            found_file = true;
            break;
        }
    }

    if !found_file {
        return Err(PassImportError::MissingDataFile);
    }

    // Parse the JSON
    let export_data: ProtonPassExport = serde_json::from_str(&json_content).map_err(|e| {
        error!("Error parsing Proton Pass Export data: {e:?}");
        PassImportError::BadContent
    })?;

    // Extract TOTP entries
    let mut entries = Vec::new();
    let mut errors = Vec::new();

    // Parse the vaults
    for (vault_id, vault) in export_data.vaults {
        for (item_idx, item) in vault.items.iter().enumerate() {
            extract_totp_entries_from_item(item, &mut entries, &mut errors, &vault_id, item_idx);
        }
    }

    Ok(ImportResult { entries, errors })
}

fn extract_totp_entries_from_item(
    item: &Item,
    entries: &mut Vec<AuthenticatorEntry>,
    errors: &mut Vec<ImportError>,
    vault_id: &str,
    item_idx: usize,
) {
    // Get the item name for use as label
    let item_name = &item.data.metadata.name;

    // Get the item note
    let item_note = if item.data.metadata.note.is_empty() {
        None
    } else {
        Some(item.data.metadata.note.clone())
    };

    // Check if the item is a login type, as only login items have a totp field in the content
    if item.data.item_type == "login" {
        // Check for main TOTP URI
        if let Some(content) = &item.data.content {
            if !content.totp_uri.is_empty() {
                match create_entry_from_uri(&content.totp_uri, item_name, item_note.clone()) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        errors.push(ImportError {
                            context: format!("Error in vault {vault_id} item {item_idx} (main TOTP)"),
                            message: format!("{e:?}"),
                        });
                    }
                }
            }
        }
    }
    // Check for custom fields with TOTP
    for (field_idx, field) in item.data.extra_fields.iter().enumerate() {
        if field.field_type == "totp" {
            if let Some(totp_uri) = &field.data.totp_uri {
                if !totp_uri.is_empty() {
                    // Use the field name as part of the label
                    let combined_name = if field.field_name.is_empty() {
                        item_name.to_string()
                    } else if item_name.is_empty() {
                        field.field_name.clone()
                    } else {
                        format!("{} - {}", item_name, field.field_name)
                    };

                    match create_entry_from_uri(totp_uri, &combined_name, item_note.clone()) {
                        Ok(entry) => entries.push(entry),
                        Err(e) => {
                            errors.push(ImportError {
                                context: format!(
                                    "Error in vault {} item {} field {} ({})",
                                    vault_id, item_idx, field_idx, field.field_name
                                ),
                                message: format!("{e:?}"),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn create_entry_from_uri(uri: &str, name: &str, note: Option<String>) -> Result<AuthenticatorEntry, PassImportError> {
    let mut content = AuthenticatorEntryContent::from_uri(uri).map_err(|_| PassImportError::BadContent)?;

    // Set the name/label if it's not already set or if it's empty
    match &mut content {
        AuthenticatorEntryContent::Totp(totp) => {
            if (totp.label.is_none() || totp.label.as_ref().is_none_or(|l| l.is_empty())) && !name.is_empty() {
                totp.label = Some(name.to_string());
            }

            // Clean reverse-exported TOTP label:issuer
            if let (Some(label), Some(issuer)) = (totp.label.as_ref(), totp.issuer.as_ref()) {
                if label == "Proton Pass" && !issuer.is_empty() {
                    let label_clone = label.clone();
                    let issuer_clone = issuer.clone();
                    totp.label = Some(issuer_clone);
                    totp.issuer = Some(label_clone);
                }
            }
        }

        // Pass does not support steam entries, but adding them for future-proofing
        AuthenticatorEntryContent::Steam(steam) => {
            if (steam.name.is_none() || steam.name.as_ref().is_none_or(|n| n.is_empty())) && !name.is_empty() {
                steam.name = Some(name.to_string());
            }
        }
    }

    Ok(AuthenticatorEntry {
        content,
        note,
        id: AuthenticatorEntry::generate_id(),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents_raw;
    use crate::AuthenticatorEntryContent;
    use proton_pass_totp::algorithm::Algorithm;

    struct ExpectedTotp<'a> {
        username: &'a str,
        secret: &'a str,
        issuer: &'a str,
        algorithm: Algorithm,
        digits: u8,
        period: u16,
    }

    fn assert_totp(entry: &AuthenticatorEntry, expected_totp: ExpectedTotp) {
        match entry.content {
            AuthenticatorEntryContent::Totp(ref totp) => {
                assert_eq!(totp.label, Some(expected_totp.username.to_string()));
                assert_eq!(totp.secret, expected_totp.secret.to_string());
                assert_eq!(totp.issuer, Some(expected_totp.issuer.to_string()));
                assert_eq!(totp.algorithm, Some(expected_totp.algorithm));
                assert_eq!(totp.digits, Some(expected_totp.digits));
                assert_eq!(totp.period, Some(expected_totp.period));
            }
            _ => panic!("Should be a TOTP"),
        }
    }

    #[test]
    fn can_parse_pass_zip() {
        let input = get_file_contents_raw("pass/PassExport.zip");

        let res = parse_pass_zip(&input).expect("should be able to parse");
        let entries = res.entries;
        assert_eq!(entries.len(), 7);

        assert_totp(
            &entries[0],
            ExpectedTotp {
                username: "ausername",
                secret: "K5UHSIDBOJSSA6LPOUQHAZLFNNUW4ZY=",
                issuer: "Main TOTP (only secret)",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        assert_totp(
            &entries[1],
            ExpectedTotp {
                username: "MYLABEL",
                secret: "JV4VGZLDOJSXIMJSGM2DKNQ",
                issuer: "MYISSUER",
                algorithm: Algorithm::SHA256,
                digits: 8,
                period: 15,
            },
        );

        assert_totp(
            &entries[2],
            ExpectedTotp {
                username: "Only custom fields",
                secret: "IN2XG5DPNVDGSZLMMQYQ",
                issuer: "Proton Pass",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        assert_totp(
            &entries[3],
            ExpectedTotp {
                username: "Only custom fields",
                secret: "IN2XG5DPNVDGSZLMMQZA",
                issuer: "Proton Pass",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        assert_totp(
            &entries[4],
            ExpectedTotp {
                username: "Main TOTP and custom fields",
                secret: "JVQWS3SUJ5KFA",
                issuer: "Proton Pass",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        assert_totp(
            &entries[5],
            ExpectedTotp {
                username: "Main TOTP and custom fields",
                secret: "IN2XG5DPNVDGSZLMMQYQ",
                issuer: "Proton Pass",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        assert_totp(
            &entries[6],
            ExpectedTotp {
                username: "Main TOTP and custom fields",
                secret: "IN2XG5DPNVDGSZLMMQZA",
                issuer: "Proton Pass",
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
            },
        );

        let errors = res.errors;
        assert_eq!(1, errors.len());

        let error = &errors[0];
        assert_eq!(error.message, "BadContent");
        assert_eq!(error.context, "Error in vault LDvfA6MxFs3NYL3MU49nPpSYWVefHskOnztrHkbZGk1boc5FOi6oahgNfZqsD_KCKWon2-GIJzCXkGXEsz5XeQ== item 3 field 2 (Malformed totp)");
    }
}
