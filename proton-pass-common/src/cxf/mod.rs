pub(crate) mod credential_kind;
mod credentials;
mod export;
mod fields;
#[cfg(test)]
mod fixtures;
mod import;
#[cfg(test)]
pub(crate) mod test_support;
mod vault;

use proton_pass_derive::{Error, ffi_error};
use proton_pass_types::{ItemData, VaultData};

pub(crate) type ProtonExtension = ();

pub(crate) type CxfHeader = credential_exchange_format::Header<ProtonExtension>;
pub(crate) type CxfAccount = credential_exchange_format::Account<ProtonExtension>;
pub(crate) type CxfCollection = credential_exchange_format::Collection<ProtonExtension>;
pub(crate) type CxfItem = credential_exchange_format::Item<ProtonExtension>;
pub(crate) type CxfCredential = credential_exchange_format::Credential<ProtonExtension>;

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemMetadata {
    pub created_at: u64,
    pub modified_at: u64,
    pub pinned: bool,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemWithMetadata {
    pub item: ItemData,
    pub metadata: ItemMetadata,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfVaultWithItems {
    pub vault: VaultData,
    pub items: Vec<ItemWithMetadata>,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfExportInput {
    pub vaults: Vec<CxfVaultWithItems>,
    pub exporter_rp_id: String,
    pub exporter_display_name: String,
    pub timestamp: u64,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfExportResult {
    pub payload: String,
    pub warnings: Vec<CxfWarning>,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfImportedVault {
    pub vault: Option<VaultData>,
    pub items: Vec<ItemData>,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfImportResult {
    pub vaults: Vec<CxfImportedVault>,
    pub warnings: Vec<CxfWarning>,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxfWarningKind {
    UnsupportedCredential,
    UnsupportedItemType,
    PartialFieldMapping,
    MalformedInput,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxfWarning {
    pub item_title: Option<String>,
    pub message: String,
    pub kind: CxfWarningKind,
}

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CxfError {
    SerializationError(String),
    DeserializationError(String),
}

#[cfg(feature = "cxp")]
pub(crate) use credential_kind::CxfCredentialKind;
#[cfg(feature = "cxp")]
pub(crate) use export::CxfExportOutcome;

pub fn export_cxf(input: CxfExportInput) -> Result<CxfExportResult, CxfError> {
    export::export(input)
}

// Exports only the credentials whose kind appears in `allowed_credential_kinds`.
// `None` means no restriction. `Some(&[])` allows nothing, which is what a peer that requested
// only credential types Proton Pass cannot produce must receive.
#[cfg(feature = "cxp")]
pub(crate) fn export_cxf_with_allowed_kinds(
    input: CxfExportInput,
    allowed_credential_kinds: Option<&[CxfCredentialKind]>,
) -> Result<CxfExportOutcome, CxfError> {
    export::export_with_allowed_kinds(input, allowed_credential_kinds)
}

pub fn import_cxf(payload: &str) -> Result<CxfImportResult, CxfError> {
    import::import(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_pass_types::{
        AliasItem, AutofillUrl, AutofillUrlMode, CustomItem, CustomSection, IdentityItem, ItemContent, ItemExtraField,
        ItemExtraFieldContent, LoginItem, NoteItem, Passkey as PassPasskey, SshKeyItem, VaultDisplayPreferences,
    };

    fn generate_ssh_private_key() -> String {
        let keypair = ssh_key::private::Ed25519Keypair::random(&mut rand::rng());
        ssh_key::PrivateKey::from(keypair)
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn generate_ssh_private_key_pkcs8_der_b64url() -> String {
        let item = SshKeyItem {
            private_key: generate_ssh_private_key(),
            public_key: String::new(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        let cred = credentials::ssh_key::ssh_key_to_credential(&item, None, &mut warnings).unwrap();
        let credential_exchange_format::Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        cred.private_key.to_string()
    }

    fn export_input(vaults: Vec<CxfVaultWithItems>) -> CxfExportInput {
        CxfExportInput {
            vaults,
            exporter_rp_id: "proton.me".to_string(),
            exporter_display_name: "Proton Pass".to_string(),
            timestamp: 1_700_000_000,
        }
    }

    fn vault_data(name: &str) -> VaultData {
        VaultData::new(name.to_string(), String::new(), VaultDisplayPreferences::default()).unwrap()
    }

    fn default_metadata() -> ItemMetadata {
        ItemMetadata {
            created_at: 0,
            modified_at: 0,
            pinned: false,
        }
    }

    fn with_metadata(item: ItemData) -> ItemWithMetadata {
        ItemWithMetadata {
            item,
            metadata: default_metadata(),
        }
    }

    fn login_item(title: &str, login: LoginItem) -> ItemData {
        ItemData::new(
            title.to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(login),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn login_with_primary_and_extra_totp_and_urls_round_trips() {
        let vault_name = "Personal";
        let title = "My login";
        let email = "alice@example.com";
        let password = "hunter2";
        let url = "https://example.com";
        let primary_totp_secret = "JBSWY3DPEHPK3PXP";
        let backup_totp_secret = "GEZDGNBVGY3TQOJQ";

        let login = LoginItem {
            email: email.to_string(),
            username: String::new(),
            password: password.to_string(),
            urls: vec![url.to_string()],
            totp_uri: format!(
                "otpauth://totp/alice?secret={primary_totp_secret}&issuer=Proton&algorithm=SHA1&digits=6&period=30"
            ),
            passkeys: Vec::new(),
            autofill_urls: vec![AutofillUrl {
                url: url.to_string(),
                mode: AutofillUrlMode::Default,
            }],
        };
        let mut item = login_item(title, login);
        item.extra_fields.push(ItemExtraField {
            name: "Backup TOTP".to_string(),
            content: ItemExtraFieldContent::Totp(format!(
                "otpauth://totp/backup?secret={backup_totp_secret}&algorithm=SHA1&digits=6&period=30"
            )),
        });

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data(vault_name),
            items: vec![with_metadata(item.clone())],
        }]);

        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        assert_eq!(import_result.vaults.len(), 1);
        let imported_vault = &import_result.vaults[0];
        assert_eq!(imported_vault.vault.as_ref().unwrap().name, vault_name);
        assert_eq!(imported_vault.items.len(), 1);

        let imported = &imported_vault.items[0];
        assert_eq!(imported.title, title);
        let ItemContent::Login(imported_login) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(imported_login.email, email);
        assert_eq!(imported_login.password, password);
        assert!(imported_login.totp_uri.contains(primary_totp_secret));
        assert_eq!(imported_login.autofill_urls.len(), 1);
        assert_eq!(imported_login.autofill_urls[0].url, url);

        let backup_field = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "TOTP")
            .expect("extra totp field imported under a generic name");
        match &backup_field.content {
            ItemExtraFieldContent::Totp(uri) => assert!(uri.contains(backup_totp_secret)),
            other => panic!("expected totp content, got {other:?}"),
        }
    }

    #[test]
    fn custom_item_with_section_totp_round_trips() {
        let section_name = "Section A";
        let field_name = "field1";
        let totp_secret = "MFRGGZDFMZTWQ2LK";

        let custom = CustomItem {
            sections: vec![CustomSection {
                section_name: section_name.to_string(),
                section_fields: vec![
                    ItemExtraField {
                        name: field_name.to_string(),
                        content: ItemExtraFieldContent::Text("value1".to_string()),
                    },
                    ItemExtraField {
                        name: "Section TOTP".to_string(),
                        content: ItemExtraFieldContent::Totp(format!(
                            "otpauth://totp/section?secret={totp_secret}&algorithm=SHA1&digits=6&period=30"
                        )),
                    },
                ],
            }],
        };
        let item = ItemData::new(
            "My custom item".to_string(),
            String::new(),
            String::new(),
            ItemContent::Custom(custom),
            Vec::new(),
        )
        .unwrap();

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Custom(custom_back) = &imported.content else {
            panic!("expected custom content")
        };
        let section = custom_back
            .sections
            .iter()
            .find(|s| s.section_name == section_name)
            .expect("section preserved");
        assert!(section.section_fields.iter().any(|f| f.name == field_name));
        let totp_field = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "TOTP")
            .expect("extra totp credential imported as a generic top-level extra field");
        match &totp_field.content {
            ItemExtraFieldContent::Totp(uri) => assert!(uri.contains(totp_secret)),
            other => panic!("expected totp content, got {other:?}"),
        }
    }

    #[test]
    fn ssh_key_with_section_round_trips() {
        let private_key = generate_ssh_private_key();
        let private_key = private_key.as_str();
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5";
        let section_name = "Section A";
        let field_name = "field1";
        let field_value = "value1";

        let ssh_key = SshKeyItem {
            private_key: private_key.to_string(),
            public_key: public_key.to_string(),
            sections: vec![CustomSection {
                section_name: section_name.to_string(),
                section_fields: vec![ItemExtraField {
                    name: field_name.to_string(),
                    content: ItemExtraFieldContent::Text(field_value.to_string()),
                }],
            }],
        };
        let item = ItemData::new(
            "My SSH key".to_string(),
            String::new(),
            String::new(),
            ItemContent::SshKey(ssh_key),
            Vec::new(),
        )
        .unwrap();

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::SshKey(ssh_back) = &imported.content else {
            panic!("expected ssh key content")
        };
        assert_eq!(ssh_back.private_key, private_key);
        assert_eq!(ssh_back.public_key, public_key);
        let section = ssh_back
            .sections
            .iter()
            .find(|s| s.section_name == section_name)
            .expect("section preserved");
        assert!(
            section
                .section_fields
                .iter()
                .any(|f| f.name == field_name
                    && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == field_value))
        );
    }

    #[test]
    fn note_credential_outranks_custom_fields_per_priority_table() {
        let note = "A note";
        let field_name = "field1";
        let custom = CustomItem {
            sections: vec![CustomSection {
                section_name: "Section A".to_string(),
                section_fields: vec![ItemExtraField {
                    name: field_name.to_string(),
                    content: ItemExtraFieldContent::Text("value1".to_string()),
                }],
            }],
        };
        let item = ItemData::new(
            "Mixed item".to_string(),
            note.to_string(),
            String::new(),
            ItemContent::Custom(custom),
            Vec::new(),
        )
        .unwrap();

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        let import_result = import_cxf(&export_result.payload).unwrap();
        let imported = &import_result.vaults[0].items[0];

        assert_eq!(imported.note, note);
        assert!(matches!(imported.content, ItemContent::Note(_)));
        assert!(imported.extra_fields.iter().any(|f| f.name == field_name));
    }

    #[test]
    fn extra_note_credentials_are_kept_as_text_custom_fields() {
        let first_note = "Primary note";
        let second_note = "Second note";
        let third_note = "Third note";
        let payload = format!(
            r#"{{
                "version": {{ "major": 1, "minor": 0 }},
                "exporterRpId": "example.com",
                "exporterDisplayName": "Example Exporter",
                "timestamp": 1700000000,
                "accounts": [{{
                    "id": "account-01",
                    "username": "",
                    "email": "",
                    "collections": [],
                    "items": [{{
                        "id": "item-01",
                        "title": "Multi note item",
                        "credentials": [
                            {{ "type": "note", "content": {{ "fieldType": "string", "value": "{first_note}" }} }},
                            {{ "type": "note", "content": {{ "fieldType": "string", "value": "{second_note}" }} }},
                            {{ "type": "note", "content": {{ "fieldType": "string", "value": "{third_note}" }} }}
                        ]
                    }}]
                }}]
            }}"#
        );

        let result = import_cxf(&payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        assert_eq!(imported.note, first_note);

        let second_field = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "Note")
            .expect("second note preserved as a text custom field");
        assert!(matches!(&second_field.content, ItemExtraFieldContent::Text(v) if v == second_note));

        let third_field = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "Note 2")
            .expect("third note preserved as a text custom field");
        assert!(matches!(&third_field.content, ItemExtraFieldContent::Text(v) if v == third_note));
    }

    #[test]
    fn alias_item_is_silently_skipped_on_export() {
        let login_title = "My login";
        let alias = ItemData::new(
            "My alias".to_string(),
            String::new(),
            String::new(),
            ItemContent::Alias(AliasItem),
            Vec::new(),
        )
        .unwrap();
        let login = login_item(
            login_title,
            LoginItem {
                email: "a@b.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(alias), with_metadata(login)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty());

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert_eq!(import_result.vaults[0].items.len(), 1);
        assert_eq!(import_result.vaults[0].items[0].title, login_title);
    }

    #[test]
    fn empty_note_item_is_skipped_with_warning() {
        let login_title = "My login";
        let empty_note = ItemData::new(
            "Empty note".to_string(),
            String::new(),
            String::new(),
            ItemContent::Note(NoteItem),
            Vec::new(),
        )
        .unwrap();
        let login = login_item(
            login_title,
            LoginItem {
                email: "a@b.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(empty_note), with_metadata(login)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert_eq!(export_result.warnings.len(), 1);
        assert_eq!(export_result.warnings[0].kind, CxfWarningKind::UnsupportedItemType);
        assert_eq!(export_result.warnings[0].item_title.as_deref(), Some("Empty note"));

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert_eq!(import_result.vaults[0].items.len(), 1);
        assert_eq!(import_result.vaults[0].items[0].title, login_title);
    }

    #[test]
    fn ssh_key_item_with_unparseable_private_key_is_skipped_with_warnings() {
        let login_title = "My login";
        let invalid_ssh_key = ItemData::new(
            "Invalid SSH key".to_string(),
            String::new(),
            String::new(),
            ItemContent::SshKey(SshKeyItem {
                private_key: "not a real key".to_string(),
                public_key: String::new(),
                sections: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let login = login_item(
            login_title,
            LoginItem {
                email: "a@b.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(invalid_ssh_key), with_metadata(login)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert_eq!(export_result.warnings.len(), 2);
        assert!(
            export_result
                .warnings
                .iter()
                .any(|w| w.kind == CxfWarningKind::UnsupportedCredential
                    && w.item_title.as_deref() == Some("Invalid SSH key"))
        );
        assert!(export_result.warnings.iter().any(
            |w| w.kind == CxfWarningKind::UnsupportedItemType && w.item_title.as_deref() == Some("Invalid SSH key")
        ));

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert_eq!(import_result.vaults[0].items.len(), 1);
        assert_eq!(import_result.vaults[0].items[0].title, login_title);
    }

    #[test]
    fn custom_item_with_no_fields_is_skipped_with_warning() {
        let login_title = "My login";
        let empty_custom = ItemData::new(
            "Empty custom".to_string(),
            String::new(),
            String::new(),
            ItemContent::Custom(CustomItem { sections: Vec::new() }),
            Vec::new(),
        )
        .unwrap();
        let login = login_item(
            login_title,
            LoginItem {
                email: "a@b.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(empty_custom), with_metadata(login)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert_eq!(export_result.warnings.len(), 1);
        assert_eq!(export_result.warnings[0].kind, CxfWarningKind::UnsupportedItemType);
        assert_eq!(export_result.warnings[0].item_title.as_deref(), Some("Empty custom"));

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert_eq!(import_result.vaults[0].items.len(), 1);
        assert_eq!(import_result.vaults[0].items[0].title, login_title);
    }

    #[test]
    fn multi_vault_export_keeps_items_grouped() {
        let vault1_name = "Vault 1";
        let vault2_name = "Vault 2";
        let vault1_item = login_item(
            "Item 1",
            LoginItem {
                email: "one@example.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );
        let vault2_item = login_item(
            "Item 2",
            LoginItem {
                email: "two@example.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );

        let input = export_input(vec![
            CxfVaultWithItems {
                vault: vault_data(vault1_name),
                items: vec![with_metadata(vault1_item)],
            },
            CxfVaultWithItems {
                vault: vault_data(vault2_name),
                items: vec![with_metadata(vault2_item)],
            },
        ]);
        let export_result = export_cxf(input).unwrap();
        let import_result = import_cxf(&export_result.payload).unwrap();

        assert_eq!(import_result.vaults.len(), 2);
        let names: Vec<String> = import_result
            .vaults
            .iter()
            .map(|v| v.vault.as_ref().unwrap().name.clone())
            .collect();
        assert!(names.contains(&vault1_name.to_string()));
        assert!(names.contains(&vault2_name.to_string()));
    }

    #[test]
    fn login_with_passkey_round_trips_end_to_end() {
        use crate::passkey::passkey_handling::serialize_passkey;
        use crate::passkey::{
            ProtonAlgorithm, ProtonKey, ProtonKeyType, ProtonLabel, ProtonPassCredentialExtensions, ProtonPassKey,
            ProtonRegisteredLabelKeyType, ProtonRegisteredLabelWithPrivateAlgorithm, ProtonValue,
        };
        use coset::iana::{Ec2KeyParameter, EllipticCurve};

        let rp_id = "example.com";
        let username = "jane";
        let user_display_name = "Jane Doe";
        let credential_id = vec![1, 2, 3, 4];
        let user_handle = vec![5, 6, 7, 8];
        let email = "jane@example.com";
        let password = "hunter2";

        let scalar: [u8; 32] = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        ];
        let secret = p256::SecretKey::from_slice(&scalar).unwrap();
        let public_point = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&secret.public_key(), false);

        let proton_pass_key = ProtonPassKey {
            key: ProtonKey {
                kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
                key_id: Vec::new(),
                alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                    ProtonAlgorithm::ES256,
                )),
                key_ops: Vec::new(),
                base_iv: Vec::new(),
                params: vec![
                    (
                        ProtonLabel::Int(Ec2KeyParameter::Crv as i64),
                        ProtonValue::Integer(crate::passkey::ProtonInteger::from(EllipticCurve::P_256 as i128)),
                    ),
                    (
                        ProtonLabel::Int(Ec2KeyParameter::X as i64),
                        ProtonValue::Bytes(public_point.x().unwrap().to_vec()),
                    ),
                    (
                        ProtonLabel::Int(Ec2KeyParameter::Y as i64),
                        ProtonValue::Bytes(public_point.y().unwrap().to_vec()),
                    ),
                    (
                        ProtonLabel::Int(Ec2KeyParameter::D as i64),
                        ProtonValue::Bytes(scalar.to_vec()),
                    ),
                ],
            },
            credential_id: credential_id.clone(),
            rp_id: rp_id.to_string(),
            user_handle: Some(user_handle.clone()),
            counter: Some(0),
            extensions: ProtonPassCredentialExtensions::default(),
            user_display_name: Some(user_display_name.to_string()),
            username: Some(username.to_string()),
        };
        let content = serialize_passkey(&proton_pass_key).unwrap();

        let passkey = PassPasskey {
            key_id: "key-01".to_string(),
            content,
            domain: rp_id.to_string(),
            rp_id: rp_id.to_string(),
            rp_name: "Example".to_string(),
            user_name: username.to_string(),
            user_display_name: user_display_name.to_string(),
            user_id: user_handle.clone(),
            create_time: 0,
            note: String::new(),
            credential_id: credential_id.clone(),
            user_handle: user_handle.clone(),
            creation_data: None,
        };

        let login = LoginItem {
            email: email.to_string(),
            username: String::new(),
            password: password.to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: vec![passkey],
            autofill_urls: Vec::new(),
        };
        let item = login_item("Login with passkey", login);

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(login_back.email, email);
        assert_eq!(login_back.password, password);
        assert_eq!(login_back.passkeys.len(), 1);
        assert_eq!(login_back.passkeys[0].rp_id, rp_id);
        assert_eq!(login_back.passkeys[0].credential_id, credential_id);
        assert_eq!(login_back.passkeys[0].user_handle, user_handle);
    }

    #[test]
    fn custom_icon_is_dropped_on_export_and_none_on_import() {
        let mut item = login_item(
            "Icon item",
            LoginItem {
                email: "a@b.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );
        item.custom_icon = Some(vec![1, 2, 3, 4]);

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(!export_result.payload.contains("customIcon"));

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert_eq!(import_result.vaults[0].items[0].custom_icon, None);
    }

    #[test]
    fn full_identity_item_round_trips_end_to_end() {
        let first_name = "Jane";
        let last_name = "Doe";
        let email = "jane@example.com";
        let organization = "Acme";
        let identity = IdentityItem {
            full_name: format!("{first_name} Q {last_name}"),
            email: email.to_string(),
            phone_number: String::new(),
            first_name: first_name.to_string(),
            middle_name: "Q".to_string(),
            last_name: last_name.to_string(),
            birthdate: String::new(),
            gender: String::new(),
            extra_personal_details: Vec::new(),
            organization: organization.to_string(),
            street_address: String::new(),
            zip_or_postal_code: String::new(),
            city: String::new(),
            state_or_province: String::new(),
            country_or_region: String::new(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: Vec::new(),
            social_security_number: String::new(),
            passport_number: String::new(),
            license_number: String::new(),
            website: String::new(),
            x_handle: String::new(),
            second_phone_number: String::new(),
            linkedin: String::new(),
            reddit: String::new(),
            facebook: String::new(),
            yahoo: String::new(),
            instagram: String::new(),
            extra_contact_details: Vec::new(),
            company: String::new(),
            job_title: String::new(),
            personal_website: String::new(),
            work_phone_number: String::new(),
            work_email: String::new(),
            extra_work_details: Vec::new(),
            extra_sections: Vec::new(),
        };
        let item = ItemData::new(
            "My identity".to_string(),
            String::new(),
            String::new(),
            ItemContent::Identity(Box::new(identity)),
            Vec::new(),
        )
        .unwrap();

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Identity(identity_back) = &imported.content else {
            panic!("expected identity content")
        };
        assert_eq!(identity_back.first_name, first_name);
        assert_eq!(identity_back.last_name, last_name);
        assert_eq!(identity_back.email, email);
        assert_eq!(identity_back.organization, organization);
    }

    #[test]
    fn malformed_payload_returns_deserialization_error() {
        let result = import_cxf("not json");
        assert!(matches!(result, Err(CxfError::DeserializationError(_))));
    }

    #[test]
    fn login_legacy_urls_export_when_autofill_urls_empty() {
        let url = "https://legacy.example.com";
        let login = LoginItem {
            email: "user@example.com".to_string(),
            username: String::new(),
            password: String::new(),
            urls: vec![url.to_string()],
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let item = login_item("Legacy login", login);

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(login_back.autofill_urls.len(), 1);
        assert_eq!(login_back.autofill_urls[0].url, url);
    }

    #[test]
    fn ssh_key_foreign_unlabeled_custom_field_is_kept_as_extra_field() {
        let extra_field_name = "foo";
        let extra_field_value = "bar";
        let private_key = generate_ssh_private_key_pkcs8_der_b64url();
        let payload = format!(
            r#"{{
                "version": {{ "major": 1, "minor": 0 }},
                "exporterRpId": "example.com",
                "exporterDisplayName": "Example Exporter",
                "timestamp": 1700000000,
                "accounts": [{{
                    "id": "account-01",
                    "username": "alice",
                    "email": "alice@example.com",
                    "collections": [],
                    "items": [{{
                        "id": "item-01",
                        "title": "My SSH Key",
                        "credentials": [
                            {{
                                "type": "ssh-key",
                                "keyType": "ssh-ed25519",
                                "privateKey": "{private_key}"
                            }},
                            {{
                                "type": "custom-fields",
                                "fields": [
                                    {{ "fieldType": "string", "label": "public_key", "value": "ssh-ed25519 AAAA" }},
                                    {{ "fieldType": "string", "label": "{extra_field_name}", "value": "{extra_field_value}" }}
                                ]
                            }}
                        ]
                    }}]
                }}]
            }}"#
        );

        let result = import_cxf(&payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        let ItemContent::SshKey(ssh_back) = &imported.content else {
            panic!("expected ssh key content")
        };
        assert_eq!(ssh_back.public_key, "ssh-ed25519 AAAA");
        assert!(imported.extra_fields.iter().any(|f| f.name == extra_field_name
            && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == extra_field_value)));
        assert!(!imported.extra_fields.iter().any(|f| f.name == "public_key"));
    }

    #[test]
    fn duplicate_item_ids_across_accounts_are_both_imported() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [
                {
                    "id": "account-01",
                    "username": "alice",
                    "email": "alice@example.com",
                    "collections": [],
                    "items": [{
                        "id": "item-01",
                        "title": "Alice login",
                        "credentials": [{
                            "type": "basic-auth",
                            "username": { "fieldType": "string", "value": "alice" }
                        }]
                    }]
                },
                {
                    "id": "account-02",
                    "username": "bob",
                    "email": "bob@example.com",
                    "collections": [],
                    "items": [{
                        "id": "item-01",
                        "title": "Bob login",
                        "credentials": [{
                            "type": "basic-auth",
                            "username": { "fieldType": "string", "value": "bob" }
                        }]
                    }]
                }
            ]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let titles: Vec<&str> = result
            .vaults
            .iter()
            .flat_map(|v| v.items.iter().map(|i| i.title.as_str()))
            .collect();
        assert_eq!(titles.len(), 2);
        assert!(titles.contains(&"Alice login"));
        assert!(titles.contains(&"Bob login"));
    }

    #[test]
    fn duplicate_item_ids_within_an_account_are_both_imported_with_warning() {
        // These two ids decode to the same underlying B64Url bytes, simulating a
        // malformed payload where two items in the same account share an id.
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [
                    { "id": "coll-01", "title": "Vault", "items": [{ "item": "item-01" }] }
                ],
                "items": [
                    {
                        "id": "item-01",
                        "title": "First",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "a" } }]
                    },
                    {
                        "id": "item-02",
                        "title": "Second",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "b" } }]
                    }
                ]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].kind, CxfWarningKind::MalformedInput);

        let titles: Vec<&str> = result
            .vaults
            .iter()
            .flat_map(|v| v.items.iter().map(|i| i.title.as_str()))
            .collect();
        assert_eq!(titles.len(), 2);
        assert!(titles.contains(&"First"));
        assert!(titles.contains(&"Second"));
    }

    #[test]
    fn item_shared_across_multiple_collections_is_imported_into_each_vault() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [
                    { "id": "coll-01", "title": "Vault One", "items": [{ "item": "item-shared" }] },
                    { "id": "coll-02", "title": "Vault Two", "items": [{ "item": "item-shared" }] }
                ],
                "items": [
                    {
                        "id": "item-shared",
                        "title": "Shared item",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "a" } }]
                    }
                ]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();

        // No warnings issued
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        // 2 vaults imported
        assert_eq!(result.vaults.len(), 2);
        for vault in &result.vaults {
            // Each vault contains the same item
            assert_eq!(vault.items.len(), 1);
            assert_eq!(vault.items[0].title, "Shared item");
        }
    }

    #[test]
    fn item_metadata_maps_to_cxf_item_creation_modification_and_favorite() {
        let item = login_item(
            "Pinned login",
            LoginItem {
                email: "pinned@example.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );
        let metadata = ItemMetadata {
            created_at: 1_650_000_000,
            modified_at: 1_660_000_000,
            pinned: true,
        };

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![ItemWithMetadata { item, metadata }],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let json: serde_json::Value = serde_json::from_str(&export_result.payload).unwrap();
        let cxf_item = &json["accounts"][0]["items"][0];
        assert_eq!(cxf_item["creationAt"], 1_650_000_000);
        assert_eq!(cxf_item["modifiedAt"], 1_660_000_000);
        assert_eq!(cxf_item["favorite"], true);
    }

    #[test]
    fn unpinned_item_metadata_omits_favorite_field() {
        let item = login_item(
            "Unpinned login",
            LoginItem {
                email: "unpinned@example.com".to_string(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            },
        );
        let metadata = ItemMetadata {
            created_at: 0,
            modified_at: 0,
            pinned: false,
        };

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![ItemWithMetadata { item, metadata }],
        }]);
        let export_result = export_cxf(input).unwrap();

        let json: serde_json::Value = serde_json::from_str(&export_result.payload).unwrap();
        let cxf_item = &json["accounts"][0]["items"][0];
        assert!(cxf_item.get("favorite").is_none());
    }

    #[test]
    fn login_with_distinct_email_and_username_round_trips_without_loss() {
        let email = "alice@example.com";
        let username = "alice_the_gamer";
        let login = LoginItem {
            email: email.to_string(),
            username: username.to_string(),
            password: "hunter2".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let item = login_item("Login with distinct email and username", login);

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);
        assert!(!export_result.payload.contains("extensions"));

        let json: serde_json::Value = serde_json::from_str(&export_result.payload).unwrap();
        let credentials = json["accounts"][0]["items"][0]["credentials"].as_array().unwrap();
        assert!(credentials.iter().any(|c| {
            c["type"] == "custom-fields"
                && c["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f["label"] == "email" && f["value"] == email)
                && c["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f["label"] == "username" && f["value"] == username)
        }));

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(login_back.email, email);
        assert_eq!(login_back.username, username);
    }

    #[test]
    fn login_extra_field_is_not_swallowed_by_identifiers_credential() {
        let email = "alice@example.com";
        let extra_field_name = "Security Question";
        let extra_field_value = "Mother's maiden name";
        let login = LoginItem {
            email: email.to_string(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let mut item = login_item("Login with extra field", login);
        item.extra_fields.push(ItemExtraField {
            name: extra_field_name.to_string(),
            content: ItemExtraFieldContent::Text(extra_field_value.to_string()),
        });

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(login_back.email, email);
        assert!(imported.extra_fields.iter().any(|f| f.name == extra_field_name
            && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == extra_field_value)));
        assert!(!imported.extra_fields.iter().any(|f| f.name == "email"));
    }

    #[test]
    fn login_with_username_only_round_trips_without_becoming_an_email() {
        let username = "just_a_handle";
        let login = LoginItem {
            email: String::new(),
            username: username.to_string(),
            password: "hunter2".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let item = login_item("Login with username only", login);

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert!(login_back.email.is_empty());
        assert_eq!(login_back.username, username);
    }

    #[test]
    fn multiple_totp_credentials_first_is_primary_rest_are_appended_in_order() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [],
                "items": [{
                    "id": "item-01",
                    "title": "Many TOTPs",
                    "credentials": [
                        { "type": "basic-auth", "username": { "fieldType": "string", "value": "alice" } },
                        { "type": "totp", "secret": "AAAAAAAAAAAAAAAA", "period": 30, "digits": 6, "algorithm": "sha1" },
                        { "type": "totp", "secret": "BBBBBBBBBBBBBBBB", "period": 30, "digits": 6, "algorithm": "sha1" },
                        { "type": "totp", "secret": "CCCCCCCCCCCCCCCC", "period": 30, "digits": 6, "algorithm": "sha1" }
                    ]
                }]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        let ItemContent::Login(login) = &imported.content else {
            panic!("expected login content")
        };
        assert!(login.totp_uri.contains("AAAAAAAAAAAAAAAA"));

        let second = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "TOTP")
            .expect("second totp credential imported as generic extra field");
        assert!(matches!(&second.content, ItemExtraFieldContent::Totp(uri) if uri.contains("BBBBBBBBBBBBBBBB")));

        let third = imported
            .extra_fields
            .iter()
            .find(|f| f.name == "TOTP 2")
            .expect("third totp credential imported with positional generic name");
        assert!(matches!(&third.content, ItemExtraFieldContent::Totp(uri) if uri.contains("CCCCCCCCCCCCCCCC")));
    }

    #[test]
    fn login_with_multiple_extra_totps_exports_as_multiple_totp_credentials() {
        let login = LoginItem {
            email: "alice@example.com".to_string(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            totp_uri: "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30".to_string(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let mut item = login_item("Login with many extra totps", login);
        item.extra_fields.push(ItemExtraField {
            name: "Backup 1".to_string(),
            content: ItemExtraFieldContent::Totp(
                "otpauth://totp/backup1?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30".to_string(),
            ),
        });
        item.extra_fields.push(ItemExtraField {
            name: "Backup 2".to_string(),
            content: ItemExtraFieldContent::Totp(
                "otpauth://totp/backup2?secret=MFRGGZDFMZTWQ2LK&algorithm=SHA1&digits=6&period=30".to_string(),
            ),
        });

        let input = export_input(vec![CxfVaultWithItems {
            vault: vault_data("Vault"),
            items: vec![with_metadata(item)],
        }]);
        let export_result = export_cxf(input).unwrap();
        assert!(export_result.warnings.is_empty(), "{:?}", export_result.warnings);

        let json: serde_json::Value = serde_json::from_str(&export_result.payload).unwrap();
        let credentials = json["accounts"][0]["items"][0]["credentials"].as_array().unwrap();
        let totp_count = credentials.iter().filter(|c| c["type"] == "totp").count();
        assert_eq!(
            totp_count, 3,
            "primary + two extra TOTPs should all be plain totp credentials"
        );

        let import_result = import_cxf(&export_result.payload).unwrap();
        assert!(import_result.warnings.is_empty(), "{:?}", import_result.warnings);
        let imported = &import_result.vaults[0].items[0];
        let ItemContent::Login(login_back) = &imported.content else {
            panic!("expected login content")
        };
        assert!(login_back.totp_uri.contains("JBSWY3DPEHPK3PXP"));
        assert!(imported.extra_fields.iter().any(|f| f.name == "TOTP"
            && matches!(&f.content, ItemExtraFieldContent::Totp(u) if u.contains("GEZDGNBVGY3TQOJQ"))));
        assert!(imported.extra_fields.iter().any(|f| f.name == "TOTP 2"
            && matches!(&f.content, ItemExtraFieldContent::Totp(u) if u.contains("MFRGGZDFMZTWQ2LK"))));
    }

    #[test]
    fn items_in_nested_sub_collections_are_kept_in_the_parent_vault() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [{
                    "id": "dG9wLWxldmVs",
                    "title": "Top Level",
                    "items": [{ "item": "dG9wLWl0ZW0" }],
                    "subCollections": [{
                        "id": "bmVzdGVk",
                        "title": "Nested",
                        "items": [{ "item": "bmVzdGVkLWl0ZW0" }],
                        "subCollections": [{
                            "id": "ZGVlcGx5LW5lc3RlZA",
                            "title": "Deeply Nested",
                            "items": [{ "item": "ZGVlcGx5LW5lc3RlZC1pdGVt" }]
                        }]
                    }]
                }],
                "items": [
                    {
                        "id": "dG9wLWl0ZW0",
                        "title": "Top item",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "top" } }]
                    },
                    {
                        "id": "bmVzdGVkLWl0ZW0",
                        "title": "Nested item",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "nested" } }]
                    },
                    {
                        "id": "ZGVlcGx5LW5lc3RlZC1pdGVt",
                        "title": "Deeply nested item",
                        "credentials": [{ "type": "note", "content": { "fieldType": "string", "value": "deep" } }]
                    }
                ]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.vaults.len(), 1);

        let vault = &result.vaults[0];
        assert!(vault.vault.is_some());
        let titles: Vec<&str> = vault.items.iter().map(|item| item.title.as_str()).collect();
        assert!(titles.contains(&"Top item"));
        assert!(titles.contains(&"Nested item"));
        assert!(titles.contains(&"Deeply nested item"));
    }

    #[test]
    fn api_key_credential_is_imported_as_a_custom_item() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [],
                "items": [{
                    "id": "item-01",
                    "title": "My API Key",
                    "credentials": [{
                        "type": "api-key",
                        "key": { "fieldType": "concealed-string", "value": "secret-token" },
                        "username": { "fieldType": "string", "value": "service-account" },
                        "keyType": { "fieldType": "string", "value": "Bearer" },
                        "url": { "fieldType": "string", "value": "https://api.example.com" }
                    }]
                }]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        assert_eq!(imported.title, "My API Key");
        let ItemContent::Custom(custom_item) = &imported.content else {
            panic!("expected custom item content")
        };
        assert_eq!(custom_item.sections.len(), 1);
        let fields = &custom_item.sections[0].section_fields;
        assert!(
            fields.iter().any(|f| f.name == "API Key"
                && matches!(&f.content, ItemExtraFieldContent::Hidden(v) if v == "secret-token"))
        );
        assert!(
            fields.iter().any(|f| f.name == "Username"
                && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == "service-account"))
        );
        assert!(
            fields
                .iter()
                .any(|f| f.name == "Key Type" && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == "Bearer"))
        );
        assert!(fields.iter().any(|f| f.name == "URL"
            && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == "https://api.example.com")));
    }

    #[test]
    fn secondary_api_key_alongside_login_is_kept_as_extra_fields() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [],
                "items": [{
                    "id": "item-01",
                    "title": "My Login",
                    "credentials": [
                        {
                            "type": "basic-auth",
                            "username": { "fieldType": "string", "value": "alice" },
                            "password": { "fieldType": "concealed-string", "value": "hunter2" }
                        },
                        {
                            "type": "api-key",
                            "key": { "fieldType": "concealed-string", "value": "secret-token" },
                            "keyType": { "fieldType": "string", "value": "Bearer" }
                        }
                    ]
                }]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        let ItemContent::Login(login) = &imported.content else {
            panic!("expected login content")
        };
        assert_eq!(login.username, "alice");
        assert!(
            imported.extra_fields.iter().any(|f| f.name == "API Key"
                && matches!(&f.content, ItemExtraFieldContent::Hidden(v) if v == "secret-token"))
        );
        assert!(
            imported
                .extra_fields
                .iter()
                .any(|f| f.name == "Key Type" && matches!(&f.content, ItemExtraFieldContent::Text(v) if v == "Bearer"))
        );
    }

    #[test]
    fn second_api_key_credential_on_the_same_item_is_kept_as_extra_fields() {
        let payload = r#"{
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "example.com",
            "exporterDisplayName": "Example Exporter",
            "timestamp": 1700000000,
            "accounts": [{
                "id": "account-01",
                "username": "",
                "email": "",
                "collections": [],
                "items": [{
                    "id": "item-01",
                    "title": "My API Keys",
                    "credentials": [
                        {
                            "type": "api-key",
                            "key": { "fieldType": "concealed-string", "value": "primary-token" }
                        },
                        {
                            "type": "api-key",
                            "key": { "fieldType": "concealed-string", "value": "secondary-token" }
                        }
                    ]
                }]
            }]
        }"#;

        let result = import_cxf(payload).unwrap();
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let imported = &result.vaults[0].items[0];
        let ItemContent::Custom(custom_item) = &imported.content else {
            panic!("expected custom item content")
        };
        assert!(
            custom_item.sections[0]
                .section_fields
                .iter()
                .any(|f| f.name == "API Key"
                    && matches!(&f.content, ItemExtraFieldContent::Hidden(v) if v == "primary-token"))
        );
        assert!(
            imported.extra_fields.iter().any(|f| f.name == "API Key"
                && matches!(&f.content, ItemExtraFieldContent::Hidden(v) if v == "secondary-token"))
        );
    }
}
