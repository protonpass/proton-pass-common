mod archive;
mod handshake;
mod hpke;

use crate::cxf::{CxfCredentialKind, CxfError, CxfExportInput, CxfImportResult, CxfWarning, CxfWarningKind};
use credential_exchange_protocol::{CredentialType, ExportResponse, Version};
use parking_lot::Mutex;
use proton_pass_derive::{Error, ffi_error};
use proton_pass_types::ItemContent;
use zeroize::Zeroizing;

#[proton_pass_derive::ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxpCredentialType {
    BasicAuth,
    Passkey,
    Totp,
    Note,
    File,
    Address,
    CreditCard,
    DriverLicense,
    ItemReference,
    IdentityDocument,
    Passport,
    PersonName,
    SshKey,
    ApiKey,
}

impl From<CxpCredentialType> for CredentialType {
    fn from(value: CxpCredentialType) -> Self {
        match value {
            CxpCredentialType::BasicAuth => CredentialType::BasicAuth,
            CxpCredentialType::Passkey => CredentialType::Passkey,
            CxpCredentialType::Totp => CredentialType::Totp,
            CxpCredentialType::Note => CredentialType::Note,
            CxpCredentialType::File => CredentialType::File,
            CxpCredentialType::Address => CredentialType::Address,
            CxpCredentialType::CreditCard => CredentialType::CreditCard,
            CxpCredentialType::DriverLicense => CredentialType::DriverLicense,
            CxpCredentialType::ItemReference => CredentialType::ItemReference,
            CxpCredentialType::IdentityDocument => CredentialType::IdentityDocument,
            CxpCredentialType::Passport => CredentialType::Passport,
            CxpCredentialType::PersonName => CredentialType::PersonName,
            CxpCredentialType::SshKey => CredentialType::SshKey,
            CxpCredentialType::ApiKey => CredentialType::ApiKey,
        }
    }
}

impl CxpCredentialType {
    fn from_upstream(value: &CredentialType) -> Option<Self> {
        Some(match value {
            CredentialType::BasicAuth => CxpCredentialType::BasicAuth,
            CredentialType::Passkey => CxpCredentialType::Passkey,
            CredentialType::Totp => CxpCredentialType::Totp,
            CredentialType::Note => CxpCredentialType::Note,
            CredentialType::File => CxpCredentialType::File,
            CredentialType::Address => CxpCredentialType::Address,
            CredentialType::CreditCard => CxpCredentialType::CreditCard,
            CredentialType::DriverLicense => CxpCredentialType::DriverLicense,
            CredentialType::ItemReference => CxpCredentialType::ItemReference,
            CredentialType::IdentityDocument => CxpCredentialType::IdentityDocument,
            CredentialType::Passport => CxpCredentialType::Passport,
            CredentialType::PersonName => CxpCredentialType::PersonName,
            CredentialType::SshKey => CxpCredentialType::SshKey,
            CredentialType::ApiKey => CxpCredentialType::ApiKey,
            CredentialType::Unknown(_) => return None,
        })
    }

    fn allowed_export_kinds(self) -> &'static [CxfCredentialKind] {
        match self {
            CxpCredentialType::BasicAuth => &[CxfCredentialKind::BasicAuth],
            CxpCredentialType::Passkey => &[CxfCredentialKind::Passkey],
            CxpCredentialType::Totp => &[CxfCredentialKind::Totp],
            CxpCredentialType::Note => &[CxfCredentialKind::Note],
            CxpCredentialType::Address => &[CxfCredentialKind::Address],
            CxpCredentialType::CreditCard => &[CxfCredentialKind::CreditCard],
            CxpCredentialType::DriverLicense => &[CxfCredentialKind::DriversLicense],
            CxpCredentialType::IdentityDocument => &[CxfCredentialKind::IdentityDocument],
            CxpCredentialType::Passport => &[CxfCredentialKind::Passport],
            CxpCredentialType::PersonName => &[CxfCredentialKind::PersonName],
            CxpCredentialType::SshKey => &[CxfCredentialKind::SshKey],
            CxpCredentialType::ApiKey => &[CxfCredentialKind::ApiKey],
            CxpCredentialType::File | CxpCredentialType::ItemReference => &[],
        }
    }
}

const EXPORTABLE_CREDENTIAL_TYPES: [CxpCredentialType; 14] = [
    CxpCredentialType::BasicAuth,
    CxpCredentialType::Passkey,
    CxpCredentialType::Totp,
    CxpCredentialType::Note,
    CxpCredentialType::File,
    CxpCredentialType::Address,
    CxpCredentialType::CreditCard,
    CxpCredentialType::DriverLicense,
    CxpCredentialType::ItemReference,
    CxpCredentialType::IdentityDocument,
    CxpCredentialType::Passport,
    CxpCredentialType::PersonName,
    CxpCredentialType::SshKey,
    CxpCredentialType::ApiKey,
];

fn allowed_export_kinds(requested: Option<&[CredentialType]>) -> Option<Vec<CxfCredentialKind>> {
    let requested = requested?;
    let mut kinds = Vec::new();
    for credential_type in requested {
        let Some(credential_type) = CxpCredentialType::from_upstream(credential_type) else {
            // An unknown type is one Proton Pass cannot produce, so it contributes no kinds.
            continue;
        };
        for kind in credential_type.allowed_export_kinds() {
            if !kinds.contains(kind) {
                kinds.push(*kind);
            }
        }
    }
    Some(kinds)
}

fn exportable_types(allowed: Option<&[CxfCredentialKind]>) -> Vec<CxpCredentialType> {
    EXPORTABLE_CREDENTIAL_TYPES
        .into_iter()
        .filter(|credential_type| match allowed {
            None => !credential_type.allowed_export_kinds().is_empty(),
            Some(allowed) => credential_type
                .allowed_export_kinds()
                .iter()
                .any(|kind| allowed.contains(kind)),
        })
        .collect()
}

fn types_of_exported_kinds(kinds: &[CxfCredentialKind]) -> Vec<CxpCredentialType> {
    EXPORTABLE_CREDENTIAL_TYPES
        .into_iter()
        .filter(|credential_type| {
            credential_type
                .allowed_export_kinds()
                .iter()
                .any(|kind| kinds.contains(kind))
        })
        .collect()
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxpExportRequestSummary {
    pub importer_name: String,
    pub requested_credential_types: Vec<CxpCredentialType>,
    pub exportable_credential_types: Vec<CxpCredentialType>,
    pub requests_all_credential_types: bool,
}

#[proton_pass_derive::ffi_type]
#[derive(Debug, PartialEq, Eq)]
pub struct CxpExportRequest {
    pub importer_name: String,
    pub supported_credential_types: Vec<CxpCredentialType>,
}

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CxpError {
    SerializationError(String),
    DeserializationError(String),
    UnsupportedHpkeParameters(String),
    UnsupportedArchiveAlgorithm(String),
    EncryptionError(String),
    DecryptionError(String),
    InvalidState(String),
}

struct CxpExportEnvelope {
    ephemeral_private_key: Zeroizing<Vec<u8>>,
    importer_name: String,
    request: String,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxpExportResponse {
    pub response: Vec<u8>,
    pub warnings: Vec<CxfWarning>,
    pub sent_credential_types: Vec<CxpCredentialType>,
}

fn begin_cxp_export(request: CxpExportRequest) -> Result<(String, CxpExportEnvelope), CxpError> {
    let keypair = hpke::generate_keypair();
    let serialized = handshake::build_export_request(
        &request.importer_name,
        request.supported_credential_types,
        keypair.public_jwk,
    )?;

    Ok((
        serialized.clone(),
        CxpExportEnvelope {
            ephemeral_private_key: keypair.private_key,
            importer_name: request.importer_name,
            request: serialized,
        },
    ))
}

fn credential_types_for_item(content: &ItemContent) -> Vec<CxpCredentialType> {
    match content {
        ItemContent::Login(login) => {
            let mut types = vec![CxpCredentialType::BasicAuth];
            if !login.passkeys.is_empty() {
                types.push(CxpCredentialType::Passkey);
            }
            if !login.totp_uri.is_empty() {
                types.push(CxpCredentialType::Totp);
            }
            types
        }
        ItemContent::Note(_) => vec![CxpCredentialType::Note],
        ItemContent::CreditCard(_) => vec![CxpCredentialType::CreditCard],
        ItemContent::SshKey(_) => vec![CxpCredentialType::SshKey],
        ItemContent::Identity(_) => vec![
            CxpCredentialType::PersonName,
            CxpCredentialType::Address,
            CxpCredentialType::IdentityDocument,
            CxpCredentialType::Passport,
            CxpCredentialType::DriverLicense,
        ],
        ItemContent::Alias(_) | ItemContent::Wifi(_) | ItemContent::Custom(_) => Vec::new(),
    }
}

fn exclude_items_with_no_representable_type(export: &mut CxfExportInput, warnings: &mut Vec<CxfWarning>) {
    for vault in &mut export.vaults {
        vault.items.retain(|item| {
            if credential_types_for_item(&item.item.content).is_empty() {
                warnings.push(CxfWarning {
                    item_title: Some(item.item.title.clone()),
                    message:
                        "This item type cannot be represented by the CXP protocol and was excluded from the export"
                            .to_string(),
                    kind: CxfWarningKind::UnsupportedCredential,
                });
                return false;
            }
            true
        });
    }
}

fn summarize_export_request(request: &str) -> Result<CxpExportRequestSummary, CxpError> {
    let parsed_request = handshake::parse_export_request(request)?;
    let requested_credential_types = parsed_request
        .request
        .credential_types
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(CxpCredentialType::from_upstream)
        .collect();

    let allowed = allowed_export_kinds(parsed_request.request.credential_types.as_deref());

    Ok(CxpExportRequestSummary {
        importer_name: parsed_request.request.importer,
        requested_credential_types,
        exportable_credential_types: exportable_types(allowed.as_deref()),
        requests_all_credential_types: parsed_request.request.credential_types.is_none(),
    })
}

fn respond_to_cxp_export(request: &str, mut export: CxfExportInput) -> Result<CxpExportResponse, CxpError> {
    let parsed_request = handshake::parse_export_request(request)?;
    let (aead, recipient_key) = handshake::negotiate_recipient_key(&parsed_request.request)?;
    let archive_algorithm = archive::negotiate(&parsed_request.archive)?;

    let mut warnings = Vec::new();
    exclude_items_with_no_representable_type(&mut export, &mut warnings);

    let allowed = allowed_export_kinds(parsed_request.request.credential_types.as_deref());

    let exporter_name = export.exporter_display_name.clone();
    let outcome = crate::cxf::export_cxf_with_allowed_kinds(export, allowed.as_deref())
        .map_err(|e| CxpError::SerializationError(format!("{e}")))?;
    warnings.extend(outcome.result.warnings);
    let sent_credential_types = types_of_exported_kinds(&outcome.exported_credential_kinds);

    let compressed_payload = archive::compress(archive_algorithm, outcome.result.payload.as_bytes())?;

    let sealed = hpke::seal(
        aead,
        &recipient_key,
        parsed_request.request.importer.as_bytes(),
        request.as_bytes(),
        &compressed_payload,
    )?;

    let response = ExportResponse {
        version: Version::V0,
        hpke: hpke::selected_parameters(aead, sealed.encapped_key_jwk),
        exporter: exporter_name,
        payload: sealed.ciphertext.into(),
    };

    let response = handshake::build_export_response(&response, archive_algorithm)?;

    Ok(CxpExportResponse {
        response,
        warnings,
        sent_credential_types,
    })
}

fn complete_cxp_export(envelope: CxpExportEnvelope, encrypted_response: &[u8]) -> Result<CxfImportResult, CxpError> {
    let parsed_response = handshake::parse_export_response(encrypted_response)?;
    let aead = handshake::validate_export_response(&parsed_response.response)?;
    let encapped_key = parsed_response.response.hpke.key.clone().ok_or_else(|| {
        CxpError::UnsupportedHpkeParameters("CXP export response is missing the encapsulated key".to_string())
    })?;

    let plaintext = hpke::open(
        aead,
        &envelope.ephemeral_private_key,
        &encapped_key,
        envelope.importer_name.as_bytes(),
        envelope.request.as_bytes(),
        parsed_response.response.payload.as_ref(),
    )?;

    let response_archive = archive::parse_selected(&parsed_response.archive)?;
    let mut decompressed = Zeroizing::new(archive::decompress(response_archive, &plaintext)?);

    let payload = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *decompressed))
            .map_err(|e| CxpError::DeserializationError(format!("decrypted CXP payload was not valid UTF-8: {e}")))?,
    );

    crate::cxf::import_cxf(&payload).map_err(|e: CxfError| CxpError::DeserializationError(format!("{e}")))
}

#[derive(Default)]
pub struct CxpImportHandler {
    pending: Mutex<Option<CxpExportEnvelope>>,
}

impl CxpImportHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_export_request(&self, request: CxpExportRequest) -> Result<String, CxpError> {
        let (serialized, envelope) = begin_cxp_export(request)?;
        *self.pending.lock() = Some(envelope);
        Ok(serialized)
    }

    pub fn process_export_response(&self, encrypted_response: &[u8]) -> Result<CxfImportResult, CxpError> {
        let envelope = self.pending.lock().take().ok_or_else(|| {
            CxpError::InvalidState("create_export_request must be called before process_export_response".to_string())
        })?;
        complete_cxp_export(envelope, encrypted_response)
    }
}

#[derive(Default)]
pub struct CxpExportHandler;

impl CxpExportHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn create_export_response(&self, request: &str, export: CxfExportInput) -> Result<CxpExportResponse, CxpError> {
        respond_to_cxp_export(request, export)
    }

    pub fn parse_export_request(&self, request: &str) -> Result<CxpExportRequestSummary, CxpError> {
        summarize_export_request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxf::test_support::sample_passkey;
    use crate::cxf::{CxfVaultWithItems, ItemMetadata, ItemWithMetadata};
    use proton_pass_types::{ItemContent, ItemData, LoginItem, VaultData, VaultDisplayPreferences};

    fn export_and_decrypt(
        input: CxfExportInput,
        requested: Option<Vec<CxpCredentialType>>,
    ) -> (crate::cxf::CxfHeader, CxpExportResponse) {
        let keypair = hpke::generate_keypair();
        let request =
            handshake::build_export_request("Peer", requested.unwrap_or_default(), keypair.public_jwk).unwrap();

        let exporter = CxpExportHandler::new();
        let response = exporter.create_export_response(&request, input).unwrap();

        let parsed_response = handshake::parse_export_response(&response.response).unwrap();
        let aead = handshake::validate_export_response(&parsed_response.response).unwrap();
        let encapped_key = parsed_response.response.hpke.key.clone().unwrap();
        let plaintext = hpke::open(
            aead,
            &keypair.private_key,
            &encapped_key,
            b"Peer",
            request.as_bytes(),
            parsed_response.response.payload.as_ref(),
        )
        .unwrap();
        let response_archive = archive::parse_selected(&parsed_response.archive).unwrap();
        let decompressed = archive::decompress(response_archive, &plaintext).unwrap();
        let payload = String::from_utf8(decompressed).unwrap();
        let header: crate::cxf::CxfHeader = serde_json::from_str(&payload).unwrap();
        (header, response)
    }

    fn credential_kinds(header: &crate::cxf::CxfHeader) -> Vec<CxfCredentialKind> {
        header.accounts[0]
            .items
            .iter()
            .flat_map(|item| item.credentials.iter())
            .map(CxfCredentialKind::of)
            .collect()
    }

    fn sample_export_input() -> CxfExportInput {
        let login = LoginItem {
            email: "alice@example.com".to_string(),
            username: String::new(),
            password: "hunter2".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let item = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(login),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![ItemWithMetadata {
                    item,
                    metadata: ItemMetadata {
                        created_at: 0,
                        modified_at: 0,
                        pinned: false,
                    },
                }],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn full_export_import_self_loop_round_trips() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::BasicAuth],
            })
            .unwrap();

        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();
        assert!(encrypted_response.warnings.is_empty());

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        assert_eq!(result.vaults.len(), 1);
        let imported_vault = &result.vaults[0];
        assert_eq!(imported_vault.vault.as_ref().unwrap().name, "Personal");
        let imported_item = &imported_vault.items[0];
        let ItemContent::Login(login) = &imported_item.content else {
            panic!("expected login content")
        };
        assert_eq!(login.email, "alice@example.com");
        assert_eq!(login.password, "hunter2");
    }

    #[test]
    fn export_request_includes_mode_and_archive_fields() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let json: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(json["mode"], "direct");
        assert_eq!(json["archive"], serde_json::json!(["deflate"]));
    }

    #[test]
    fn export_response_includes_archive_field() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();

        let json: serde_json::Value = serde_json::from_slice(&encrypted_response.response).unwrap();
        assert_eq!(json["archive"], "deflate");
    }

    #[test]
    fn export_request_offers_multiple_hpke_aead_suites() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let json: serde_json::Value = serde_json::from_str(&request).unwrap();
        let aeads: Vec<u64> = json["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .map(|params| params["aead"].as_u64().unwrap())
            .collect();
        assert_eq!(aeads, vec![3, 1, 2]);
    }

    #[test]
    fn export_succeeds_when_peer_only_offers_aes_256_gcm() {
        let keypair = hpke::generate_keypair();
        let request = handshake::build_export_request("Proton Pass", vec![], keypair.public_jwk).unwrap();
        let mut request: serde_json::Value = serde_json::from_str(&request).unwrap();
        let hpke_offers = request["hpke"].as_array().unwrap().clone();
        let aes_256_offer = hpke_offers.into_iter().find(|params| params["aead"] == 2).unwrap();
        request["hpke"] = serde_json::json!([aes_256_offer]);
        let request = serde_json::to_string(&request).unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();
        assert!(encrypted_response.warnings.is_empty());

        let response_json: serde_json::Value = serde_json::from_slice(&encrypted_response.response).unwrap();
        assert_eq!(response_json["hpke"]["aead"], 2);

        let parsed_response = handshake::parse_export_response(&encrypted_response.response).unwrap();
        let aead = handshake::validate_export_response(&parsed_response.response).unwrap();
        let encapped_key = parsed_response.response.hpke.key.clone().unwrap();
        let plaintext = hpke::open(
            aead,
            &keypair.private_key,
            &encapped_key,
            b"Proton Pass",
            request.as_bytes(),
            parsed_response.response.payload.as_ref(),
        )
        .unwrap();
        let response_archive = archive::parse_selected(&parsed_response.archive).unwrap();
        let decompressed = archive::decompress(response_archive, &plaintext).unwrap();
        let payload = String::from_utf8(decompressed).unwrap();
        let import_result = crate::cxf::import_cxf(&payload).unwrap();
        assert_eq!(import_result.vaults.len(), 1);
    }

    #[test]
    fn export_request_missing_mode_is_rejected() {
        let request = r#"{
            "version": 0,
            "hpke": [],
            "importer": "Some Importer",
            "archive": ["deflate"]
        }"#;

        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response(request, sample_export_input());
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn export_request_with_unsupported_archive_algorithm_is_rejected_cleanly() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let mut request: serde_json::Value = serde_json::from_str(&request).unwrap();
        request["archive"] = serde_json::json!(["zip"]);
        let request = serde_json::to_string(&request).unwrap();

        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response(&request, sample_export_input());
        assert!(matches!(result, Err(CxpError::UnsupportedArchiveAlgorithm(_))));
    }

    #[test]
    fn processing_a_response_without_a_pending_request_returns_invalid_state() {
        let importer = CxpImportHandler::new();
        let result = importer.process_export_response(b"anything");
        assert!(matches!(result, Err(CxpError::InvalidState(_))));
    }

    #[test]
    fn processing_a_response_twice_returns_invalid_state_on_the_second_call() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;

        assert!(importer.process_export_response(&encrypted_response).is_ok());
        assert!(matches!(
            importer.process_export_response(&encrypted_response),
            Err(CxpError::InvalidState(_))
        ));
    }

    #[test]
    fn starting_a_new_request_discards_a_not_yet_completed_one() {
        let importer = CxpImportHandler::new();

        let stale_request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "First".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Second".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        // Encrypted for the discarded "First" request's ephemeral key; the handler is now holding
        // "Second"'s key material instead, so decryption must fail rather than silently succeed.
        let exporter = CxpExportHandler::new();
        let response = exporter
            .create_export_response(&stale_request, sample_export_input())
            .unwrap()
            .response;

        let result = importer.process_export_response(&response);
        assert!(matches!(result, Err(CxpError::DecryptionError(_))));
    }

    #[test]
    fn unsupported_hpke_parameters_from_peer_are_rejected_cleanly() {
        let request = r#"{
            "version": 0,
            "hpke": [{
                "mode": "base",
                "kem": 16,
                "kdf": 1,
                "aead": 2,
                "key": null
            }],
            "importer": "Some Importer",
            "mode": "direct",
            "archive": ["deflate"]
        }"#;

        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response(request, sample_export_input());
        assert!(matches!(result, Err(CxpError::UnsupportedHpkeParameters(_))));
    }

    #[test]
    fn malformed_export_request_returns_clean_error() {
        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response("not json", sample_export_input());
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn parse_export_request_summarizes_importer_and_credential_types() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::BasicAuth, CxpCredentialType::Passkey],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(&request).unwrap();

        assert_eq!(summary.importer_name, "Proton Pass");
        assert_eq!(
            summary.requested_credential_types,
            vec![CxpCredentialType::BasicAuth, CxpCredentialType::Passkey]
        );
        assert!(!summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_reports_no_restriction_when_credential_types_absent() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(&request).unwrap();

        assert!(summary.requested_credential_types.is_empty());
        assert!(summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_drops_unrecognized_credential_types() {
        let request = r#"{
            "version": 0,
            "hpke": [],
            "importer": "Some Importer",
            "credentialTypes": ["basic-auth", "some-future-type"],
            "mode": "direct",
            "archive": ["deflate"]
        }"#;

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(request).unwrap();

        assert_eq!(summary.importer_name, "Some Importer");
        assert_eq!(summary.requested_credential_types, vec![CxpCredentialType::BasicAuth]);
        assert!(!summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_returns_clean_error_on_malformed_json() {
        let exporter = CxpExportHandler::new();
        let result = exporter.parse_export_request("not json");
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    fn login_with_totp_and_passkey(title: &str) -> ItemData {
        ItemData::new(
            title.to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: "alice".to_string(),
                password: "hunter2".to_string(),
                urls: vec!["https://example.com".to_string()],
                totp_uri: "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".to_string(),
                passkeys: vec![sample_passkey()],
                autofill_urls: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap()
    }

    fn single_item_input(item: ItemData) -> CxfExportInput {
        CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault: VaultData::new(
                    "Personal".to_string(),
                    String::new(),
                    VaultDisplayPreferences::default(),
                )
                .unwrap(),
                items: vec![ItemWithMetadata {
                    item,
                    metadata: ItemMetadata {
                        created_at: 0,
                        modified_at: 0,
                        pinned: false,
                    },
                }],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn requesting_only_basic_auth_does_not_leak_totp_or_passkeys_from_the_same_item() {
        let (header, response) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            Some(vec![CxpCredentialType::BasicAuth]),
        );

        let kinds = credential_kinds(&header);
        assert!(kinds.contains(&CxfCredentialKind::BasicAuth));
        assert!(!kinds.contains(&CxfCredentialKind::Totp), "{kinds:?}");
        assert!(!kinds.contains(&CxfCredentialKind::Passkey), "{kinds:?}");
        assert_eq!(response.sent_credential_types, vec![CxpCredentialType::BasicAuth]);
    }

    #[test]
    fn requesting_only_totp_does_not_leak_the_password_or_passkeys() {
        let (header, response) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            Some(vec![CxpCredentialType::Totp]),
        );

        assert_eq!(credential_kinds(&header), vec![CxfCredentialKind::Totp]);
        assert_eq!(response.sent_credential_types, vec![CxpCredentialType::Totp]);
    }

    #[test]
    fn requesting_only_passkeys_does_not_leak_the_password_or_totp() {
        let (header, response) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            Some(vec![CxpCredentialType::Passkey]),
        );

        assert_eq!(credential_kinds(&header), vec![CxfCredentialKind::Passkey]);
        assert_eq!(response.sent_credential_types, vec![CxpCredentialType::Passkey]);
    }

    #[test]
    fn requesting_only_basic_auth_drops_the_totp_stored_in_an_extra_field() {
        let mut item = ItemData::new(
            "Login with TOTP field".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: String::new(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            }),
            vec![proton_pass_types::ItemExtraField {
                name: "2FA".to_string(),
                content: proton_pass_types::ItemExtraFieldContent::Totp(
                    "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".to_string(),
                ),
            }],
        )
        .unwrap();
        item.note = "a secret note".to_string();

        let (header, response) = export_and_decrypt(single_item_input(item), Some(vec![CxpCredentialType::BasicAuth]));

        let kinds = credential_kinds(&header);
        assert!(!kinds.contains(&CxfCredentialKind::Totp), "{kinds:?}");
        assert!(!kinds.contains(&CxfCredentialKind::Note), "{kinds:?}");
        assert_eq!(response.sent_credential_types, vec![CxpCredentialType::BasicAuth]);
    }

    fn sample_identity() -> proton_pass_types::IdentityItem {
        proton_pass_types::IdentityItem {
            full_name: "Alice Doe".to_string(),
            email: "alice@example.com".to_string(),
            phone_number: "+10000000000".to_string(),
            first_name: "Alice".to_string(),
            middle_name: String::new(),
            last_name: "Doe".to_string(),
            birthdate: String::new(),
            gender: String::new(),
            extra_personal_details: Vec::new(),
            organization: String::new(),
            street_address: "1 Example Street".to_string(),
            zip_or_postal_code: "12345".to_string(),
            city: "Exampleville".to_string(),
            state_or_province: String::new(),
            country_or_region: "Wonderland".to_string(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: Vec::new(),
            social_security_number: "000-00-0000".to_string(),
            passport_number: "P1234567".to_string(),
            license_number: "D7654321".to_string(),
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
        }
    }

    fn identity_item_with_extras() -> ItemData {
        let mut identity = sample_identity();
        identity.extra_sections = vec![proton_pass_types::CustomSection {
            section_name: "Membership".to_string(),
            section_fields: vec![proton_pass_types::ItemExtraField {
                name: "Member ID".to_string(),
                content: proton_pass_types::ItemExtraFieldContent::Text("M-42".to_string()),
            }],
        }];
        ItemData::new(
            "Identity".to_string(),
            String::new(),
            String::new(),
            ItemContent::Identity(Box::new(identity)),
            vec![proton_pass_types::ItemExtraField {
                name: "Locker".to_string(),
                content: proton_pass_types::ItemExtraFieldContent::Hidden("1234".to_string()),
            }],
        )
        .unwrap()
    }

    #[test]
    fn requesting_only_person_name_does_not_leak_the_rest_of_an_identity_item() {
        let (header, response) = export_and_decrypt(
            single_item_input(identity_item_with_extras()),
            Some(vec![CxpCredentialType::PersonName]),
        );

        assert_eq!(credential_kinds(&header), vec![CxfCredentialKind::PersonName]);
        assert_eq!(response.sent_credential_types, vec![CxpCredentialType::PersonName]);
    }

    #[test]
    fn requesting_every_identity_type_keeps_the_identity_custom_fields() {
        let (header, _) = export_and_decrypt(
            single_item_input(identity_item_with_extras()),
            Some(vec![
                CxpCredentialType::PersonName,
                CxpCredentialType::Address,
                CxpCredentialType::IdentityDocument,
                CxpCredentialType::Passport,
                CxpCredentialType::DriverLicense,
            ]),
        );

        let custom_fields = credential_kinds(&header)
            .into_iter()
            .filter(|kind| *kind == CxfCredentialKind::CustomFields)
            .count();
        // Unmapped identity fields, the extra section and the item extra fields.
        assert_eq!(custom_fields, 3);
    }

    fn login_with_extra_field() -> ItemData {
        ItemData::new(
            "Login with extras".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: "alice".to_string(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: vec![sample_passkey()],
                autofill_urls: Vec::new(),
            }),
            vec![proton_pass_types::ItemExtraField {
                name: "Recovery code".to_string(),
                content: proton_pass_types::ItemExtraFieldContent::Hidden("abcd-efgh".to_string()),
            }],
        )
        .unwrap()
    }

    #[test]
    fn requesting_basic_auth_keeps_the_login_identifiers_and_extra_fields() {
        let (header, _) = export_and_decrypt(
            single_item_input(login_with_extra_field()),
            Some(vec![CxpCredentialType::BasicAuth]),
        );

        assert_eq!(
            credential_kinds(&header),
            vec![
                CxfCredentialKind::BasicAuth,
                CxfCredentialKind::CustomFields,
                CxfCredentialKind::CustomFields,
            ]
        );
    }

    #[test]
    fn requesting_only_passkeys_drops_the_login_extra_fields() {
        let (header, _) = export_and_decrypt(
            single_item_input(login_with_extra_field()),
            Some(vec![CxpCredentialType::Passkey]),
        );

        assert_eq!(credential_kinds(&header), vec![CxfCredentialKind::Passkey]);
    }

    #[test]
    fn requesting_ssh_keys_keeps_the_public_key_and_sections() {
        let private_key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::random(&mut rand::rng()));
        let item = ItemData::new(
            "SSH key".to_string(),
            String::new(),
            String::new(),
            ItemContent::SshKey(proton_pass_types::SshKeyItem {
                private_key: private_key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
                public_key: private_key.public_key().to_openssh().unwrap(),
                sections: vec![proton_pass_types::CustomSection {
                    section_name: "Host".to_string(),
                    section_fields: vec![proton_pass_types::ItemExtraField {
                        name: "Server".to_string(),
                        content: proton_pass_types::ItemExtraFieldContent::Text("example.com".to_string()),
                    }],
                }],
            }),
            Vec::new(),
        )
        .unwrap();

        let (header, response) = export_and_decrypt(single_item_input(item), Some(vec![CxpCredentialType::SshKey]));

        assert!(response.warnings.is_empty(), "{:?}", response.warnings);
        assert_eq!(
            credential_kinds(&header),
            vec![
                CxfCredentialKind::SshKey,
                CxfCredentialKind::CustomFields,
                CxfCredentialKind::CustomFields,
            ]
        );
    }

    #[test]
    fn restricting_the_export_does_not_report_warnings_about_credentials_it_drops() {
        // The login holds a passkey that fails to export, and an SSH key whose public half alone
        // would warn. Neither is requested, so neither should produce a warning.
        let (_, response) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            Some(vec![CxpCredentialType::BasicAuth]),
        );

        assert!(response.warnings.is_empty(), "{:?}", response.warnings);
    }

    #[test]
    fn requesting_a_type_proton_pass_cannot_produce_sends_no_credentials() {
        let (header, response) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            Some(vec![CxpCredentialType::File]),
        );

        assert!(credential_kinds(&header).is_empty());
        assert!(response.sent_credential_types.is_empty());
        assert!(header.accounts[0].items.is_empty());
    }

    #[test]
    fn an_unrestricted_request_still_exports_every_credential() {
        let (header, _) = export_and_decrypt(
            single_item_input(login_with_totp_and_passkey("Multi credential login")),
            None,
        );

        let kinds = credential_kinds(&header);
        assert!(kinds.contains(&CxfCredentialKind::BasicAuth));
        assert!(kinds.contains(&CxfCredentialKind::Totp));
        assert!(kinds.contains(&CxfCredentialKind::Passkey));
    }

    #[test]
    fn export_request_summary_reports_only_types_that_can_be_sent() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Peer".to_string(),
                supported_credential_types: vec![
                    CxpCredentialType::BasicAuth,
                    CxpCredentialType::File,
                    CxpCredentialType::ItemReference,
                ],
            })
            .unwrap();

        let summary = CxpExportHandler::new().parse_export_request(&request).unwrap();

        assert_eq!(
            summary.requested_credential_types,
            vec![
                CxpCredentialType::BasicAuth,
                CxpCredentialType::File,
                CxpCredentialType::ItemReference
            ]
        );
        assert_eq!(summary.exportable_credential_types, vec![CxpCredentialType::BasicAuth]);
    }

    #[test]
    fn create_export_response_only_includes_requested_credential_types() {
        use proton_pass_types::{CardType, CreditCardItem};

        let login = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: String::new(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let credit_card = ItemData::new(
            "My card".to_string(),
            String::new(),
            String::new(),
            ItemContent::CreditCard(CreditCardItem {
                cardholder_name: "Alice".to_string(),
                card_type: CardType::Visa,
                number: "4111111111111111".to_string(),
                verification_number: "123".to_string(),
                expiration_date: "2030-01".to_string(),
                pin: String::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        let export = CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![
                    ItemWithMetadata {
                        item: login,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                    ItemWithMetadata {
                        item: credit_card,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                ],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        };

        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::CreditCard],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter.create_export_response(&request, export).unwrap();

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        let imported_items = &result.vaults[0].items;
        assert_eq!(imported_items.len(), 1);
        assert!(matches!(imported_items[0].content, ItemContent::CreditCard(_)));
    }

    #[test]
    fn create_export_response_warns_and_excludes_items_with_no_representable_type() {
        use proton_pass_types::{WifiItem, WifiSecurity};

        let login = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: String::new(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let wifi = ItemData::new(
            "My WiFi".to_string(),
            String::new(),
            String::new(),
            ItemContent::Wifi(WifiItem {
                ssid: "MyNetwork".to_string(),
                password: "hunter2".to_string(),
                security: WifiSecurity::WPA2,
                sections: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        let export = CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![
                    ItemWithMetadata {
                        item: login,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                    ItemWithMetadata {
                        item: wifi,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                ],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        };

        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::BasicAuth],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter.create_export_response(&request, export).unwrap();
        assert_eq!(encrypted_response.warnings.len(), 1);
        assert_eq!(
            encrypted_response.warnings[0].kind,
            crate::cxf::CxfWarningKind::UnsupportedCredential
        );
        assert_eq!(encrypted_response.warnings[0].item_title.as_deref(), Some("My WiFi"));

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        let imported_items = &result.vaults[0].items;
        assert_eq!(imported_items.len(), 1);
        assert!(matches!(imported_items[0].content, ItemContent::Login(_)));
    }

    #[test]
    fn create_export_response_warns_and_excludes_unrepresentable_items_even_without_a_type_restriction() {
        use proton_pass_types::{WifiItem, WifiSecurity};

        let login = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: String::new(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let wifi = ItemData::new(
            "My WiFi".to_string(),
            String::new(),
            String::new(),
            ItemContent::Wifi(WifiItem {
                ssid: "MyNetwork".to_string(),
                password: "hunter2".to_string(),
                security: WifiSecurity::WPA2,
                sections: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        let export = CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![
                    ItemWithMetadata {
                        item: login,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                    ItemWithMetadata {
                        item: wifi,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                ],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        };

        let importer = CxpImportHandler::new();
        // No credential type restriction: `filter_export_input_by_requested_types` never runs.
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter.create_export_response(&request, export).unwrap();
        assert_eq!(encrypted_response.warnings.len(), 1);
        assert_eq!(
            encrypted_response.warnings[0].kind,
            crate::cxf::CxfWarningKind::UnsupportedCredential
        );
        assert_eq!(encrypted_response.warnings[0].item_title.as_deref(), Some("My WiFi"));

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        let imported_items = &result.vaults[0].items;
        assert_eq!(imported_items.len(), 1);
        assert!(matches!(imported_items[0].content, ItemContent::Login(_)));
    }

    #[test]
    fn create_export_response_includes_everything_when_request_has_no_restriction() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        assert_eq!(result.vaults[0].items.len(), 1);
    }

    #[test]
    fn complete_export_rejects_a_response_with_an_unsupported_version() {
        let importer = CxpImportHandler::new();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let response = r#"{
            "version": 7,
            "hpke": { "mode": "base", "kem": 32, "kdf": 1, "aead": 3, "key": null },
            "exporter": "Other App",
            "payload": "AAAA",
            "archive": "deflate"
        }"#;

        let result = importer.process_export_response(response.as_bytes());
        assert!(matches!(result, Err(CxpError::UnsupportedHpkeParameters(_))));
    }

    #[test]
    fn malformed_export_response_returns_clean_error() {
        let importer = CxpImportHandler::new();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let result = importer.process_export_response(b"not json");
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn truncated_ciphertext_returns_clean_error_not_a_panic() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let mut encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;
        encrypted_response.truncate(encrypted_response.len() / 2);

        let result = importer.process_export_response(&encrypted_response);
        assert!(matches!(
            result,
            Err(CxpError::DeserializationError(_)) | Err(CxpError::DecryptionError(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication_not_a_panic() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;
        let mut response: serde_json::Value = serde_json::from_slice(&encrypted_response).unwrap();
        let payload = response["payload"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = payload.chars().collect();
        let flip_index = chars.len() / 2;
        chars[flip_index] = if chars[flip_index] == 'A' { 'B' } else { 'A' };
        response["payload"] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = serde_json::to_vec(&response).unwrap();

        let result = importer.process_export_response(&tampered);
        assert!(matches!(result, Err(CxpError::DecryptionError(_))));
    }
}
