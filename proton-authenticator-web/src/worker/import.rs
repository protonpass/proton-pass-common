use crate::entry::WasmAuthenticatorEntryModel;
use js_sys::Uint8Array;
use proton_authenticator::ThirdPartyImportError;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

type ImportResult = Result<AuthenticatorImportResult, JsError>;

fn convert_import_error(err: ThirdPartyImportError) -> JsError {
    JsError::new(&format!("{err:?}"))
}

#[derive(Debug, Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AuthenticatorImportError {
    pub context: String,
    pub message: String,
}

impl From<proton_authenticator::ImportError> for AuthenticatorImportError {
    fn from(err: proton_authenticator::ImportError) -> Self {
        Self {
            context: err.context,
            message: err.message,
        }
    }
}

#[derive(Debug, Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AuthenticatorImportResult {
    pub entries: Vec<WasmAuthenticatorEntryModel>,
    pub errors: Vec<AuthenticatorImportError>,
}

impl From<proton_authenticator::ImportResult> for AuthenticatorImportResult {
    fn from(result: proton_authenticator::ImportResult) -> Self {
        Self {
            entries: result
                .entries
                .into_iter()
                .map(WasmAuthenticatorEntryModel::from)
                .collect(),
            errors: result.errors.into_iter().map(AuthenticatorImportError::from).collect(),
        }
    }
}

#[wasm_bindgen]
pub fn import_from_aegis_json(contents: String, password: Option<String>) -> ImportResult {
    let res = proton_authenticator::parse_aegis_json(&contents, password)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_aegis_txt(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_aegis_txt(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_bitwarden_json(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_bitwarden_json(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_bitwarden_csv(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_bitwarden_csv(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_ente_txt(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_ente_txt(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_ente_encrypted(contents: String, password: String) -> ImportResult {
    let res = proton_authenticator::parse_ente_encrypted(&contents, &password)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_google_qr(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_google_authenticator_totp(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_lastpass_json(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_lastpass_json(&contents)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_proton_authenticator(contents: String) -> ImportResult {
    let res = proton_authenticator::parse_proton_authenticator_export(&contents)
        .map_err(|e| JsError::new(&format!("Proton Authenticator import error: {e:?}")))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_proton_authenticator_with_password(contents: String, password: String) -> ImportResult {
    let res = proton_authenticator::parse_proton_authenticator_export_with_password(&contents, &password)
        .map_err(|e| JsError::new(&format!("Proton Authenticator import error: {e:?}")))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_2fas(contents: String, password: Option<String>) -> ImportResult {
    let res = proton_authenticator::parse_2fas_file(&contents, password)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[wasm_bindgen]
pub fn import_from_pass_zip(zip_contents: Uint8Array) -> ImportResult {
    let contents_as_array = zip_contents.to_vec();
    let res = proton_authenticator::parse_pass_zip(&contents_as_array)
        .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
    Ok(AuthenticatorImportResult::from(res))
}

#[cfg(feature = "qr")]
#[wasm_bindgen]
pub fn import_from_google_authenticator_qr(
    image_data: Uint8Array,
) -> Result<Option<AuthenticatorImportResult>, JsError> {
    let image_bytes = image_data.to_vec();

    // Scan the QR code from the image
    match proton_authenticator::qr::parse_qr_code(&image_bytes) {
        Some(qr_content) => {
            // If QR code was successfully scanned, parse it as Google Authenticator content
            let res = proton_authenticator::parse_google_authenticator_totp(&qr_content)
                .map_err(|e| convert_import_error(ThirdPartyImportError::from(e)))?;
            Ok(Some(AuthenticatorImportResult::from(res)))
        }
        None => {
            // No QR code found or couldn't parse the image
            Ok(None)
        }
    }
}
