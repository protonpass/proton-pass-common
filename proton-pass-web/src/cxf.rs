use proton_pass_common::cxf::{CxfExportInput, CxfExportResult, CxfImportResult, export_cxf, import_cxf};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn cxf_export(input: Ts<CxfExportInput>) -> Result<Ts<CxfExportResult>, JsError> {
    let input = input.to_rust()?;
    let result = export_cxf(input).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(result.into_ts()?)
}

#[wasm_bindgen]
pub fn cxf_import(payload: String) -> Result<Ts<CxfImportResult>, JsError> {
    let result = import_cxf(&payload).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(result.into_ts()?)
}
