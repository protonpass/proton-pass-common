use crate::entry::WasmAuthenticatorEntryModel;
use crate::worker::client::WasmAuthenticatorCodeResponse;
use proton_authenticator::generator::{
    GeneratorCurrentTimeProvider, TotpGenerationHandle, TotpGenerator as CoreTotpGenerator, TotpGeneratorCallback,
    TotpGeneratorDependencies,
};
use proton_authenticator::AuthenticatorCodeResponse;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WebTotpGenerator {
    inner: CoreTotpGenerator,
}

pub struct WebCurrentTimeProvider {
    inner: js_sys::Function,
}

unsafe impl Send for WebCurrentTimeProvider {}
unsafe impl Sync for WebCurrentTimeProvider {}

impl GeneratorCurrentTimeProvider for WebCurrentTimeProvider {
    fn now(&self) -> u64 {
        match self.inner.call0(&JsValue::NULL) {
            Ok(v) => match v.as_f64() {
                Some(v) => v as u64,
                None => 0,
            },
            Err(_) => 0,
        }
    }
}

#[wasm_bindgen]
impl WebTotpGenerator {
    #[wasm_bindgen(constructor)]
    pub fn new(period: u32, only_on_code_change: bool, current_time_provider: js_sys::Function) -> Self {
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(WebCurrentTimeProvider {
                inner: current_time_provider,
            }),
        };
        Self {
            inner: CoreTotpGenerator::new(dependencies, only_on_code_change, period),
        }
    }

    /// Async start; expects a JSON-serializable array of WebAuthenticatorEntry and a JS callback.
    #[wasm_bindgen]
    pub async fn start(
        &self,
        entries: Vec<WasmAuthenticatorEntryModel>,
        callback: js_sys::Function,
    ) -> Result<WebTotpGenerationHandle, JsError> {
        let mut as_entries = vec![];
        for entry in entries {
            as_entries.push(entry.to_entry()?);
        }
        let cb = WasmCallback { callback };
        let handle = self.inner.start_async(as_entries, cb).await;
        Ok(WebTotpGenerationHandle { inner: handle })
    }
}

/// Adapter to call the JS callback.
struct WasmCallback {
    callback: js_sys::Function,
}

unsafe impl Send for WasmCallback {}
unsafe impl Sync for WasmCallback {}

impl TotpGeneratorCallback for WasmCallback {
    fn on_codes(&self, codes: Vec<AuthenticatorCodeResponse>) {
        let res = js_sys::Array::new_with_length(codes.len() as u32);

        for (idx, code) in codes.into_iter().enumerate() {
            let mapped = WasmAuthenticatorCodeResponse::from(code);
            let as_js_value: JsValue = mapped.into();
            res.set(idx as u32, as_js_value);
        }

        let _ = self.callback.call1(&JsValue::NULL, &res);
    }
}

#[wasm_bindgen]
pub struct WebTotpGenerationHandle {
    inner: TotpGenerationHandle,
}

#[wasm_bindgen]
impl WebTotpGenerationHandle {
    #[wasm_bindgen]
    pub fn cancel(&mut self) {
        self.inner.cancel();
    }
}
