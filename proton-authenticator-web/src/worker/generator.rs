use crate::entry::WasmAuthenticatorEntryModel;
use crate::worker::client::WasmAuthenticatorCodeResponse;
use proton_authenticator::generator::{
    GeneratorCurrentTimeProvider, TotpGenerationHandle, TotpGenerator as CoreTotpGenerator, TotpGeneratorCallback,
    TotpGeneratorDependencies,
};
use proton_authenticator::AuthenticatorCodeResponse;
use std::sync::Arc;
use wasm_bindgen::__rt::IntoJsResult;
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
    ) -> WebTotpGenerationHandle {
        let entries = entries
            .into_iter()
            .map(|e| e.to_entry().expect("todo: fixme"))
            .collect();
        let cb = WasmCallback { callback };
        let handle = self.inner.start_async(entries, cb).await;
        WebTotpGenerationHandle { inner: handle }
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
        let res = js_sys::Array::new();

        for code in codes {
            let mapped = WasmAuthenticatorCodeResponse::from(code);
            if let Ok(v) = mapped.into_js_result() {
                res.push(&v);
            }
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
