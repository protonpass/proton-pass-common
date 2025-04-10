use crate::entry::WasmAuthenticatorEntryModel;
use crate::worker::client::WasmAuthenticatorCodeResponse;
use proton_authenticator::generator::{
    GeneratorCurrentTimeProvider, TotpGenerationHandle, TotpGenerator as CoreTotpGenerator, TotpGeneratorCallback,
    TotpGeneratorDependencies,
};
use proton_authenticator::{emit_log_message, AuthenticatorCodeResponse, LogLevel};
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
            Ok(v) => {
                let value_as_debug = format!("{v:?}");
                u64::try_from(v).unwrap_or_else(|e| {
                    emit_log_message(
                        LogLevel::Error,
                        format!("Error when trying to convert {value_as_debug} to u64: {e:?}"),
                    );
                    0
                })
            }
            Err(e) => {
                emit_log_message(
                    LogLevel::Error,
                    format!("Got error when invoking time generator: {:?}", e),
                );
                0
            }
        }
    }
}

/// Callback-based TOTP generator that allows the caller to subscribe to TOTP code changes, and
/// to get notified of changes in a configurable manner
#[wasm_bindgen]
impl WebTotpGenerator {
    /// Create a new instance of the TOTP generator
    /// - period_ms: how often the generator should check if the codes have changed. Time in ms
    /// - only_on_code_change: if true, only invoke the callback if the codes have changed. If false, it will always be called
    /// - current_time_provider: callback that will be invoked to get the current time
    #[wasm_bindgen(constructor)]
    pub fn new(period_ms: u32, only_on_code_change: bool, current_time_provider: js_sys::Function) -> Self {
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(WebCurrentTimeProvider {
                inner: current_time_provider,
            }),
        };
        Self {
            inner: CoreTotpGenerator::new(dependencies, only_on_code_change, period_ms),
        }
    }

    /// Start generating the codes.
    ///  - entries: Entries to generate codes for
    ///  - callback: callback that will be invoked when new codes are generated
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
