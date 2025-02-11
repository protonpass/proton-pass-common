use js_sys::Function;
use proton_authenticator::{register_authenticator_logger as common_register, LogLevel as CommonLogLevel, Logger};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

/// The log levels we pass along to our JavaScript logger.
#[derive(Debug, Clone, Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum AuthenticatorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<AuthenticatorLogLevel> for CommonLogLevel {
    fn from(level: AuthenticatorLogLevel) -> Self {
        match level {
            AuthenticatorLogLevel::Trace => CommonLogLevel::Trace,
            AuthenticatorLogLevel::Debug => CommonLogLevel::Debug,
            AuthenticatorLogLevel::Info => CommonLogLevel::Info,
            AuthenticatorLogLevel::Warn => CommonLogLevel::Warn,
            AuthenticatorLogLevel::Error => CommonLogLevel::Error,
        }
    }
}

impl From<CommonLogLevel> for AuthenticatorLogLevel {
    fn from(level: CommonLogLevel) -> Self {
        match level {
            CommonLogLevel::Trace => AuthenticatorLogLevel::Trace,
            CommonLogLevel::Debug => AuthenticatorLogLevel::Debug,
            CommonLogLevel::Info => AuthenticatorLogLevel::Info,
            CommonLogLevel::Warn => AuthenticatorLogLevel::Warn,
            CommonLogLevel::Error => AuthenticatorLogLevel::Error,
        }
    }
}

/// A trait that defines the logging interface.
pub trait AuthenticatorLogger: Send + Sync {
    fn log(&self, level: AuthenticatorLogLevel, msg: String);
}

/// A WASM-friendly logger that wraps a JavaScript callback.
/// When a log is triggered in Rust, it will call the provided JS function,
/// passing in the log level (as a string) and message.
#[wasm_bindgen]
pub struct JsAuthenticatorLogger {
    callback: Function,
}

unsafe impl Send for JsAuthenticatorLogger {}
unsafe impl Sync for JsAuthenticatorLogger {}

#[wasm_bindgen]
impl JsAuthenticatorLogger {
    /// Create a new `JsAuthenticatorLogger` from a JavaScript function.
    /// The function will be called with two arguments:
    /// 1. A string representing the log level (e.g. "info")
    /// 2. The log message.
    #[wasm_bindgen(constructor)]
    pub fn new(callback: Function) -> JsAuthenticatorLogger {
        JsAuthenticatorLogger { callback }
    }
}

impl AuthenticatorLogger for JsAuthenticatorLogger {
    fn log(&self, level: AuthenticatorLogLevel, msg: String) {
        // Map our log level to a string.
        let level_str = match level {
            AuthenticatorLogLevel::Trace => "trace",
            AuthenticatorLogLevel::Debug => "debug",
            AuthenticatorLogLevel::Info => "info",
            AuthenticatorLogLevel::Warn => "warn",
            AuthenticatorLogLevel::Error => "error",
        };

        // Call the JS callback.
        let this = JsValue::NULL;
        // We ignore any errors from calling the callback.
        let _ = self
            .callback
            .call2(&this, &JsValue::from_str(level_str), &JsValue::from_str(&msg));
    }
}

/// This adapter wraps our internal (JS) logger into the format expected by
/// the `proton_authenticator` crate.
struct LoggerAdapter {
    internal: Arc<dyn AuthenticatorLogger>,
}

impl Logger for LoggerAdapter {
    fn log(&self, level: CommonLogLevel, msg: String) {
        // Convert the common log level into our internal logger’s log level.
        let internal_level = level.into();
        self.internal.log(internal_level, msg);
    }
}

/// Expose a function to JavaScript to register a logger.
///
/// JavaScript can call this function with a callback function:
///
/// ```js
/// import { register_authenticator_logger } from "your_wasm_crate";
///
/// register_authenticator_logger((level, message) => {
///   // For example, log to the browser console:
///   console[level](message);
/// });
/// ```
///
#[wasm_bindgen]
pub fn register_authenticator_logger(callback: Function) {
    let js_logger = Arc::new(JsAuthenticatorLogger::new(callback));
    let adapter = LoggerAdapter { internal: js_logger };
    // Register the logger adapter with the underlying library.
    common_register(Arc::new(adapter));
}

#[wasm_bindgen]
pub fn emit_log(log_level: AuthenticatorLogLevel, message: String) {
    proton_authenticator::emit_log_message(log_level.into(), message);
}
