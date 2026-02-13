use proton_authenticator::{
    emit_log_message, register_authenticator_logger as common_register, LogLevel as CommonLogLevel, Logger,
};
use std::sync::Arc;

#[derive(Debug, Clone, uniffi::Enum)]
pub enum AuthenticatorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<CommonLogLevel> for AuthenticatorLogLevel {
    fn from(log_level: CommonLogLevel) -> Self {
        match log_level {
            CommonLogLevel::Trace => AuthenticatorLogLevel::Trace,
            CommonLogLevel::Debug => AuthenticatorLogLevel::Debug,
            CommonLogLevel::Info => AuthenticatorLogLevel::Info,
            CommonLogLevel::Warn => AuthenticatorLogLevel::Warn,
            CommonLogLevel::Error => AuthenticatorLogLevel::Error,
        }
    }
}

impl From<AuthenticatorLogLevel> for CommonLogLevel {
    fn from(log_level: AuthenticatorLogLevel) -> Self {
        match log_level {
            AuthenticatorLogLevel::Trace => CommonLogLevel::Trace,
            AuthenticatorLogLevel::Debug => CommonLogLevel::Debug,
            AuthenticatorLogLevel::Info => CommonLogLevel::Info,
            AuthenticatorLogLevel::Warn => CommonLogLevel::Warn,
            AuthenticatorLogLevel::Error => CommonLogLevel::Error,
        }
    }
}

#[uniffi::export(with_foreign)]
pub trait AuthenticatorLogger: Send + Sync {
    fn log(&self, level: AuthenticatorLogLevel, msg: String);
}

struct LoggerAdapter {
    mobile: Arc<dyn AuthenticatorLogger>,
}

impl Logger for LoggerAdapter {
    fn log(&self, level: CommonLogLevel, msg: String) {
        self.mobile.log(level.into(), msg);
    }
}

#[uniffi::export]
pub fn register_authenticator_logger(logger: Arc<dyn AuthenticatorLogger>) {
    let adapter = LoggerAdapter { mobile: logger };
    common_register(Arc::new(adapter));
}

#[uniffi::export]
pub fn emit_log(level: AuthenticatorLogLevel, message: String) {
    emit_log_message(level.into(), message)
}
