use proton_authenticator::{register_authenticator_logger as common_register, LogLevel as CommonLogLevel, Logger};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum AuthenticatorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub trait AuthenticatorLogger: Send + Sync {
    fn log(&self, level: AuthenticatorLogLevel, msg: String);
}

struct LoggerAdapter {
    mobile: Arc<dyn AuthenticatorLogger>,
}

impl Logger for LoggerAdapter {
    fn log(&self, level: CommonLogLevel, msg: String) {
        let mobile_level = match level {
            CommonLogLevel::Trace => AuthenticatorLogLevel::Trace,
            CommonLogLevel::Debug => AuthenticatorLogLevel::Debug,
            CommonLogLevel::Info => AuthenticatorLogLevel::Info,
            CommonLogLevel::Warn => AuthenticatorLogLevel::Warn,
            CommonLogLevel::Error => AuthenticatorLogLevel::Error,
        };
        self.mobile.log(mobile_level, msg);
    }
}

pub fn register_authenticator_logger(logger: Arc<dyn AuthenticatorLogger>) {
    let adapter = LoggerAdapter { mobile: logger };
    common_register(Arc::new(adapter));
}
