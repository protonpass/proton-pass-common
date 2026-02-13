#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod algorithm;
pub mod error;
pub mod queries;
pub mod sanitizer;

#[allow(clippy::module_inception)]
pub mod totp;

pub use algorithm::Algorithm;
pub use totp::TOTP;
