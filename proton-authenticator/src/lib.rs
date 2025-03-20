#[macro_use]
#[allow(unused_macros)]
mod log;

pub mod crypto;
pub mod entry;
pub mod generator;
pub mod issuer_mapper;
pub mod parser;
pub mod steam;

mod client;

#[cfg(test)]
pub mod test_utils;

pub use client::{AuthenticatorClient, AuthenticatorCodeResponse, AuthenticatorError};
pub use entry::{
    AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntryError, AuthenticatorEntrySteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters, AuthenticatorEntryTotpParameters, AuthenticatorEntryType,
    AuthenticatorEntryUpdateContents,
};
pub use issuer_mapper::{IssuerInfo, TOTPIssuerMapper};
pub use log::{emit_log_message, register_authenticator_logger, LogLevel, Logger};
pub use parser::aegis::{parse_aegis_json, parse_aegis_txt};
pub use parser::bitwarden::{parse_bitwarden_csv, parse_bitwarden_json};
pub use parser::ente::parse_ente_txt;
pub use parser::google::parse_google_authenticator_totp;
pub use parser::lastpass::parse_lastpass_json;
pub use parser::proton_authenticator::parse_proton_authenticator_export;
pub use parser::twofas::parse_2fas_file;
pub use parser::{ImportError, ImportResult, ThirdPartyImportError};

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub use proton_pass_totp::{Algorithm, TOTP};
