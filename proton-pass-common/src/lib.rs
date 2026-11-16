#![allow(unexpected_cfgs)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod alias_prefix;
pub mod creditcard;

#[cfg(feature = "cxf")]
pub mod cxf;
#[cfg(feature = "cxp")]
pub mod cxp;
pub mod domain;
#[cfg(feature = "duplicate")]
pub mod duplicate;
pub mod email;
pub mod file;
#[cfg(feature = "gunzip")]
pub mod gunzip;
pub mod host;

#[cfg(feature = "duplicate")]
pub mod merge;

#[cfg(feature = "resize-image")]
pub mod image;
pub mod invite;
pub mod login;
pub mod markdown;
pub mod passkey;
pub use passkey_types;
pub mod password;
pub mod qr;
pub mod share;
pub mod sshkey;
pub mod string_modifiers;
pub mod twofa;
#[cfg(feature = "url-matching")]
pub mod url_matching;
pub mod username;
pub mod wifi;

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub use proton_pass_totp as totp;
pub use qrcode;
pub use url;
